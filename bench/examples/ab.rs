//! Same-binary A/B: a baseline revision of protohoggr against the working
//! tree, on well-formed workloads. Linux only.
//!
//! ```text
//! brokkr run ab -- time [FILTER]                 # wall-clock ratios
//! brokkr run ab -- pmu [FILTER]                  # hardware counters
//! brokkr run ab --features swap -- time          # slots exchanged (BA)
//! brokkr run ab --features aa -- time            # baseline vs baseline (AA)
//! brokkr run ab -- info                          # build: line only
//! ```
//!
//! The binary holds the workloads of `protohoggr_bench::workloads!` twice,
//! in two harness slots, each instantiated against a different crate: by
//! default slot X against `protohoggr_base` (the git revision pinned in
//! `bench/Cargo.toml`) and slot Y against `protohoggr` (the working tree).
//! Feature `swap` exchanges which crate each slot is instantiated against;
//! feature `aa` replaces the working tree with `protohoggr_ctl`, the same
//! baseline commit under a second cargo identity. Every ratio printed is the
//! other side over the baseline side, whatever the slots hold.
//!
//! Measurement: pinned to one CPU (`AB_CPU`, default 2); each workload
//! rotates through `BUFS` distinct buffers; the two sides alternate which
//! runs first. `time` prints the median and p10/p90 of 41 per-round ratios.
//! `pmu` (x86-64 only) counts user-space instructions, cycles and branch
//! misses with `perf_event_open`, refusing any count the kernel multiplexed,
//! and prints the median of 9 repeats per side. A filter that matches no
//! workload is an error.
//!
//! Before measuring it prints one `build:` line - the slot assignment, the
//! panic strategy, whether `--cfg ab_ensemble` reached the build, the enabled
//! target features from a fixed list, and the xxh3-128 of the running
//! executable, which is the directory name `brokkr build ab` stores the same
//! bytes under - and checks that both sides compute the same results on
//! every input. See `reference/performance.md`.

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ab: CPU pinning and perf counters are implemented for Linux only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
mod linux {
    use protohoggr_bench::{BUFS, Inputs, N};
    use std::hint::black_box;
    use std::time::Instant;

    /// Instantiate slot X, then slot Y, against the two named crates.
    macro_rules! slots {
        ($x:ident, $y:ident) => {
            protohoggr_bench::workloads!(mod slot_x = $x);
            protohoggr_bench::workloads!(mod slot_y = $y);
            const SLOT_NAMES: [&str; 2] = [stringify!($x), stringify!($y)];
        };
    }

    #[cfg(not(any(feature = "swap", feature = "aa")))]
    slots!(protohoggr_base, protohoggr);
    #[cfg(all(feature = "swap", not(feature = "aa")))]
    slots!(protohoggr, protohoggr_base);
    #[cfg(all(feature = "aa", not(feature = "swap")))]
    slots!(protohoggr_base, protohoggr_ctl);
    #[cfg(all(feature = "aa", feature = "swap"))]
    slots!(protohoggr_ctl, protohoggr_base);

    /// Whether slot X holds the baseline.
    const BASE_IN_X: bool = !cfg!(feature = "swap");

    /// What the non-baseline side is called in the output.
    const OTHER: &str = if cfg!(feature = "aa") { "ctl" } else { "new" };

    const ROUNDS: usize = 41;
    const REPEATS: usize = 9;
    const ITERS: u32 = 400;

    type Run<'a> = Box<dyn FnMut() + 'a>;

    struct Case<'a> {
        name: String,
        base: Run<'a>,
        other: Run<'a>,
    }

    impl<'a> Case<'a> {
        /// Assign the slot X and slot Y runs to baseline and other.
        fn new(name: String, x: Run<'a>, y: Run<'a>) -> Self {
            let (base, other) = if BASE_IN_X { (x, y) } else { (y, x) };
            Self { name, base, other }
        }
    }

    /// A run of `$call` over the buffers of `$set`, one buffer per call.
    macro_rules! rotating {
        ($set:expr, $call:path) => {{
            let set: &[Vec<u8>] = $set;
            let mut i = 0usize;
            Box::new(move || {
                i = (i + 1) % BUFS;
                let _result = black_box($call(black_box(&set[i])));
            }) as Run<'_>
        }};
    }

    /// As `rotating!`, for workloads that decode into an output vector.
    macro_rules! rotating_out {
        ($set:expr, $call:path) => {{
            let set: &[Vec<u8>] = $set;
            let mut i = 0usize;
            let mut out = Vec::with_capacity(N + N / 8);
            Box::new(move || {
                i = (i + 1) % BUFS;
                $call(black_box(&set[i]), &mut out);
                black_box(&out);
            }) as Run<'_>
        }};
    }

    pub fn main() {
        let mut args = std::env::args().skip(1);
        let mode = args.next().unwrap_or_default();
        let filter = args.next().unwrap_or_default();
        if !matches!(mode.as_str(), "time" | "pmu" | "info") {
            eprintln!("usage: ab time|pmu [FILTER]   measure the workloads matching FILTER");
            eprintln!(
                "       ab info                print the build: line, check results, measure nothing"
            );
            std::process::exit(2);
        }
        if mode == "pmu" && !cfg!(target_arch = "x86_64") {
            // The perf_event_attr words below assume little-endian layout and
            // the generic ioctl encoding; only x86-64 has been checked.
            fail("pmu mode is implemented for x86-64 only");
        }
        let cpu = std::env::var("AB_CPU")
            .ok()
            .map_or(Ok(2), |v| v.parse::<usize>())
            .unwrap_or_else(|e| fail(&format!("AB_CPU: {e}")));
        sys::pin(cpu);
        print_build();

        let inputs = Inputs::generate();
        verify(&inputs);
        if mode == "info" {
            return;
        }
        let mut matched = 0usize;
        for case in &mut cases(&inputs) {
            if !case.name.contains(filter.as_str()) {
                continue;
            }
            matched += 1;
            if mode == "pmu" {
                run_pmu(case);
            } else {
                run_time(case);
            }
        }
        if matched == 0 {
            fail(&format!("no workload matches {filter:?}"));
        }
    }

    pub fn fail(msg: &str) -> ! {
        eprintln!("ab: {msg}");
        std::process::exit(1);
    }

    fn print_build() {
        let exe = std::fs::read("/proc/self/exe")
            .unwrap_or_else(|e| fail(&format!("reading /proc/self/exe: {e}")));
        let panic = if cfg!(panic = "abort") {
            "abort"
        } else {
            "unwind"
        };
        println!(
            "build: x={} y={} panic={panic} ab_ensemble={} features={} exe-xxh3-128={:032x}",
            SLOT_NAMES[0],
            SLOT_NAMES[1],
            cfg!(ab_ensemble),
            target_features(),
            xxhash_rust::xxh3::xxh3_128(&exe),
        );
    }

    /// The enabled features among a fixed list that changes x86-64 codegen.
    fn target_features() -> String {
        let all = [
            ("sse4.2", cfg!(target_feature = "sse4.2")),
            ("popcnt", cfg!(target_feature = "popcnt")),
            ("avx", cfg!(target_feature = "avx")),
            ("avx2", cfg!(target_feature = "avx2")),
            ("bmi1", cfg!(target_feature = "bmi1")),
            ("bmi2", cfg!(target_feature = "bmi2")),
            ("lzcnt", cfg!(target_feature = "lzcnt")),
            ("fma", cfg!(target_feature = "fma")),
            ("avx512f", cfg!(target_feature = "avx512f")),
            ("avx512bw", cfg!(target_feature = "avx512bw")),
            ("avx512vl", cfg!(target_feature = "avx512vl")),
        ];
        let on: Vec<&str> = all.iter().filter(|f| f.1).map(|f| f.0).collect();
        if on.is_empty() {
            "none".to_owned()
        } else {
            on.join(",")
        }
    }

    /// Both slots must compute the same result on every input.
    fn verify(inputs: &Inputs) {
        for (name, set) in inputs.packed() {
            for d in set {
                if slot_x::packed_sum(d) != slot_y::packed_sum(d) {
                    fail(&format!("packed_sum differs between slots on {name}"));
                }
                let (mut a, mut b) = (Vec::new(), Vec::new());
                slot_x::cumulative(d, &mut a);
                slot_y::cumulative(d, &mut b);
                if a != b {
                    fail(&format!("cumulative differs between slots on {name}"));
                }
            }
        }
        for (name, set) in inputs.messages() {
            for d in set {
                let (qx, qy) = (slot_x::msg_question(d).ok(), slot_y::msg_question(d).ok());
                if qx.is_none() || qx != qy || slot_x::msg_unwrap(d) != slot_y::msg_unwrap(d) {
                    fail(&format!("message loop differs between slots on {name}"));
                }
            }
        }
    }

    fn cases(inputs: &Inputs) -> Vec<Case<'_>> {
        let mut cases = Vec::new();
        for (name, set) in inputs.packed() {
            cases.push(Case::new(
                format!("packed_sum/{name}"),
                rotating!(set, slot_x::packed_sum),
                rotating!(set, slot_y::packed_sum),
            ));
            cases.push(Case::new(
                format!("cumulative/{name}"),
                rotating_out!(set, slot_x::cumulative),
                rotating_out!(set, slot_y::cumulative),
            ));
        }
        for (name, set) in inputs.messages() {
            cases.push(Case::new(
                format!("msg_question/{name}"),
                rotating!(set, slot_x::msg_question),
                rotating!(set, slot_y::msg_question),
            ));
            cases.push(Case::new(
                format!("msg_unwrap/{name}"),
                rotating!(set, slot_x::msg_unwrap),
                rotating!(set, slot_y::msg_unwrap),
            ));
        }
        cases
    }

    fn warm(case: &mut Case<'_>) {
        for _ in 0..ITERS {
            (case.base)();
            (case.other)();
        }
    }

    fn time(f: &mut dyn FnMut()) -> f64 {
        let t = Instant::now();
        for _ in 0..ITERS {
            f();
        }
        t.elapsed().as_secs_f64() / f64::from(ITERS)
    }

    fn run_time(case: &mut Case<'_>) {
        warm(case);
        let mut ratios = Vec::with_capacity(ROUNDS);
        for round in 0..ROUNDS {
            let (base, other) = if round % 2 == 0 {
                let base = time(&mut case.base);
                (base, time(&mut case.other))
            } else {
                let other = time(&mut case.other);
                (time(&mut case.base), other)
            };
            ratios.push(other / base);
        }
        ratios.sort_by(f64::total_cmp);
        println!(
            "{:24} {OTHER}/base median {:.3}  p10 {:.3}  p90 {:.3}",
            case.name,
            ratios[ROUNDS / 2],
            ratios[ROUNDS / 10],
            ratios[ROUNDS - 1 - ROUNDS / 10],
        );
    }

    /// Counter value per call of `f`, over `ITERS` calls.
    fn count(event: sys::Event, f: &mut dyn FnMut()) -> f64 {
        let counter = sys::Counter::open(event);
        counter.start();
        for _ in 0..ITERS {
            f();
        }
        sys::as_f64(counter.stop()) / f64::from(ITERS)
    }

    fn run_pmu(case: &mut Case<'_>) {
        warm(case);
        let mut line = format!("{:24}", case.name);
        for event in sys::EVENTS {
            let mut base = Vec::with_capacity(REPEATS);
            let mut other = Vec::with_capacity(REPEATS);
            for rep in 0..REPEATS {
                if rep % 2 == 0 {
                    base.push(count(event, &mut case.base));
                    other.push(count(event, &mut case.other));
                } else {
                    other.push(count(event, &mut case.other));
                    base.push(count(event, &mut case.base));
                }
            }
            base.sort_by(f64::total_cmp);
            other.sort_by(f64::total_cmp);
            let (b, o) = (base[REPEATS / 2], other[REPEATS / 2]);
            line += &format!(
                "  {} base {b:.0} {OTHER} {o:.0} ({:+.2}%)",
                event.name,
                (o / b - 1.0) * 100.0
            );
        }
        println!("{line}");
    }

    /// CPU affinity and user-space hardware counters, through libc.
    mod sys {
        use super::fail;

        /// One `PERF_TYPE_HARDWARE` event.
        #[derive(Clone, Copy)]
        pub struct Event {
            pub name: &'static str,
            config: u64,
        }

        pub const EVENTS: [Event; 3] = [
            Event {
                name: "instructions",
                config: 1,
            },
            Event {
                name: "cycles",
                config: 0,
            },
            Event {
                name: "branch-misses",
                config: 5,
            },
        ];

        pub fn pin(cpu: usize) {
            // SAFETY: cpu_set_t is plain data; CPU_SET bounds-checks `cpu`
            // against the set size; sched_setaffinity reads `size_of` bytes
            // of `set`, which lives for the call.
            let rc = unsafe {
                let mut set: libc::cpu_set_t = std::mem::zeroed();
                libc::CPU_SET(cpu, &mut set);
                libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &raw const set)
            };
            if rc != 0 {
                fail(&format!(
                    "pinning to CPU {cpu}: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }

        /// A counter count as a float, for per-call averages.
        #[expect(clippy::cast_precision_loss, reason = "counts far below 2^52")]
        pub fn as_f64(v: u64) -> f64 {
            v as f64
        }

        pub struct Counter(libc::c_int);

        const IOC_ENABLE: libc::c_ulong = 0x2400;
        const IOC_DISABLE: libc::c_ulong = 0x2401;
        const IOC_RESET: libc::c_ulong = 0x2403;

        impl Counter {
            pub fn open(event: Event) -> Self {
                // perf_event_attr as words: type and size, config,
                // sample_period, sample_type, read_format, flags.
                let mut attr = [0u64; 16];
                attr[0] = 112 << 32; // PERF_TYPE_HARDWARE = 0, size 112
                attr[1] = event.config;
                attr[4] = 1 | 2; // TOTAL_TIME_ENABLED | TOTAL_TIME_RUNNING
                attr[5] = 1 | (1 << 5) | (1 << 6); // disabled, exclude_kernel, exclude_hv
                // SAFETY: `attr` is 128 bytes, at least the 112 declared, and
                // outlives the call; pid 0 / cpu -1 is this thread on any CPU.
                let fd = unsafe {
                    libc::syscall(libc::SYS_perf_event_open, attr.as_ptr(), 0, -1, -1, 0)
                };
                match libc::c_int::try_from(fd) {
                    Ok(fd) if fd >= 0 => Self(fd),
                    _ => fail(&format!(
                        "perf_event_open({}): {}",
                        event.name,
                        std::io::Error::last_os_error()
                    )),
                }
            }

            fn ioctl(&self, request: libc::c_ulong) {
                // SAFETY: the descriptor is open; these requests take no argument.
                if unsafe { libc::ioctl(self.0, request as _, 0) } != 0 {
                    fail(&format!(
                        "perf ioctl {request:#x}: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }

            pub fn start(&self) {
                self.ioctl(IOC_RESET);
                self.ioctl(IOC_ENABLE);
            }

            /// Stop and read the count, refusing a multiplexed one.
            pub fn stop(&self) -> u64 {
                self.ioctl(IOC_DISABLE);
                let mut v = [0u64; 3];
                // SAFETY: reads at most 24 bytes into the 24-byte `v`.
                let n = unsafe { libc::read(self.0, v.as_mut_ptr().cast(), size_of_val(&v)) };
                if usize::try_from(n).ok() != Some(size_of_val(&v)) {
                    fail(&format!("short counter read: {n}"));
                }
                if v[1] == 0 || v[1] != v[2] {
                    fail(&format!(
                        "counter multiplexed: enabled {} running {}",
                        v[1], v[2]
                    ));
                }
                v[0]
            }
        }

        impl Drop for Counter {
            fn drop(&mut self) {
                // SAFETY: closes the descriptor this value owns, once.
                unsafe { libc::close(self.0) };
            }
        }
    }
}
