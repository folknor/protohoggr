# Verification hunt: `bench` scope

Scope: `benches/varint.rs`, the `[dev-dependencies]` and `[[bench]]` tables in
`Cargo.toml`, and every performance claim in source and docs that rests on a
benchmark. Findings follow the brief's five questions, then a list of things
outside the scope that turned up along the way. Nothing is ranked.

Evidence I used besides the tracked files: `git log` and `git show` on this repo,
pbfhogg's commit `dd7f69a` (`notes/SIMD.md` at that commit), the varint-simd
0.4.1 and criterion 0.8.2 sources in the cargo registry, the user-level
`~/.cargo/config.toml`, `.brokkr/check-logs/*`, and `brokkr man bench`,
`brokkr man check clippy`, `brokkr test --help`. I built and ran nothing.

---

## Summary of the structural recommendation

Most of what follows comes from one structural fact. The benchmark is a target
of the library package, so its two dev-dependencies (criterion with default
features, and varint-simd) belong to *every* test target of the package. They
end up in the lockfile, the `brokkr check` clippy phase, the test build, the
MSRV, the set of hosts the check can run on, and the ISA the check needs. Yet
nothing in `tests/wire.rs` uses either crate.

The right move is to take the benchmark out of the library package:

- Make a workspace with `protohoggr` (zero dependencies, zero dev-dependencies)
  and a `publish = false` member, e.g. `bench/` holding `protohoggr-bench`,
  which owns criterion, varint-simd and the bench target. Gate the varint-simd
  comparison behind `cfg(all(target_arch = "x86_64", target_feature = "ssse3"))`
  in that crate, or drop it (see C1 to C3: the comparison it supports is closed
  and its recorded numbers cannot be reproduced as documented).
- Put the "every strategy decodes the same values" invariant in a `#[test]` in
  that crate, built on shared data-generation functions, so the check exercises
  the bench's correctness without timing anything.
- Keep the durable numbers in `reference/performance.md` with the brokkr bench
  environment stamp next to them. Doc comments should then say what was decided
  and point to that file, not carry numbers of their own.

Enforcement: a `dependency_rules` entry in `brokkr.toml` (that phase runs on
every check and has no rules today, see G4) can say that the `protohoggr`
package has no `[dependencies]` and no `[dev-dependencies]`. That holds both the
README's "No external dependencies" and the separation itself.

---

## 1. Tests that prove nothing

### T1. The benchmark's correctness claim has no assertion, and the ground truth is thrown away

CHANGELOG 0.3.0 says the bias fix made it "so all strategies decode the same
values". Nothing checks this. `make_packed_sint64` returns `(values, packed_body)`,
and every decode bench destructures it as `let (_, small_packed) = ...`, so the
oracle that would prove equivalence is computed and then dropped. Each strategy
`black_box`es its outputs one by one and never compares them to anything. The
`_overflow` flag from `decode_four_unsafe` is ignored too.

Here is what could go wrong without anyone seeing it:
- Change the "small" pattern to include a value whose zigzag form needs more than
  3 bytes. `decode_four_unsafe::<u16>` then truncates silently and
  mis-segments the stream. The bench keeps reporting a time, now for decoding
  garbage.
- The batch loops once decoded padding zeros as extra values (that was the 0.3.0
  bug). That is exactly the kind of bias an equality assertion would have caught
  when the bench was written.

Fix: one function per strategy that returns the decoded `Vec<i64>` (or a sum and
a count). A `#[test]` asserts each one equals `values`, and the timed closure
calls the same function. Enforceable: yes, by a test, once the bench crate's
tests run in the check (see S2).

### T2. The bench is type-checked by the check but never linked or run

The `brokkr check` log shows clippy running with `--all-targets` (so the bench is
type-checked), while the test phase runs `cargo test ... --tests`, which does not
build bench targets. So the bench is never linked and never executed by any
gate. Anything that fails only at link or run time passes the check:
- `decode_two_unsafe` checks `T::MAX_VARINT_BYTES + U::MAX_VARINT_BYTES > 16`
  with a runtime `panic!` that the varint-simd source describes as "eliminated
  at compile time". Change a type in the bench to `(u64, u64)` and clippy is
  still happy. The panic only appears when someone runs `brokkr bench`.
- `make_packed_sint64` strips the tag and length by indexing `buf[pos]` in two
  hand-written loops. A change to the encoder's framing becomes a panic or a
  silently wrong body, and the check never runs it.

Fix: criterion supports `cargo test --benches`, which runs each routine once in
test mode. Wire that into the bench crate's lane, or rely on the `#[test]` from
T1, which also exercises the data generators. Enforceable: yes, as a check lane.
Cost: one debug link of the bench binary plus one pass over each routine, which
is milliseconds of execution.

### T3. Bench labels and comments name data the bench does not contain

- `large_delta_data` is documented as "Large deltas (3-5 byte varints after
  zigzag)". The bench IDs label it `large_3B`. Working out the zigzag values of
  the ten-value pattern: 5000 -> 10000 (2 B), -3200 -> 6399 (2 B),
  18000 -> 36000 (3 B), -7500 -> 14999 (2 B), 42000 -> 84000 (3 B),
  -15000 -> 29999 (3 B), 8700 -> 17400 (3 B), -2100 -> 4199 (2 B),
  31000 -> 62000 (3 B), -9900 -> 19799 (3 B). That is 4 two-byte and 6
  three-byte values, a mean of 2.6 bytes, and **no** 4- or 5-byte values. The
  "3-5 byte" comment is false, and `large_3B` is a mixed 2/3-byte workload.
- `small_delta_data` is called "typical OSM dense node ID deltas". It is a
  period-10 pattern in which every value is 1 byte. That says nothing about how
  dense node data is distributed (see C1).

Fix: generate the datasets from stated byte-length distributions (for example
"100% 1-byte", "50/50 2-byte and 3-byte"), name the IDs after that
distribution, and have a `#[test]` assert the distribution by counting bytes
per varint with `count_packed_varints` and the body length. Enforceable: yes, by
a test.

### T4. The scalar and SIMD sides are not measured the same way

- Decode: `scalar_iter` wraps its input in `black_box(d)`. None of the SIMD
  closures do. Both put each output through `black_box`, so the practical
  effect is probably small, but the asymmetry is unforced.
- Decode: `simd_single` gets the unpadded slice. So the last values go through
  varint-simd's safe `decode`, which falls into the copy-into-a-16-byte-stack-buffer
  path whenever fewer than 16 bytes remain. The batch tails get the padded slice
  and never hit that path.
- Encode: `scalar` times `encode_packed_sint64`. That function encodes into
  `scratch`, then writes a tag and a length and `extend_from_slice`s the whole
  body into `buf`, so it is framing plus a memcpy of the body. `simd_single` times
  bare `encode_to_slice` with no framing. So the two sides do different work.
- Encode: `varint_simd::encode::encode_to_slice` is the crate's *safe
  convenience wrapper*. It encodes into a `[u8; 16]` and then
  `slice[..size].copy_from_slice(&data[..size])`, which is a bounds-checked,
  variable-length copy per value. The fast way to use that library is
  `encode_unsafe` with an unconditional 16-byte store into a padded buffer. The
  bench measured the wrapper's copy, not SIMD encoding. The doc claim "scalar is
  3.5x faster" for encode (C2) rests on this.
- The crate now has `encode_varint_to_slice` (0.4.0). It is the like-for-like
  counterpart to `encode_to_slice`, and the bench never measures it.

Fix: give both sides the same contract. Same input wrapping, same padding, same
output shape: either both write framing or neither does. Compare
`encode_varint_to_slice` with `encode_unsafe` plus a 16-byte store.
Enforceable: partly. Shared helpers make the symmetry structural, but fairness
itself cannot be linted.

### T5. `padded()` documents a reason that no longer holds

"Pad buffer with 16 zero bytes so SIMD pointer reads don't go out of bounds."
Since the 0.3.0 fix, the batch loops run while `pos < data_end - 16`, so every
16-byte read `[pos, pos + 16)` stays inside the real data and never touches the
padding. The padding now only decides whether the scalar tail takes varint-simd's
no-copy path, which is a measurement artefact (T4), not a safety need. Neither
`unsafe` call in the bench has a `// SAFETY:` comment, while `src/lib.rs` puts
one on every unsafe block. Enforceable: yes. `clippy::undocumented_unsafe_blocks`
(not in the deny list today) would require a SAFETY comment on each bench call,
and that comment is where the stale reasoning would have to be restated and
checked.

---

## 2. Guards and claims that have stopped holding

### C1. `Cursor::read_varint` doc comment (src/lib.rs)

The claim: "Benchmarked (criterion, 8000 packed sint64, varint-simd v0.4.1
SSSE3): scalar is 2.3x faster than SIMD batch4 decode for 1-byte varints (the
dominant OSM case - dense node id/lat/lon deltas) and tied for 3-byte varints.
The 1-byte fast path below is perfectly predicted ... See `notes/SIMD.md` in
pbfhogg (dd7f69a)."

The problems:
- **Measured on the biased bench.** The numbers came with commit `fcad0e7`
  (2026-03-02) and match the table in pbfhogg `dd7f69a:notes/SIMD.md`. The
  tail-byte bias that made the batch loops decode extra padding values was fixed
  in `3219f18` (2026-04-12). No later commit records a new measurement. So the
  only numbers in the source were produced by a benchmark the project itself
  calls biased.
- **"SSSE3" is not what this build compiles.** `decode_two_unsafe` and
  `decode_four_unsafe` exist only under `cfg(target_feature = "ssse3")`. The
  default `x86_64-unknown-linux-gnu` baseline is SSE2, so the bench compiles here
  only because `~/.cargo/config.toml` sets `-Ctarget-cpu=native`. That flag also
  turns on AVX2 on this host, and varint-simd's `num.rs` switches its `u64`
  vector paths on `cfg(target_feature = "avx2")`. `simd_single` uses
  `decode::<u64>`, so it runs the AVX2 path. Whatever ran in March, an ISA label
  in a comment does not describe what `brokkr bench` measures today on this
  machine, and nothing records which flags were in effect.
- **"tied for 3-byte varints"**: that workload is 2.6 bytes on average (T3).
- **"dense node id/lat/lon deltas" as 1-byte**: the research doc the comment
  cites says otherwise. `dd7f69a:notes/SIMD.md` says "Node ID deltas: mostly 1-3
  bytes" and "Lat/lon deltas: mostly 1-2 bytes". So the stated dominant case is
  contradicted by its own source.
- **"perfectly predicted by the CPU branch predictor"**: the data is 100% 1-byte
  in a period-10 pattern, so the predictor never has to work. Nothing measured
  branch misses. Real mixed-length streams are where the claim would matter, and
  the bench has none.
- **The citation points outside this repo, at a deleted note.** `notes/SIMD.md`
  is no longer in pbfhogg's `notes/` at HEAD. It is reachable only through
  another repo's history, by a short sha. AGENTS.md says nothing durable may
  cite `notes/`. That rule is written for this repo's folders, but the reason
  behind it (a note can be wrong or vanish) applies more strongly to another
  repo's deleted note.

Checkable: the sha resolves (it does today). Not checkable as written: the
numbers, the ISA, and the data shape. Fix: replace the numbers with the decision
and a pointer to `reference/performance.md`, which records a `brokkr bench`
baseline with its environment stamp (rustc, host, CPU, cargo-config digests,
per `brokkr man bench`). Enforceable: a textlint rule in `brokkr.toml` banning
`notes/` and `pbfhogg (` references in `src/**` doc comments, plus a rule that
doc comments in `src/` contain no `\d(\.\d)?x faster` patterns. The second makes
the "numbers live in reference/performance.md" rule mechanical.

### C2. `encode_varint` doc comment (src/lib.rs)

The claim: "Benchmarked (criterion, 8000 packed sint64, varint-simd v0.4.1
SSE2): scalar is 3.5x faster for 1-byte varints and 1.5x faster for 3-byte
varints."

- The scalar side of that measurement was `encode_packed_sint64` (framing plus
  memcpy), not `encode_varint` (T4). The comment attributes a composite's number
  to a single function.
- The SIMD side was the safe `encode_to_slice` wrapper with a per-value
  variable-length copy (T4).
- "3-byte" is the 2.6-byte mixed set (T3).
- "SSE2": under `-Ctarget-cpu=native`, varint-simd's `u64::num_to_vector_stage1`
  takes the `cfg(target_feature = "avx2")` path.
- Same cross-repo `notes/` citation as C1.

Fix and enforcement: as C1.

### C3. CHANGELOG 0.2.0: "Benchmarked scalar vs varint-simd SSSE3/SSE2 - scalar wins 2-6x on decode, 1.5-3.5x on encode"

Same measurements as C1 and C2, before the bias fix. The "6x" is against
`simd_single`, the safe single-value decode that nobody would choose as the SIMD
competitor. CHANGELOG entries are a history and are not expected to be
re-measured. But the 0.3.0 entry ("Fixed SIMD benchmark tail-byte bias") does not
say the 0.2.0 numbers were measured under that bias, so a reader takes them as
current. Fix: one clause in the 0.3.0 entry saying so. Enforceable: no. This is
editorial.

### C4. `encode_varint_to_slice`: "branchless fast path ... covering ~95% of zigzag-encoded OSM way-ref deltas"

This appears in the `src/lib.rs` doc, in README ("branchless 1-2 byte fast
path"), and in CHANGELOG 0.4.0.
- **Not branchless as written.** The code is `if value < 0x80 { ...; return 1 }`
  then `if value < 0x4000 { ...; return 2 }`, which is two conditional early
  returns. Whether LLVM emits a cmov is unverified. No benchmark, assembly
  check or test looks. The gitignored plan `.plans/dynamic-beaming-giraffe.md`
  says only "The compiler can emit cmov".
- **"~95%" has no source in the repo**, and two sources contradict it. The cited
  research doc says "Way ref deltas: 2-4 bytes (node IDs jump more)". And this
  repo's own bench, whose large set is labelled "typical way ref deltas", has
  60% of values at 3 bytes, that is at or above 16384 and outside the fast path.
- No benchmark covers this function at all.

Fix: drop "branchless", or prove it with a `cargo asm`-style check, which is
heavy and needs pinned codegen. Drop "~95%" or cite a measurement over real data
in `reference/performance.md`. Enforceable: "branchless" could be held by an
assembly snapshot test, which is fragile across nightly bumps. The honest wording
needs no enforcement.

### C5. CHANGELOG 0.4.0 hot-path primitives imply speedups nobody measured

`decode_packed_sint64_cumulative` ("replacing per-element `PackedSint64Iter` +
manual accumulation"), `count_packed_varints` ("SSE2 SIMD on x86-64") and
`read_varint_unchecked` were all added as performance work for pbfhogg (the
gitignored plan says "These five additions eliminate per-element overhead").
`benches/varint.rs` measures none of them. Its `scalar_iter` still times the
checked `PackedSint64Iter`, which the 0.4.0 entry describes as the thing being
replaced. The single justification for the 0.4.0 API sits in a gitignored file.
Fix: bench these against the per-element baselines they claim to replace. Store
the result in `reference/performance.md`.

### C6. The bench header says "Run with: cargo bench --bench varint"

AGENTS.md says "Never run raw `cargo` ... Use `brokkr`", and `brokkr bench varint`
exists. It writes baselines to `.brokkr/bench/` with an environment stamp and
refuses cross-environment comparisons. Raw `cargo bench` writes to
`target/criterion` under the name `base`. Each run overwrites the previous
reference, and `cargo clean` deletes it (Q5, W1). So the in-file instruction
sends the reader down the path that produces numbers that cannot be compared.
Enforceable: a textlint rule banning `cargo bench` in `benches/**`.

### C7. Stale lint allows on the bench crate root

`#![allow(clippy::unwrap_used, clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap)]`.
The bench has no `.unwrap()`. Its only `as` cast is `N as u64` (usize to u64),
which none of the three cast lints fire on for 64-bit targets. As far as I can
read, every one of the four allows is unused. They are crate-wide, so they would
also hide a real truncating cast added later (for example while reworking the
SIMD lengths, which are `u8`). Fix: remove them, or use
`#[expect(...)]` at the specific site. Enforceable: yes. Deny
`clippy::allow_attributes` in `[lints.clippy]` so every suppression has to be an
`#[expect]`, and an unused `#[expect]` raises `unfulfilled_lint_expectations`,
which brokkr's any-diagnostic-fails rule turns into a check failure. That is the
source-level counterpart to brokkr's `allow_exact` "suppressed nothing" warning.
`src/lib.rs` has many `#[allow(clippy::cast_*)]`, and the same rule would audit
them too.

### C8. The `rust-version = "1.85"` claim is false for anyone who runs the tests

criterion 0.8.2 declares `rust-version = "1.86"`. Because criterion is a
dev-dependency of the package, `cargo +1.85 test` cannot build. Nothing in the
check builds on 1.85, so nobody would notice. (AGENTS.md also says "nightly
toolchain", and there is no `rust-toolchain.toml`, so that claim is not enforced
either.) Moving the bench out (Summary) makes the library's MSRV depend on the
library alone again. Enforceable: an MSRV sweep (`cargo +1.85 check --lib
--tests`) as a brokkr `[[check]]` entry. See also L3 for a possible second MSRV
problem inside `src/lib.rs` itself.

### C9. `.gitignore` lists `Cargo.lock`, but `Cargo.lock` is tracked

The ignore line is a no-op for a tracked file. It reads as a policy ("library,
don't commit the lockfile") that the repo does not follow. 77 of the 78 locked
packages exist only because of the bench's dev-dependencies, so in practice
every lockfile diff in this repo is bench churn. Fix: drop the ignore line.
After the bench moves out, the root lock has one entry, or the workspace lock
carries the bench crate's tree, which is honest about where it comes from.

### C10. A deprecation that is enforced already

CHANGELOG 0.2.1 moved from `criterion::black_box` to `std::hint::black_box`. That
change *is* held: using the deprecated item raises a rustc `deprecated` warning,
and brokkr fails the check on any clippy-phase diagnostic. I list it as an
example of a rule the build already pays for, not as a finding.

---

## 3. The test suite as a system

### S1. Every check builds the bench's dependency tree, twice, for tests that use none of it

- `Cargo.lock` has 78 packages. Only `protohoggr` is not a dev-dependency or one
  of their transitive dependencies. Among them: rayon and crossbeam, plotters,
  serde, serde_derive and serde_json, regex and regex-automata, clap, ciborium,
  two majors of syn, zerocopy-derive, `rustc_version` (varint-simd's build
  dependency), and `alloca`, which builds `alloca.c` through `cc`. So
  `brokkr check` on this "pure Rust, no external dependencies" crate needs a **C
  compiler** on the host.
- `target/debug/build/` has 57 entries. None belong to protohoggr, which has no
  build script.
- The clippy phase (`--all-targets`) builds the whole tree in check mode. The
  test phase (`cargo test --tests`) builds it again with full codegen, because
  dev-dependencies are linked into every test target, including `tests/wire.rs`,
  which imports neither crate.
- Warm runs cost nothing ("test binaries built in 30ms"). The cost is on every
  cold build. With a nightly toolchain those come often: each toolchain bump,
  each `brokkr clean`, each fresh checkout or CI runner, and each change to
  `~/.cargo/config.toml` rustflags (which invalidates every crate).
- criterion's default features (`rayon`, `plotters`) account for much of that
  tree. `html_reports`, the only feature the manifest asks for, adds no
  dependencies of its own. `brokkr bench` compares through criterion's
  baselines and does not need plots.

Fix: the workspace split in the Summary. The interim fix is
`criterion = { version = "0.8", default-features = false, features = ["cargo_bench_support"] }`.
That removes rayon and plotters but keeps everything in the library's
test build. Enforceable: yes, with the `dependency_rules` rule from the Summary.
`brokkr deps` (the duplicate-versions audit) would also flag the two syn
majors, both of which are bench-only.

### S2. A focused `brokkr test NAME` builds a different profile from the one the check built

`brokkr test --help`: "release by default; --debug for dev ... `[test] debug` in
brokkr.toml decides (default release)". `brokkr.toml` has no `[test]` table. The
check's test phase runs in dev (the log shows no `--release`). AGENTS.md
documents `brokkr test <NAME>` as the focused-run command. So the first focused
run after a check compiles protohoggr **and the whole bench dependency tree**
(S1) a second time in release, for a 156-test suite that runs serially in about
300 ms. That is a second full build per profile switch, and it puts tests on an
artefact other than the one the check produced. Fix: set `[test] debug = true` in
`brokkr.toml`, so the focused run reuses the check's debug artefacts. With S1
fixed, a release run would at worst rebuild one dependency-free crate.
Enforceable: by configuration. Nothing would notice if the line were removed.

### S3. Nothing builds the bench in the profile it is measured in

The check type-checks the bench in check mode. `brokkr bench` builds it in the
bench profile (release). Between those, no gate links it (T2). This is
inherent to benches and is fine as long as T1 and T2 are covered by tests that
run in the check. I mention it so the separate-crate test lane is not mistaken
for "the bench builds".

---

## 4. What the tests reach that they should have been handed

### A1. The host's rustflags decide whether the check compiles at all

The bench uses `decode_four_unsafe` and `decode_two_unsafe`, which varint-simd
compiles only under `target_feature = "ssse3"`, and `encode_to_slice`, which
needs `sse2`. `brokkr check` runs clippy on `--all-targets`, so the check's
outcome depends on an ambient flag in `~/.cargo/config.toml`
(`-Ctarget-cpu=native`) that nothing in the repo declares. Take that file away
and clippy fails with an unresolved-function compile error in
`benches/varint.rs`, on a default x86_64 host and therefore on any standard CI
image. The bench takes its ISA from the environment instead of being given it.
Fix: inside the bench crate, gate the varint-simd section on
`cfg(target_feature = "ssse3")` with an explicit `compile_error!` or a skipped
group that prints a message. Or declare the requirement in a repo-local
`.cargo/config.toml` scoped to the bench crate. Enforceable: yes. A brokkr
`[[check]]` sweep with `RUSTFLAGS` set to the baseline target (brokkr already
supports `rustflags-*` sweeps per `brokkr man check clippy`) proves the check
does not rely on `target-cpu=native`.

### A2. The bench's numbers depend on host codegen that nothing records next to the claim

The same ambient `-Ctarget-cpu=native` decides which varint-simd paths run
(`num.rs` picks between AVX2, BMI2/pdep and fallback paths by cfg). It also
decides how the scalar protohoggr code is vectorised. `brokkr bench` records a
digest of the cargo config, so stored baselines are protected. The doc-comment
numbers (C1, C2) carry no such stamp, and their ISA label is the only
environment record. Fix: as C1, numbers only in `reference/performance.md`
alongside the stamp.

### A3. The varint-simd build script reads the build host's CPU (latent)

varint-simd's `build.rs` runs `cpuid` to pick its `fast_pdep` cfgs, but only when
the `native-optimizations` feature is on, and it is not on here. So this is
latent. If anyone enables that feature to "make the SIMD side fair", the
compiled behaviour also depends on the CPU of the build host, outside the
rustflags digest that `brokkr bench` records. Worth one line wherever the bench
setup is documented.

---

## 5. Where the tests assume they run, and what they may touch

### W1. Raw `cargo bench` writes durable results into cargo's scratch directory

Following the bench header's own instruction (C6) puts criterion's data, and with
`html_reports` an HTML tree, into `target/criterion/`. Cargo owns that
directory, `cargo clean` and `brokkr clean` treat it as disposable, and each run
overwrites the `base` baseline. `brokkr bench` sets `CRITERION_HOME` to
`.brokkr/bench/`, which brokkr owns and its `clean` spares. So the correct
location exists. The repo just points people at the wrong one. Fix: C6. Then
`html_reports` serves no purpose in the brokkr flow and can go.

### W2. `.brokkr/` is not ignored

`git status` shows `.brokkr/` untracked. It holds `accounting/` journals and
`check-logs/`, and would hold `bench/` baselines once anyone runs `brokkr bench`.
None of that is ignored, so an `git add -A` commits brokkr's run state, and every
status shows noise. Whether baselines should be committed is a policy decision.
`brokkr man bench` says they "are not reconstructible from the source tree", which
argues for keeping them somewhere durable. Logs and accounting should not be
committed. Fix: ignore `.brokkr/` except possibly `.brokkr/bench/`, or have brokkr
write its own `.brokkr/.gitignore` the way cargo writes `target/CACHEDIR.TAG`.

### W3. The suite cannot run on non-x86 hosts, which is the only place the scalar fallback compiles

On aarch64 (Apple Silicon, Graviton), `benches/varint.rs` cannot compile, because
the varint-simd functions it calls are cfg-gated on x86 target features. That
fails the check's clippy phase. I did not verify whether the varint-simd library
itself builds there. If it does not, `cargo test --tests` fails as well. The
research doc already says "SSSE3 x86_64 only (no aarch64)". Meanwhile
`count_packed_varints_scalar` in `src/lib.rs` is
`#[cfg(not(target_arch = "x86_64"))]`. On the x86 host where the check runs, it is
never compiled, type-checked, linted or tested. The tests that mention the
scalar path ("Exercises SIMD 16-byte chunk + 1-byte scalar tail on x86-64") cover
only the SSE2 function's own tail. So the bench's dev-dependency blocks the one
platform where that fallback is live, and the platform where the check does run
cannot see it. The result is a silent degradation: a broken fallback would ship.

Fix: always compile the scalar function (`#[cfg_attr(target_arch = "x86_64", allow(dead_code))]`,
or better, make it the test oracle). Add a `#[test]` asserting
`count_packed_varints_sse2 == count_packed_varints_scalar` on varied inputs
(lengths 0 to 64, every alignment), and move varint-simd out of the package.
Enforceable: yes. The oracle test runs on every host, and a `--target
aarch64-unknown-linux-gnu` clippy sweep (no linking needed) would type-check the
non-x86 arm.

---

## Lateral findings outside the scope

### L1. `brokkr check` writes accounting and logs into the repo root (see W2)

Each check adds a directory under `.brokkr/accounting/` and a file under
`.brokkr/check-logs/`, which is ten logs after this morning's runs. Retention is
handled for logs ("newest ten kept" per the bench manual). I could not see any
retention for `accounting/`.

### L2. `brokkr bench --commit` uses git worktrees

The user's global instructions say "Never use git worktrees". The tool's only
way to measure a historical commit (which re-measuring C1 and C2 at `fcad0e7` and
at HEAD would need) is a persistent worktree. That conflict needs a decision
before anyone re-runs the old numbers.

### L3. Possible second MSRV problem in `src/lib.rs` (unverified)

`count_packed_varints_sse2` calls `_mm_movemask_epi8(chunk)` outside an `unsafe`
block inside a `#[target_feature(enable = "sse2")] unsafe fn`. That is clean on
current nightly, because arch intrinsics became safe to call in a matching
`target_feature` context, which I believe was in Rust 1.87. On 1.85, under
edition 2024's `unsafe_op_in_unsafe_fn` (warn by default), it would raise a
warning, and brokkr fails on any warning. I did not build on 1.85. The C8 MSRV
sweep would settle it.

### L4. Redundant cfg

`count_packed_varints_sse2` is already `#[cfg(target_arch = "x86_64")]`, and its
`use core::arch::x86_64::...` line repeats the same cfg. Harmless noise.

### L5. `.gitignore` entry `data` matches nothing in the repo

There is no `data` directory and no code that writes one. It looks inherited
from pbfhogg. This is the same kind of dead name-keyed guard as C9.

### L6. The README design-philosophy list and the lib.rs crate doc

The crate doc says "No external dependencies - pure Rust, no std beyond default".
That holds for `[dependencies]`. With dev-dependencies that need a C compiler for
the test suite (S1), "no external dependencies" is true for consumers and false
for contributors. Once the bench moves out it is true for both, and the
`dependency_rules` entry (Summary) keeps it that way.

### L7. The research doc's planet-scale volume table is the bench's real context and is unreachable

The deleted `notes/SIMD.md` explains why the bench exists (about 119 B varints
at planet scale, dense nodes 64%). It also explains why the decision is
reversible: there is a closed item named P3-20, and a recommendation to revisit
with multi-byte fast paths. None of that is in this repo. If the decision stays
in the doc comments, the durable reasoning should live in
`reference/performance.md` here, not in another repo's git history.

---

## Existing enforcement worth knowing (for calibrating the fixes)

- **Gremlins**: covers `benches/varint.rs`. The first check log of the day
  flagged its em-dashes and the U+2713 and U+2717 check marks, which have since
  been fixed. So text rules in benches are already enforced.
- **Clippy with `--all-targets`**: the strict `[lints.clippy]` set applies to the
  bench, minus its four crate-level allows (C7). Any diagnostic fails the check,
  so `#[expect]` plus `allow_attributes` would be enforced at once.
- **`dependency_rules`, `textlint`, `manifest`, `header`**: these phases run on
  every check and currently have nothing configured in `brokkr.toml` (it contains
  only `project = "protohoggr"`). They are the cheapest places to hold C1, C6, G4,
  L6 and the Summary's no-dependencies rule.

### G4. Phases that run and check nothing

`dependency_rules`, `textlint`, `header` and `manifest` all report as started in
every check log, and print nothing else. That is right when there are no rules,
but the log does not separate "checked, clean" from "nothing configured".
`member_check` and `fixture_lint` do say "not applicable". A reader of the log
cannot tell that, for example, the README's dependency claim is not held. If
brokkr printed "no rules configured" for these the way it does for
`member_check`, the gap would show.
