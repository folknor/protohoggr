//! Varint decode/encode microbenchmarks comparing scalar (protohoggr) vs SIMD (varint-simd).
//!
//! Run with: `brokkr bench varint`
//!
//! Inputs: 8000 zigzag-encoded sint64 values, as one-byte (`small_1B`),
//! mostly three-byte (`large_3B`) or exclusively ten-byte (`ten_10B`)
//! varints.
//!
//! ## Decode scenarios
//! 1. scalar    - current `PackedSint64Iter`
//! 2. `simd_batch` - `decode_four_unsafe<u16>` for ≤2-byte varints (small deltas),
//!    `decode_two_unsafe<u32>` for ≤5-byte varints (large deltas)
//! 3. `simd_single` - safe `decode::<u64>` one at a time
//!
//! ## Encode scenarios
//! 4. scalar    - current `encode_packed_sint64`
//! 5. `simd_single` - `encode_to_slice` per value
//!
//! ## Which comparisons are built
//! varint-simd is x86_64-only, so on other targets only the scalar scenarios
//! exist. On x86_64, `simd_single` and the encode comparison need only SSE2
//! (baseline), but the batch decoders need SSSE3, which baseline x86_64 lacks:
//! they are built only under `-Ctarget-feature=+ssse3` (or a `-Ctarget-cpu`
//! that implies it). Whatever is left out is named on stderr at startup.
//!
//! Every varint-simd benchmark ID ends in the highest instruction-set level
//! that changes varint-simd's code in this build (`avx2`, `ssse3` or `sse2`):
//! AVX2 switches its `u64` single-value paths, including the batch loops'
//! `decode::<u64>` tail, so the same scenario name measures different code at
//! different levels.
//!
//! ## Type constraints on batch decode
//!   `decode_four_unsafe` reads 16 bytes and requires the sum of max varint bytes ≤ 16.
//!   u16 (max 3 bytes) → 4×3=12 [x], u32 (max 5 bytes) → 4×5=20 [ ].
//!   `decode_two_unsafe` → u32: 2×5=10 [x], u64: 2×10=20 [ ].
//!   So for sint64 values that happen to fit in u32 (most OSM deltas), the best batch
//!   decode is `decode_two<u32>`; for tiny deltas (≤u16), `decode_four<u16>` is available.

use criterion::{BenchmarkGroup, BenchmarkId, Criterion, criterion_group, measurement::WallTime};
use protohoggr::{PackedSint64Iter, encode_packed_sint64};
use std::hint::black_box;

const N: usize = 8000;

// ---------------------------------------------------------------------------
// Test data generation
// ---------------------------------------------------------------------------

/// Build N i64 delta values cycling through the given pattern, then encode as a
/// packed sint64 field body (zigzag + varint, no outer tag/length prefix).
fn make_packed_sint64(deltas: &[i64]) -> (Vec<i64>, Vec<u8>) {
    let values: Vec<i64> = deltas.iter().copied().cycle().take(N).collect();
    let mut buf = Vec::new();
    let mut scratch = Vec::new();
    encode_packed_sint64(&mut buf, &mut scratch, 1, &values);
    // Strip the tag + length prefix to get the raw packed body.
    let mut pos = 0usize;
    // skip tag varint
    while buf[pos] >= 0x80 {
        pos += 1;
    }
    pos += 1;
    // skip length varint
    while buf[pos] >= 0x80 {
        pos += 1;
    }
    pos += 1;
    let packed_body = buf[pos..].to_vec();
    (values, packed_body)
}

/// Small deltas (1-byte varints after zigzag): typical OSM dense node ID deltas.
fn small_delta_data() -> (Vec<i64>, Vec<u8>) {
    make_packed_sint64(&[1, 2, 1, 3, 1, 2, 4, 1, 5, 2])
}

/// Large deltas (3-5 byte varints after zigzag): typical way ref deltas.
fn large_delta_data() -> (Vec<i64>, Vec<u8>) {
    make_packed_sint64(&[
        5000, -3200, 18000, -7500, 42000, -15000, 8700, -2100, 31000, -9900,
    ])
}

/// Ten-byte varints only, both signs: zigzag needs ten bytes exactly when
/// `v >= 2^62` or `v < -2^62`. The longest varint protobuf allows, and the
/// path where a 64-bit decoder's final-byte overflow check runs.
fn ten_byte_data() -> (Vec<i64>, Vec<u8>) {
    let data = make_packed_sint64(&[
        1 << 62,
        -(1 << 62) - 1,
        i64::MAX,
        i64::MIN,
        (1 << 62) + 0x1234_5678,
        -(1 << 62) - 0x1234_5679,
        0x5555_5555_5555_5555,
        -0x5555_5555_5555_5556,
        (1 << 62) | 0x7f,
        -(1 << 62) - 0x80,
    ]);
    assert_eq!(data.1.len(), 10 * N, "every value must encode to ten bytes");
    data
}

// ---------------------------------------------------------------------------
// varint-simd comparisons (x86_64 only; batch decoders need SSSE3)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
mod simd {
    use super::{BenchmarkGroup, BenchmarkId, WallTime, black_box};
    use protohoggr::{zigzag_decode_64, zigzag_encode_64};

    /// Highest instruction-set level that changes varint-simd's code in this
    /// build. Appended to every varint-simd benchmark ID.
    const LEVEL: &str = if cfg!(target_feature = "avx2") {
        "avx2"
    } else if cfg!(target_feature = "ssse3") {
        "ssse3"
    } else {
        "sse2"
    };

    fn id(name: &str, label: &str) -> BenchmarkId {
        BenchmarkId::new(format!("{name}_{LEVEL}"), label)
    }

    /// Safe single-value decode loop over `d`, from `pos` to `end`.
    fn decode_single_tail(d: &[u8], mut pos: usize, end: usize) {
        while pos < end {
            if let Ok((v, len)) = varint_simd::decode::decode::<u64>(&d[pos..]) {
                black_box(zigzag_decode_64(v));
                pos += len;
            } else {
                break;
            }
        }
    }

    /// `simd_single`: safe `decode::<u64>` one value at a time.
    pub fn decode_single(group: &mut BenchmarkGroup<'_, WallTime>, label: &str, data: &[u8]) {
        group.bench_with_input(id("simd_single", label), data, |b, d| {
            b.iter(|| decode_single_tail(d, 0, d.len()));
        });
    }

    /// `simd_single` encode: `encode_to_slice` per zigzag value.
    pub fn encode_single(group: &mut BenchmarkGroup<'_, WallTime>, label: &str, values: &[i64]) {
        group.bench_with_input(id("simd_single", label), values, |b, vals| {
            let mut out = vec![0u8; vals.len() * 10];
            b.iter(|| {
                let mut pos = 0usize;
                for &v in black_box(vals) {
                    let zz = zigzag_encode_64(v);
                    let len = varint_simd::encode::encode_to_slice(zz, &mut out[pos..]);
                    pos += usize::from(len);
                }
                black_box(pos);
            });
        });
    }

    /// Pad buffer with 16 zero bytes so SIMD pointer reads don't go out of bounds.
    #[cfg(target_feature = "ssse3")]
    fn padded(data: &[u8]) -> Vec<u8> {
        let mut p = data.to_vec();
        p.extend_from_slice(&[0u8; 16]);
        p
    }

    /// `simd_batch4_u16`: `decode_four_unsafe<u16 x 4>`, then a safe tail.
    #[cfg(target_feature = "ssse3")]
    pub fn decode_batch4_u16(group: &mut BenchmarkGroup<'_, WallTime>, label: &str, data: &[u8]) {
        group.bench_with_input(id("simd_batch4_u16", label), &padded(data), |b, d| {
            b.iter(|| {
                let mut pos = 0usize;
                let data_end = d.len() - 16; // actual data length (padding excluded)
                let batch_end = data_end.saturating_sub(16); // safe zone for 16-byte reads
                while pos < batch_end {
                    let ptr = d[pos..].as_ptr();
                    let (a, bv, cv, dv, la, lb, lc, ld, _overflow): (
                        u16,
                        u16,
                        u16,
                        u16,
                        u8,
                        u8,
                        u8,
                        u8,
                        bool,
                    ) = unsafe { varint_simd::decode::decode_four_unsafe(ptr) };
                    black_box(zigzag_decode_64(u64::from(a)));
                    black_box(zigzag_decode_64(u64::from(bv)));
                    black_box(zigzag_decode_64(u64::from(cv)));
                    black_box(zigzag_decode_64(u64::from(dv)));
                    pos += usize::from(la) + usize::from(lb) + usize::from(lc) + usize::from(ld);
                }
                decode_single_tail(d, pos, data_end);
            });
        });
    }

    /// `simd_batch2_u32`: `decode_two_unsafe<u32, u32>`, then a safe tail.
    #[cfg(target_feature = "ssse3")]
    pub fn decode_batch2_u32(group: &mut BenchmarkGroup<'_, WallTime>, label: &str, data: &[u8]) {
        group.bench_with_input(id("simd_batch2_u32", label), &padded(data), |b, d| {
            b.iter(|| {
                let mut pos = 0usize;
                let data_end = d.len() - 16;
                let batch_end = data_end.saturating_sub(16);
                while pos < batch_end {
                    let ptr = d[pos..].as_ptr();
                    let (a, bv, la, lb): (u32, u32, u8, u8) =
                        unsafe { varint_simd::decode::decode_two_unsafe(ptr) };
                    black_box(zigzag_decode_64(u64::from(a)));
                    black_box(zigzag_decode_64(u64::from(bv)));
                    pos += usize::from(la) + usize::from(lb);
                }
                decode_single_tail(d, pos, data_end);
            });
        });
    }
}

/// Name, on stderr, every varint-simd comparison this build leaves out.
fn report_omitted_comparisons() {
    if cfg!(not(target_arch = "x86_64")) {
        eprintln!(
            "varint bench: varint-simd comparisons are x86_64-only; running the scalar benchmarks alone"
        );
    } else if cfg!(not(target_feature = "ssse3")) {
        eprintln!(
            "varint bench: simd_batch4_u16 and simd_batch2_u32 not built: they need SSSE3 \
             (build with -Ctarget-feature=+ssse3 or a -Ctarget-cpu that has it)"
        );
    }
}

// ---------------------------------------------------------------------------
// Decode benchmarks
// ---------------------------------------------------------------------------

fn bench_scalar_iter(group: &mut BenchmarkGroup<'_, WallTime>, label: &str, data: &[u8]) {
    group.bench_with_input(BenchmarkId::new("scalar_iter", label), data, |b, d| {
        b.iter(|| {
            for v in PackedSint64Iter::new(black_box(d)) {
                black_box(v);
            }
        });
    });
}

fn bench_decode(c: &mut Criterion) {
    let (_, small_packed) = small_delta_data();
    let (_, large_packed) = large_delta_data();
    let (_, ten_packed) = ten_byte_data();

    let mut group = c.benchmark_group("decode_sint64");
    group.throughput(criterion::Throughput::Elements(N as u64));

    bench_scalar_iter(&mut group, "small_1B", &small_packed);
    #[cfg(all(target_arch = "x86_64", target_feature = "ssse3"))]
    simd::decode_batch4_u16(&mut group, "small_1B", &small_packed);
    #[cfg(target_arch = "x86_64")]
    simd::decode_single(&mut group, "small_1B", &small_packed);

    bench_scalar_iter(&mut group, "large_3B", &large_packed);
    #[cfg(all(target_arch = "x86_64", target_feature = "ssse3"))]
    {
        simd::decode_batch2_u32(&mut group, "large_3B", &large_packed);
        // batch2 with u32 for small deltas too, for direct comparison
        simd::decode_batch2_u32(&mut group, "small_1B", &small_packed);
    }
    #[cfg(target_arch = "x86_64")]
    simd::decode_single(&mut group, "large_3B", &large_packed);

    // The batch decoders take at most five-byte varints, so only the
    // single-value comparison applies here.
    bench_scalar_iter(&mut group, "ten_10B", &ten_packed);
    #[cfg(target_arch = "x86_64")]
    simd::decode_single(&mut group, "ten_10B", &ten_packed);

    group.finish();
}

// ---------------------------------------------------------------------------
// Encode benchmarks
// ---------------------------------------------------------------------------

fn bench_encode(c: &mut Criterion) {
    let (small_values, _) = small_delta_data();
    let (large_values, _) = large_delta_data();
    let (ten_values, _) = ten_byte_data();

    let mut group = c.benchmark_group("encode_sint64");
    group.throughput(criterion::Throughput::Elements(N as u64));

    for (label, values) in [
        ("small_1B", &small_values),
        ("large_3B", &large_values),
        ("ten_10B", &ten_values),
    ] {
        // 4) scalar encode_packed_sint64
        group.bench_with_input(BenchmarkId::new("scalar", label), values, |b, vals| {
            let mut buf = Vec::with_capacity(vals.len() * 2);
            let mut scratch = Vec::with_capacity(vals.len() * 10);
            b.iter(|| {
                buf.clear();
                encode_packed_sint64(&mut buf, &mut scratch, 1, black_box(vals));
                black_box(&buf);
            });
        });

        // 5) varint-simd encode_to_slice per value
        #[cfg(target_arch = "x86_64")]
        simd::encode_single(&mut group, label, values);
    }

    group.finish();
}

criterion_group!(benches, bench_decode, bench_encode);

// criterion_main! plus the omitted-comparison notice. Keeps the macro's
// configure_from_args, so baseline and filter arguments still apply.
fn main() {
    report_omitted_comparisons();
    benches();
    Criterion::default().configure_from_args().final_summary();
}
