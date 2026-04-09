//! Varint decode/encode microbenchmarks comparing scalar (protohoggr) vs SIMD (varint-simd).
//!
//! Run with: cargo bench --bench varint
//!
//! ## Decode scenarios (8000 zigzag-encoded sint64 deltas)
//! 1. scalar    — current `PackedSint64Iter`
//! 2. simd_batch — `decode_four_unsafe<u16>` for ≤2-byte varints (small deltas),
//!    `decode_two_unsafe<u32>` for ≤5-byte varints (large deltas)
//! 3. simd_single — safe `decode::<u64>` one at a time
//!
//! ## Encode scenarios
//! 4. scalar    — current `encode_packed_sint64`
//! 5. simd_single — `encode_to_slice` per value
//!
//! ## Type constraints on batch decode
//!   `decode_four_unsafe` reads 16 bytes and requires the sum of max varint bytes ≤ 16.
//!   u16 (max 3 bytes) → 4×3=12 ✓, u32 (max 5 bytes) → 4×5=20 ✗.
//!   `decode_two_unsafe` → u32: 2×5=10 ✓, u64: 2×10=20 ✗.
//!   So for sint64 values that happen to fit in u32 (most OSM deltas), the best batch
//!   decode is decode_two<u32>; for tiny deltas (≤u16), decode_four<u16> is available.

#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use protohoggr::{
    PackedSint64Iter, encode_packed_sint64, zigzag_decode_64, zigzag_encode_64,
};

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

/// Pad buffer with 16 zero bytes so SIMD pointer reads don't go out of bounds.
fn padded(data: &[u8]) -> Vec<u8> {
    let mut p = data.to_vec();
    p.extend_from_slice(&[0u8; 16]);
    p
}

// ---------------------------------------------------------------------------
// Decode benchmarks
// ---------------------------------------------------------------------------

fn bench_decode_small(group: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>) {
    let (_, small_packed) = small_delta_data();
    let label = "small_1B";
    let data = &small_packed;
    let pad = padded(data);

    // 1) scalar PackedSint64Iter
    group.bench_with_input(BenchmarkId::new("scalar_iter", label), data, |b, d| {
        b.iter(|| {
            for v in PackedSint64Iter::new(black_box(d)) {
                black_box(v);
            }
        });
    });

    // 2) simd batch — decode_four_unsafe<u16×4> (small deltas fit in u16)
    group.bench_with_input(BenchmarkId::new("simd_batch4_u16", label), &pad, |b, d| {
        b.iter(|| {
            let mut pos = 0usize;
            let end = d.len() - 16;
            while pos < end {
                let ptr = d[pos..].as_ptr();
                let (a, bv, cv, dv, la, lb, lc, ld, _overflow): (
                    u16, u16, u16, u16, u8, u8, u8, u8, bool,
                ) = unsafe { varint_simd::decode::decode_four_unsafe(ptr) };
                black_box(zigzag_decode_64(u64::from(a)));
                black_box(zigzag_decode_64(u64::from(bv)));
                black_box(zigzag_decode_64(u64::from(cv)));
                black_box(zigzag_decode_64(u64::from(dv)));
                pos += usize::from(la) + usize::from(lb) + usize::from(lc) + usize::from(ld);
            }
            // tail: safe single decode for remaining values
            while pos < end {
                if let Ok((v, len)) = varint_simd::decode::decode::<u64>(&d[pos..]) {
                    black_box(zigzag_decode_64(v));
                    pos += len;
                } else {
                    break;
                }
            }
        });
    });

    // 3) simd safe single decode
    group.bench_with_input(BenchmarkId::new("simd_single", label), data, |b, d| {
        b.iter(|| {
            let mut pos = 0usize;
            while pos < d.len() {
                if let Ok((v, len)) = varint_simd::decode::decode::<u64>(&d[pos..]) {
                    black_box(zigzag_decode_64(v));
                    pos += len;
                } else {
                    break;
                }
            }
        });
    });
}

fn bench_decode_large(group: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>) {
    let (_, small_packed) = small_delta_data();
    let (_, large_packed) = large_delta_data();
    let label = "large_3B";
    let data = &large_packed;
    let pad = padded(data);

    // 1) scalar
    group.bench_with_input(BenchmarkId::new("scalar_iter", label), data, |b, d| {
        b.iter(|| {
            for v in PackedSint64Iter::new(black_box(d)) {
                black_box(v);
            }
        });
    });

    // 2) simd batch — decode_two_unsafe<u32,u32> (large deltas fit in u32)
    group.bench_with_input(BenchmarkId::new("simd_batch2_u32", label), &pad, |b, d| {
        b.iter(|| {
            let mut pos = 0usize;
            let end = d.len() - 16;
            while pos < end {
                let ptr = d[pos..].as_ptr();
                let (a, bv, la, lb): (u32, u32, u8, u8) =
                    unsafe { varint_simd::decode::decode_two_unsafe(ptr) };
                black_box(zigzag_decode_64(u64::from(a)));
                black_box(zigzag_decode_64(u64::from(bv)));
                pos += usize::from(la) + usize::from(lb);
            }
            while pos < end {
                if let Ok((v, len)) = varint_simd::decode::decode::<u64>(&d[pos..]) {
                    black_box(zigzag_decode_64(v));
                    pos += len;
                } else {
                    break;
                }
            }
        });
    });

    // Also benchmark batch2 with u32 for small deltas, for direct comparison
    let small_pad = padded(&small_packed);
    group.bench_with_input(
        BenchmarkId::new("simd_batch2_u32", "small_1B"),
        &small_pad,
        |b, d| {
            b.iter(|| {
                let mut pos = 0usize;
                let end = d.len() - 16;
                while pos < end {
                    let ptr = d[pos..].as_ptr();
                    let (a, bv, la, lb): (u32, u32, u8, u8) =
                        unsafe { varint_simd::decode::decode_two_unsafe(ptr) };
                    black_box(zigzag_decode_64(u64::from(a)));
                    black_box(zigzag_decode_64(u64::from(bv)));
                    pos += usize::from(la) + usize::from(lb);
                }
                while pos < end {
                    if let Ok((v, len)) = varint_simd::decode::decode::<u64>(&d[pos..]) {
                        black_box(zigzag_decode_64(v));
                        pos += len;
                    } else {
                        break;
                    }
                }
            });
        },
    );

    // 3) simd safe single
    group.bench_with_input(BenchmarkId::new("simd_single", label), data, |b, d| {
        b.iter(|| {
            let mut pos = 0usize;
            while pos < d.len() {
                if let Ok((v, len)) = varint_simd::decode::decode::<u64>(&d[pos..]) {
                    black_box(zigzag_decode_64(v));
                    pos += len;
                } else {
                    break;
                }
            }
        });
    });
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_sint64");
    group.throughput(criterion::Throughput::Elements(N as u64));
    bench_decode_small(&mut group);
    bench_decode_large(&mut group);
    group.finish();
}

// ---------------------------------------------------------------------------
// Encode benchmarks
// ---------------------------------------------------------------------------

fn bench_encode(c: &mut Criterion) {
    let (small_values, _) = small_delta_data();
    let (large_values, _) = large_delta_data();

    let mut group = c.benchmark_group("encode_sint64");
    group.throughput(criterion::Throughput::Elements(N as u64));

    for (label, values) in [("small_1B", &small_values), ("large_3B", &large_values)] {
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
        group.bench_with_input(
            BenchmarkId::new("simd_single", label),
            values,
            |b, vals| {
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
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_decode, bench_encode);
criterion_main!(benches);
