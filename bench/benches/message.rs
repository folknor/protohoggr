//! Tag-dispatch message loops over well-formed messages.
//!
//! Run with: `brokkr bench message`
//!
//! Each input set is `BUFS` distinct messages (see `protohoggr_bench`), and
//! every iteration decodes the next one rather than replaying one message:
//!
//! - `mixed`: varint, five-byte length-delimited, fixed32, and skipped
//!   fixed64 and varint fields.
//! - `fixed_len`: fixed32 and three-byte length-delimited fields only.
//! - `wide_tags`: two-byte tags, fixed32 and 130-byte length-delimited
//!   fields (two-byte length prefixes).
//!
//! The loop propagates errors with `?`, as decoders written against the
//! crate do. Throughput is in input bytes.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use protohoggr_bench::{BUFS, Inputs, candidate};
use std::hint::black_box;

fn bench_message(c: &mut Criterion) {
    let inputs = Inputs::generate();
    let mut group = c.benchmark_group("message");
    for (label, set) in inputs.messages() {
        let bytes: usize = set.iter().map(Vec::len).sum();
        group.throughput(Throughput::Bytes((bytes / BUFS) as u64));
        group.bench_with_input(BenchmarkId::new("question", label), set, |b, set| {
            let mut i = 0usize;
            b.iter(|| {
                i = (i + 1) % BUFS;
                black_box(candidate::msg_question(black_box(&set[i])))
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_message);
criterion_main!(benches);
