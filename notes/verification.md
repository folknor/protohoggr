# Verification findings

```
1. An entry is removed entirely when completely resolved. No historical record
   stays here.
2. Stable IDs never change and are never reused; removal leaves a gap.
3. An entry adjudicated against, verified incorrect, or whose outcome is that no
   action is taken owes comments at the code sites it names - and, where the
   claim touches a documented contract, the relevant `reference/` or `docs/`
   page - before the entry is removed, so the finding is not hunted again.
4. Once all findings are resolved, the file gets deleted.
5. Finding IDs are never written into the code or other documents. They are
   stable only until this document is drained; the next hunt writes new ones,
   and they are never deduplicated through git history. Carry the context
   inline instead.
```

From the verification hunt of 2026-10-26: where the tests, checks and the
machinery that runs them give a misleading account of the code, get in each
other's way, or cost more than they need to. Unverified: each entry is what
the hunters reported, and the fix pass decides. Defects are in
`notes/bugs.md`. "Reported by" names the hunter and scope (`codex/tests`,
`opus/brokkr-config` and so on). Where hunters disagree, both readings are
recorded. Unranked.

Several hunters observed the same baseline: the suite is hermetic at runtime
(no clock, environment, network, randomness, threads, file I/O, global state,
sleeps, child processes or nested builds), one auto-discovered integration
binary, and no CI or git hook - `brokkr check` run by hand on one host is the
only gate.

---

## Tests

## VER-007 - `decode_packed_sint64_cumulative` "mirrors `PackedSint64Iter`" is held by one case and a hand copy

The batch decoder re-implements the varint loop inline. The doc and CHANGELOG
0.4.0 promise identical stop semantics, but only the overflow-at-10th-byte case
is cross-checked, and `cumulative_stops_matches_packed_iter_on_overflow`
compares each side to a literal rather than to each other. Untested divergence
surfaces: a truncated multi-byte tail after valid values (the case the doc
names; no cumulative test at all), mid-stream truncation followed by valid
bytes, an over-long sequence (reaching the cumulative decoder's unreachable
`shift > 63` branch, kept on purpose for codegen), data counted as zero
by `count_packed_varints` but non-empty, and non-fused iteration (the packed
iterators resuming after `None`, filed in `notes/bugs.md`).

Proposed: a single private `#[inline]` varint-step function used by
`Cursor::read_varint`, `PackedIter::next` and the cumulative decoder, making
"mirrors" true by construction and removing the duplicated cold slow path
(opus/tests); then a differential test asserting
`cumulative(data, base) == PackedSint64Iter::new(data).scan(base, wrapping_add)`
over exhaustive short byte strings plus a seeded in-file PRNG (xorshift, no
dependency) for longer valid and corrupted bodies. The same approach covers
`read_varint_unchecked` vs `read_varint` and `encode_varint_to_array` vs
`encode_varint` (opus/machinery). Enforceable by the test; structurally by the
shared core.

Reported by: opus/tests, opus/machinery; codex/tests lists the truncated-tail
case among missing vectors (VER-010).

## VER-008 - Skip-zero variants and packed empties are partly untested, and the pairs are hand-synced copies

The coverage gaps are closed by literal-byte tests. What remains is the
structural cause: the 24 field encoders are 12 pairs where the skip variant
duplicates the `_always` body instead of calling it, and the six typed packed
iterators are six copies of the same ~50 lines. `packed_typed_iter_empty`,
`_remaining_bytes` and the `check_size_hint` macro list the six types by hand,
so a seventh gets no coverage and no warning.

Proposed: define skip variants as `if v != default { X_always(..) }` or
generate pairs with one `macro_rules!`; generate typed iterators as a generic
`PackedTyped<'a, D>` or a macro that also emits `FusedIterator`; one generic or
macro-driven test per behaviour, with default-zero, default-nonzero,
always-zero and always-nonzero cases per family and wire bytes independent of
the implementation. Enforceable structurally.

Reported by: codex/tests, opus/tests.

## Benchmark

## VER-021 - The benchmark has no correctness gate and is never run by the check

CHANGELOG 0.3.0 says the tail-bias fix made "all strategies decode the same
values". Nothing asserts it. `make_packed_sint64` returns `(values, body)` and
every decode bench drops `values`; each strategy `black_box`es its outputs and
compares them to nothing; `decode_four_unsafe`'s `_overflow` flag is ignored.
Every SIMD safe-decode loop breaks on error and scalar iteration stops silently,
yet throughput always advertises 8,000 elements, so a regression that decodes
fewer values reads as faster (codex/bench). The three batch/tail loops are
maintained separately over padded slices, and padding can mask an incomplete
final varint (codex/bench). Changing the small pattern to a value needing more
than 3 zigzag bytes would make `decode_four_unsafe::<u16>` mis-segment the
stream while the bench keeps reporting a time (opus/bench).

The check type-checks the bench (`clippy --all-targets`) but the test phase
(`--tests`) never builds or runs it, so link- or run-time failures pass: for
example `decode_two_unsafe` checks
`T::MAX_VARINT_BYTES + U::MAX_VARINT_BYTES > 16` with a runtime `panic!`, and
`make_packed_sint64`'s hand-written framing loops index `buf[pos]`
(opus/bench). The full run is 11 cases at criterion's default 3 s warmup plus
5 s measurement, about 88 s, none of it validating correctness (codex/bench).

Proposed: one function per strategy returning its decoded values, a `#[test]`
asserting each equals the oracle, and the timed closure calling the same
function; shared batch/tail adapters tested around batch boundaries
(non-multiples of two and four) with padding behind a fixture type carrying
the logical length; run benches in test mode (`cargo test --benches` /
`-- --test`) as a lane; derive throughput from the validated fixture; a check
of the expected bench inventory so renamed or removed cases cannot shrink
coverage silently (codex/bench). Enforceable by tests in the check.

Reported by: codex/bench, opus/bench, opus/machinery.

## VER-022 - Scalar and SIMD sides of the benchmark do different work

- Encode: `scalar` times `encode_packed_sint64` (zigzag, varint into scratch,
  tag and length, then a copy of the 8,000- or 20,800-byte body into `buf`);
  `simd_single` times bare `varint_simd::encode::encode_to_slice` with no
  framing. That wrapper encodes into a `[u8; 16]` then does a bounds-checked
  variable-length copy per value; the fast use of that library is
  `encode_unsafe` with an unconditional 16-byte store (opus/bench).
- SIMD encode passes only `pos` to `black_box`, not the written bytes, so the
  optimizer is not prevented from eliminating stores (codex/bench; not shown to
  happen).
- Decode: `scalar_iter` wraps input in `black_box`, the SIMD closures do not;
  `simd_single` gets the unpadded slice and so falls into varint-simd's
  copy-to-stack-buffer path for the last values, while batch tails get the
  padded slice (opus/bench).
- `padded()` says the 16 zero bytes keep SIMD reads in bounds; since the 0.3.0
  fix the batch loops never read padding, so the stated reason no longer holds
  and the padding only steers the tail into a no-copy path (opus/bench).
- `encode_varint_to_array`, the like-for-like counterpart to
  `encode_to_slice`, is never measured.

Proposed: separate raw-varint and complete-packed-field comparisons with
identical output contracts and byte-for-byte equality checked outside timing;
same input wrapping and padding on both sides; observe written slices the same
way; compare `encode_varint_to_array` with `encode_unsafe` plus a 16-byte
store. Enforceable partly: shared adapter signatures make symmetry structural;
fairness itself cannot be linted.

Reported by: codex/bench, opus/bench.

## VER-023 - Benchmark datasets are mislabelled

- `large_delta_data` is documented "3-5 byte varints after zigzag" and its ID
  says `large_3B`. Its ten-value pattern zigzags to 4 two-byte and 6 three-byte
  values: 3,200 two-byte and 4,800 three-byte per iteration, mean 2.6 bytes,
  body 20,800 bytes, no 4- or 5-byte values.
- `small_delta_data` is called "typical OSM dense node ID deltas"; it is a
  period-10 pattern, all 1-byte, repeated 800 times.

Proposed: generate cases from stated byte-length distributions, name IDs after
them, and assert the distribution in a test (count bytes per varint, body
length); derive labels from fixture metadata. Enforceable by test.

Reported by: codex/bench, opus/bench, opus/machinery.



## VER-026 - The bench header sends readers to raw `cargo bench` and cargo's scratch directory

The bench header said "Run with: cargo bench --bench varint", against
AGENTS.md's "never run raw `cargo`". Raw `cargo bench` writes criterion data
(and, with `html_reports`, an HTML tree) to `target/criterion/` under the
rolling name `base`: each run overwrites the last and `cargo clean` /
`brokkr clean` deletes it, along with the only record of the measurements the
doc comments cite. Criterion also picks Gnuplot or Plotters from installed
tools. `brokkr bench varint` sets `CRITERION_HOME` to `.brokkr/bench/`, which
brokkr owns and its clean spares, with commit-named baselines, an environment
stamp and refusal of cross-environment comparison.

Partly addressed by moving the bench into its own package `bench/`: the header now
says `brokkr bench varint`, and criterion is built with
`default-features = false, features = ["cargo_bench_support"]`, so there is
no `html_reports` and no Plotters backend (Gnuplot is still picked up if
installed). Remaining: nothing enforces it. Enforceable by text rule; proposed
by opus/brokkr-config (bench path now `bench/benches/**/*.rs`):

```toml
[[textlint]]
name = "no-raw-cargo-instructions-rs"
pattern = '\bcargo (?:bench|test|build|check|clippy|run|doc)\b'
paths = ["src/**/*.rs", "tests/**/*.rs", "benches/**/*.rs"]
region = "comment"
message = "point at the brokkr command (brokkr bench, brokkr test, brokkr check), not raw cargo"

[[textlint]]
name = "no-raw-cargo-instructions-md"
pattern = '\bcargo (?:bench|test|build|check|clippy|run|doc)\b'
paths = ["README.md"]
message = "point at the brokkr command, not raw cargo"
```

opus/tests also notes the bench hand-strips tag and length with byte loops
instead of using `Cursor`.

Reported by: codex/bench, opus/tests, opus/bench, opus/machinery,
opus/brokkr-config.

## Lints and suppressions

## VER-028 - The clippy deny list is a copied template that misses the lints this crate needs

`[lints.clippy]` includes lints that cannot fire here
(`regex_creation_in_loops`, `await_holding_lock`, `await_holding_refcell_ref`,
`large_enum_variant`, `clone_on_ref_ptr`), which makes the list read as
curated while lints the crate does need are absent:
`multiple_unsafe_ops_per_block` (`undocumented_unsafe_blocks` is now denied),
`arithmetic_side_effects` on the cursor
arithmetic and `indexing_slicing` on the decoder (bounded reads now go
through `Cursor::take`, but the varint paths and `read_raw_field` still index).

Proposed: curate the list for a decoder of untrusted lengths with unsafe hot
paths. The list is its own enforcement.

Reported by: opus/machinery; individual lints proposed by opus/tests,
opus/bench, opus/brokkr-config.

## Repository and check machinery

## VER-042 - The lib unit-test harness holds only the `count_packed_varints` tests

The `#[cfg(test)] mod tests` in `src/lib.rs` now exists and holds the
`count_packed_varints` backend tests. Still missing from it: the differential
test in VER-007 and tests of private items (`sint32_wire_bits`,
`read_varint_slow`'s branches) (opus/tests, opus/machinery).

The brokkr-side parts of this finding (three cargo invocations per check, a
dead-harness warning) are tracked in brokkr's bz tracker. Readings differ on
the serial `--test-threads=1` run: codex/tests and codex/machinery say measure
before choosing a thread policy; opus/tests and opus/machinery say serial costs
nothing measurable here.

Reported by: codex/tests, codex/machinery, opus/tests, opus/machinery.

## Outside the repository

## VER-050 - Where cross-project conventions should live as brokkr config

opus/brokkr-config raises, as an intent question: the AGENTS.md conventions
(gremlins, no `notes/` citations, no raw cargo) apply across projects. A
user-wide `~/.config/brokkr/brokkr.toml` (absent on this host) is host-local in
the same way the harness memory directory is - on a host without it the rules
silently stop applying. A shared file pulled in with `include` assumes a
sibling checkout and fails every brokkr command where it is missing. A
per-project copy, as pbfhogg does with `scripts/check_doc_links.py`, is the
only form that travels with the repository.

Reported by: opus/brokkr-config.
