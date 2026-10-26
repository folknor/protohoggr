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

## VER-001 - Encoders are checked mostly by roundtrip, not against literal wire bytes

Many tests encode and decode with protohoggr and compare, so an encoder and
decoder that go wrong the same way cannot fail them. The `zigzag_encode_32`
sign-extension bug (fixed in 496598c) passed
`sint32_field_encode_decode_roundtrip` this way; the fix added literal vectors
for sint32 only. Sites still roundtrip-only or length-only:

- `int64_field_encode_decode_roundtrip`: no literal bytes for a negative int64.
- `int32_field_negative_sign_extends` accepts any eleven bytes, and
  `packed_int32_negative` checks tag, length prefix and total length but not
  the ten payload bytes. Both pass with wrong encoded values.
- `packed_sint64_`, `packed_int32_`, `packed_bool_encode_decode_roundtrip`.
- All fixed-width encoders (`fixed32`, `fixed64`, `float`, `double`): no
  literal bytes; byte order is pinned only transitively through
  `read_fixed32`/`read_fixed64` tests built on `to_le_bytes`.
- `encode_to_slice_*` and `unchecked_*`: output checked only by
  `read_varint`, which is itself pinned by literal tests (opus/tests calls
  this acceptable but implicit).
- `cumulative_roundtrip`, `_with_base`, `cumulative_boundary_values`,
  `cumulative_extreme_deltas`: input produced by `encode_packed_sint64`.
- codex/tests: the "boundary sweep" omits several seven-bit width boundaries.

Proposed: a shared literal conformance corpus of (value, expected bytes,
expected consumed length), with encoders and decoders run independently
against it, covering both sides of every seven-bit width boundary; at least
one golden row per encoder on a threshold-crossing value (negative, bit 31 or
63 set, multi-byte tag). opus/tests suggests taking bytes from the spec or
`protoc --encode` output checked in as literals. Keep roundtrips as a second
layer. Enforceable by the corpus tests, mutation testing (codex/tests), and
structurally if skip/always pairs are generated (see VER-008).

Reported by: codex/tests, opus/tests.

## VER-002 - `int64_field_positive` can pass with no assertion executed

It hand-decodes the varint after the tag and asserts only inside the loop when
it finds a terminal byte. Tag-only output, an unterminated payload, or
trailing bytes after a correct value all pass. It also maintains a second
varint decoder inside the test.

Proposed: `assert_eq!(buf, [0x08, 0x89, 0x27])` (codex/tests, opus/tests), or
decode with `Cursor` and assert the cursor is empty (opus/machinery).
Enforceable by the rewritten test plus mutation testing (codex/tests);
opus/machinery: no general lint, only a review rule against asserts that sit
inside loop conditionals.

Reported by: codex/tests, opus/tests, opus/machinery.

## VER-006 - Tests whose names or comments claim something they do not do

- `zigzag_decode_roundtrip` checks known values and never roundtrips.
- `zigzag_encode_decode_roundtrip` covers only the 64-bit pair; the 32-bit
  pair, which CHANGELOG now calls "a pure 32-bit bijection", has no roundtrip.
  Proposed: a strided `u32` sweep in debug, exhaustive in a release lane.
- `int32_field_positive_roundtrip` decodes with `read_varint` (u64) because
  `Cursor` has no int32 reader though it has `read_varint_i64`; the caller-side
  `as i32` path is untested (opus/tests calls this a small API gap).
- `count_varints_17_bytes` / `count_varints_32_bytes` say they exercise the
  SIMD chunk "on x86-64"; elsewhere the same names run the scalar fallback.
  The unit tests in `src/lib.rs` now name each backend they check.
- `cumulative_stops_on_overflow_varint` comment says "A valid varint [0x01]"
  but the data is `[0x02]` (opus/machinery).
- `cumulative_stops_matches_packed_iter_on_overflow`: see VER-007.

Enforceable: one-off rewrites; opus/tests says not mechanically holdable.

Reported by: opus/tests, opus/machinery.

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

Coverage gaps (opus/tests table, codex/tests):

- `encode_int32_field` and `encode_uint32_field`: zero omission never tested;
  their `_always` variants never called with non-zero values.
- `encode_fixed32_field`, `encode_fixed64_field`: never called with non-zero
  input; `float`/`double` skip variants only with `-0.0`. If
  `encode_fixed32_field` wrote a `WIRE_64BIT` tag or 8 bytes, nothing fails.
- Empty-input skip tested only for `encode_packed_uint32` and
  `encode_packed_bool`; not `_int32`, `_sint64`, `_sint32`.

Structural cause: the 24 field encoders are 12 pairs where the skip variant
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

## VER-009 - Scratch-buffer reuse and append semantics are never exercised

Every packed-encoder test passes a fresh `Vec::new()` as scratch and every
encoder test starts from an empty `buf`. Removing `scratch.clear()` from any
packed encoder, or an encoder that clears or overwrites `buf`, would pass.
`multi_field_message_roundtrip` and `read_raw_field_roundtrip` cover appends
only indirectly and for no packed encoder. codex/tests: whether scratch
contents after an empty call are meaningful is undocumented; the
implementation preserves them.

Proposed: per packed encoder, reuse a dirty scratch and a pre-filled `buf` and
assert exact output after the prefix, with empty input between non-empty
calls; a `dirty()` fixture helper as the default spelling. Structural
alternative: an owned `PackedEncoder` that clears internally (opus/tests).
Enforceable only by test convention, or by the structural change.

Reported by: codex/tests, opus/tests.

## VER-010 - Documented conversion and pass-through behaviours have no direct vectors

Missing (codex/tests):

- wider raw varints truncating through `PackedUint32Iter` and
  `PackedInt32Iter` (documented, now as protobuf's specified conversion; the
  uint32 roundtrip supplies only fitting values);
- negative packed int64 (`PackedInt64Iter` tested only with non-negative);
- non-canonical bools (values other than 0 and 1, multi-byte varints);
- reserved wire types passing through `read_tag` (documented behaviour);
- truncated packed tails, and cumulative decoding stopping on truncation.

Proposed: literal input/output tables, each followed by a sentinel value to
prove complete consumption. codex/tests: these are compatibility claims, not a
request for adversarial validation.

Reported by: codex/tests.

## VER-011 - Float tests use tolerance where the contract is bit-exact, and zero-copy is never shown

- `read_float` / `read_double` assert `(decoded - val).abs() < EPSILON`; the
  contract is bit-exact, which the later roundtrip tests already spell as
  `to_bits()`. `float_nan_roundtrip` / `double_nan_roundtrip` assert only
  `is_nan()`, so NaN payload and sign destruction would pass. The tests need
  `#[allow(clippy::approx_constant)]` only because they chose 3.14 and
  2.718281828 (opus/tests).
- opus/machinery: `float_cmp = "deny"` pushes tests toward the weaker
  approximate assertion, while `float_infinity_roundtrip` and the `-0.0` tests
  use `assert_eq!` on floats, which the lint does not see inside the macro, so
  the lint is enforced inconsistently.
- `read_len_delimited` and raw-field tests compare slice contents and never
  show the result borrows the right region of the input (codex/tests).

Proposed: `to_bits()` everywhere, literal IEEE bit patterns including distinct
NaN payloads and signed zero; pointer-and-length assertions for borrowed
slices. Enforceable by tests; a textlint rule against `EPSILON` in `tests/`
(opus/machinery).

Reported by: codex/tests, opus/tests, opus/machinery.

## VER-018 - The check builds and tests a host-tuned artifact under a user-global cargo config

`~/.cargo/config.toml`, outside the repo, sets for `x86_64-unknown-linux-gnu`:
`-Ctarget-cpu=native` (a Zen 5 part with AVX-512 per opus/tests),
`-Zthreads=16` (nightly-only), `-Clink-arg=-fuse-ld=wild` (needs gcc >= 16.1),
`rustc-wrapper = brokkr-rustc-guard`, `profile.dev.debug = "line-tables-only"`
and `jobs = 12`. Consequences reported:

- Tests validate code compiled for this CPU; crates.io consumers get baseline
  x86-64. Scalar loops may vectorize differently; a codegen-dependent bug
  would pass here and fail elsewhere, or the reverse, and nothing records the
  effective flags (silent degradation).
- `-Zthreads` makes every stable toolchain refuse to build on this host, which
  is why "nightly toolchain" appears in AGENTS.md and why the MSRV cannot be
  checked here (VER-019).
- A host without wild or gcc 16 fails at link time (refusal).
- The doc-comment benchmark numbers carry the same hidden condition.

Proposed: make the check's target explicit - a project `.cargo/config.toml`
with `rustflags = ["-Ctarget-cpu=x86-64"]` (later `-Ctarget-cpu` wins,
opus/tests), and/or a brokkr sweep with known `CARGO_ENCODED_RUSTFLAGS` that
records the flags; a lane that builds with host rustflags stripped proves the
crate does not need them (opus/machinery). Enforceable by the sweep or the
project config file.

Reported by: opus/tests, opus/machinery; codex/bench notes the
`-Ctarget-cpu=native` dependency.

## VER-019 - The toolchain is unpinned, and `rust-version` is never checked

- AGENTS.md says "nightly toolchain"; no `rust-toolchain.toml` exists, so
  nightly comes from the rustup default
  (`nightly-x86_64-unknown-linux-gnu (default)`). Which nightly runs is
  whatever was last installed; nightly clippy adds and renames lints, and
  under any-diagnostic-fails new lints break the check in untouched code, so a
  result is not reproducible across days (opus/machinery,
  opus/brokkr-config). brokkr test needs nightly (`-Z unstable-options
  --format json`), the rustdoc phase picks `--check` only on nightly, and Miri
  is nightly-only, so a stable-default host degrades three ways
  (opus/brokkr-config).
- `rust-version` is published to crates.io and checked by nothing: the check
  builds only on the host nightly, never on the declared minimum.
  opus/brokkr-config notes clippy's default-warn `incompatible_msrv` reads `rust-version` and,
  under brokkr, fails on std APIs stabilized after it, so API drift is caught;
  language-feature drift and lint-behaviour differences between the minimum
  and the host nightly are not (opus/machinery).

Proposed: pin a dated nightly in `rust-toolchain.toml`; an MSRV lane
(`cargo +<msrv> check --lib`) with host rustflags neutralized, which needs the
minimum toolchain installed. Separate the promises: library on its minimum
compiler, dev machinery on a specified nightly, and record compiler and brokkr
identities in results (codex/machinery). Open intent question: should the
toolchain be pinned?

Reported by: codex/machinery, opus/tests, opus/bench, opus/machinery,
opus/brokkr-config.

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

## Documentation claims




## VER-037 - AGENTS.md, CLAUDE.md and LLM.md statements that are false or drift

- AGENTS.md: "nightly toolchain" - see VER-019.
- CLAUDE.md: "Always run `brokkr fmt` before a commit". Nothing checks it.
  Proposed by opus/brokkr-config:

  ```toml
  [[script_check]]
  name = "rustfmt"
  command = "cargo fmt --all --check && echo rustfmt-clean"
  expect = "rustfmt-clean"
  stage = "pre-clippy"
  ```

  or a pre-commit hook (opus/machinery).
- LLM.md: the sentence claiming the separation is enforced by tooling was
  reworded to say it is kept by working practice and not audited here. Still
  open for the user: the absolute claim that the development agent never sees
  third-party source, and what the document should claim. The
  check does not audit agent access or provenance; `.review.toml` holds only an
  `[_audit] id`. opus/machinery: LLM.md is byte-identical in size to brokkr's
  copy, so it is a template. codex/machinery found insufficient evidence to
  call the historical claim false. Proposed: state the actual boundary for this
  repo.
- CHANGELOG Unreleased has a Breaking section while `Cargo.toml` says 0.4.0;
  nothing ties a Breaking entry to a version bump. A release-time script check
  could (opus/machinery).
- opus/brokkr-config: an `[[textlint]]` rule would hold "`unwrap_used` is
  denied in library code" against an `#[allow(clippy::unwrap_used)]` landing in
  `src/` (holds today):

  ```toml
  [[textlint]]
  name = "no-unwrap-escape-in-src"
  pattern = 'allow\([^)]*clippy::(?:unwrap_used|expect_used|unwrap_in_result)'
  paths = ["src/**/*.rs"]
  region = "code"
  message = "unwrap_used is denied in library code; return WireResult instead"
  ```

Reported by: codex/machinery, opus/tests, opus/machinery, opus/brokkr-config.

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

## VER-048 - The harness memory file for this project is stale and against the user's rules

`~/.claude/projects/-home-folk-Programs-protohoggr/memory/MEMORY.md` says "78
integration tests" and "~810 lines" (today 156 tests and about 1,300 lines) and
lists an older API. The user's rules say never to use that directory and not to
hard-code drifting counts; it is loaded into every session as if
authoritative. Proposed: delete it, moving anything worth keeping into
AGENTS.md.

Reported by: opus/tests, opus/machinery, opus/brokkr-config.

## VER-049 - `.claude/settings.local.json` allowlists raw `cargo`

It permits `Bash(cargo:*)`, `Bash(cargo test:*)` and `Bash(cargo clippy:*)`
while AGENTS.md says never run raw `cargo`. The file is ignored by the user's
global git ignore, so it is local only, but the permission layer permits the
violation and is the one place the rule could be enforced mechanically.

Reported by: opus/tests, opus/machinery.

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
