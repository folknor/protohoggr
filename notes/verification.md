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

## VER-003 - Negative tests assert only `is_err()`, and `WireError` has no kind to assert

`WireError` is `{ msg: &'static str }` with no kind, `PartialEq` or `Clone`,
so tests cannot say which failure they expect and none does. Cases where the
test cannot fail for the reason it names:

- `skip_field_unknown_wire_type` and `read_raw_field_unknown_wire_type` run on
  an empty cursor. If wire type 3 were accepted and routed to a skip path, the
  call would still fail on end-of-input. Wire type 7 and values above 7 are
  not tried.
- `decode_varint_11byte_rejected` and `decode_varint_10byte_overflow_high`
  pass on the 10th-byte overflow error (see VER-004).
- `read_fixed32_truncated`, `read_fixed*_truncated`, `read_raw_field_truncated_*`
  pass for any error.
- `WireError::msg` is a public field, so anyone can construct arbitrary errors
  (opus/tests).

Proposed: make `WireError` an enum of kinds (`Copy`, `PartialEq`, message via
`Display`) and assert kinds; give the unknown-wire-type tests input valid for
any accepted type (for example 16 zero bytes) so truncation cannot be the
reason. Enforceable by type plus tests; opus/tests notes `dead_code` does not
fire on pub enum variants, so a test constructing every variant from input
holds dead kinds; opus/machinery proposes a textlint rule banning bare
`.is_err())` in `tests/`.

Reported by: opus/tests, opus/machinery.

## VER-004 - The "varint too long" error branch is dead, and a test is named for it

In `read_varint_slow` and in `decode_packed_sint64_cumulative`, `shift` steps
7, 14, ..., 63 and returns or breaks on both branches at 63, so
`if shift > 63 { ... "varint too long" ... }` (and the cumulative
"Overlong varint - stop silently") never executes. Every over-long varint is
reported as "varint overflows u64". `decode_varint_11byte_rejected` says "too
long regardless of final byte" but is rejected by the 10th-byte overflow check,
duplicating `decode_varint_10byte_overflow`. No coverage run is part of the
check, so nothing notices.

Proposed: delete both branches, or restructure so one branch owns over-long
and one owns overflow; rename or drop the test. Enforceable by the error enum
plus a per-kind test (VER-003), or a periodic coverage lane
(`cargo llvm-cov`).

Reported by: opus/tests, opus/machinery.

## VER-005 - `wire_error_is_error` and `wire_error_display` assert less than they claim

`wire_error_is_error` is `let _: &dyn std::error::Error = &err;`, a
compile-time fact presented as a runtime test that cannot fail once it
compiles. Its comment says `source()` returns `None`, which is never asserted.
`wire_error_display` asserts only the `"wire format error:"` prefix
(opus/tests).

Proposed: assert `err.source().is_none()` if that is an intended contract, or
turn the trait check into a `const` static assertion (in `lib.rs`, per
opus/machinery) so it does not count as a test. codex/tests: the trait check
is meaningful and should remain.

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
  SIMD chunk "on x86-64"; elsewhere the same names run the scalar fallback
  (see VER-014).
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
bytes, an over-long sequence (the dead branch in VER-004), data counted as zero
by `count_packed_varints` but non-empty, and non-fused iteration (the packed
iterators resuming after `None`, filed in `notes/bugs.md`).

Proposed: a single private `#[inline]` varint-step function used by
`Cursor::read_varint`, `PackedIter::next` and the cumulative decoder, making
"mirrors" true by construction and removing the duplicated cold slow path
(opus/tests); then a differential test asserting
`cumulative(data, base) == PackedSint64Iter::new(data).scan(base, wrapping_add)`
over exhaustive short byte strings plus a seeded in-file PRNG (xorshift, no
dependency) for longer valid and corrupted bodies. The same approach covers
`read_varint_unchecked` vs `read_varint` and `encode_varint_to_slice` vs
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

## VER-012 - Unsafe-decoder tests take their precondition from the encoder under test, and one unsafe contract could be a type

`wire.rs` tests around `unchecked_*` feed `encode_varint_to_slice` output
straight into `read_varint_unchecked`, so an encoder regression turns a test
failure into an invalid unsafe call (codex/tests).

`encode_varint_to_slice`'s only safety requirement is `buf.len() >= 10`;
taking `&mut [u8; 10]` (or a capacity-bearing wrapper) makes it structural and
the function safe, with callers doing one `try_into()` per site
(codex/tests, codex/machinery, opus/machinery). codex/machinery: the
"validated regions" that `read_varint_unchecked` relies on have no
representation; a validated packed-region type could carry the proof.
`missing_safety_doc` establishes that documentation exists, not that callers
meet it.

Proposed: hand the unsafe decoder independently known valid byte vectors; the
signature change. Enforceable by the signature and independent fixtures.

Reported by: codex/tests, codex/machinery, opus/machinery.

## VER-013 - Unsafe code has no Miri lane, and `SAFETY:` comments are a convention nothing enforces

`read_varint_unchecked`, `read_varint_unchecked_slow`, `encode_varint_to_slice`,
`Cursor::rest` (sound only while the `pos <= data.len()` field invariant holds)
and the raw-pointer loads in `count_packed_varints_sse2` are tested only
natively, where a one-byte over-read does not crash. Debug `ub_checks` on
`get_unchecked` catch some over-reads in the dev profile; the SSE2 `ptr.add`
reads are not covered (opus/tests). The `SAFETY:` comments in the slow path
("slow path won't read OOB") are unverified. opus/tests: the tests slice
exactly to `n` bytes, so they are well shaped for Miri.

`src/lib.rs` comments every unsafe block; the tests' `unsafe` blocks and the
bench's two unsafe calls carry none (opus/tests, opus/machinery,
opus/bench). Private `read_varint_unchecked_slow` has no `# Safety` section.

opus/brokkr-config: Miri on the host and on foreign targets covers UB, 32-bit
`usize` (the `*_huge_len_*` tests in `tests/wire.rs` feed a length of
2^32 + 3, which only a 32-bit run turns into a check that `read_len_delimited`
narrows with `try_from` rather than truncating; on 64-bit they cannot tell),
big-endian byte order (every fixed-width
path uses `to_le_bytes`/`from_le_bytes`; nothing tests a big-endian target)
and the scalar fallback (VER-014) at once, with no linker. Proposed
`brokkr.toml` entries:

```toml
[[script_check]]
name = "miri-x86_64"
command = "cargo miri test --tests 2>&1 && echo miri-x86_64-ok"
expect = "miri-x86_64-ok"
stage = "background"
diagnostics = "rustc"

[[script_check]]
name = "miri-i686"
command = "cargo miri test --tests --target i686-unknown-linux-gnu 2>&1 && echo miri-i686-ok"
expect = "miri-i686-ok"
stage = "background"
diagnostics = "rustc"

[[script_check]]
name = "miri-s390x"
command = "cargo miri test --tests --target s390x-unknown-linux-gnu 2>&1 && echo miri-s390x-ok"
expect = "miri-s390x-ok"
stage = "background"
diagnostics = "rustc"
```

Notes from opus/brokkr-config: cost unmeasured (sysroot per target on first
run); background checks are joined before tests are listed, so Miri wall time
adds to every check; `cargo miri test --tests` builds every dev-dependency for
the target and whether varint-simd builds for `i686`/`s390x` is unknown
(VER-016 removes the risk); Miri runs outside brokkr's execution accounting;
brokkr has no `when = "gate"` key for `[[script_check]]`, so an expensive check
cannot be confined to the gate without also dropping cheap ones, and script
checks run under the markdown-only shortcut. opus/tests proposes a narrower
periodic lane restricted to `unchecked_`, `encode_to_slice_` and
`count_varints_`. Open intent question: is Miri's cost acceptable in the
routine run?

Enforceable: `undocumented_unsafe_blocks = "deny"` (optionally
`multiple_unsafe_ops_per_block`) in `[lints.clippy]`; `src/` already complies.
The Miri lane.

Reported by: opus/tests, opus/machinery, opus/bench, opus/brokkr-config;
codex/tests and codex/machinery also propose a Miri lane.

## VER-014 - The non-x86_64 `count_packed_varints` path is never compiled, linted or tested

`count_packed_varints_scalar` is `#[cfg(not(target_arch = "x86_64"))]`. On the
only host that runs the check it is never compiled, never seen by clippy and
never run; on other architectures the SSE2 path is absent. Nothing
cross-checks the SSE2 result against a reference, and the existing SIMD-length
tests (17 and 32 bytes) do not cover a mixed continuation-byte tail after a
vector chunk or offset subslices (codex/tests). README advertises a "scalar
fallback elsewhere" that has never been built (opus/brokkr-config). Integration
tests reach only the public API, so they cannot select an implementation. This
is the "production value with no injection point" shape. The bench's
x86-only dev-dependency also blocks the one platform where the fallback is
live (opus/bench).

Proposed: compile the scalar version unconditionally as a private function,
keep the dispatcher, and add a differential unit test asserting
`sse2 == scalar` over lengths 0..=64, every alignment and varied byte patterns
(or a `#[doc(hidden)]` test surface). Optional cross-target lint lane. Proposed
by opus/brokkr-config (the nightly toolchain has the aarch64-musl std; no
linker needed for clippy):

```toml
[[script_check]]
name = "clippy-aarch64-lib"
command = "cargo clippy --target aarch64-unknown-linux-musl --lib -- -D warnings 2>&1 && echo cross-clippy-ok"
expect = "cross-clippy-ok"
stage = "pre-test"
diagnostics = "rustc"
```

opus/brokkr-config notes a brokkr gap: there is no clippy-only sweep shape, and
a `[[check]] target` for a non-native triple always runs the test phase, which
cannot execute here (`aarch64-unknown-linux-musl` cannot run;
`i686-unknown-linux-gnu` lacks 32-bit link files on this host). codex/tests:
report which backend actually ran. Enforceable structurally (both always
compile) plus the differential test; the cross lane.

Reported by: codex/tests, codex/machinery, opus/tests, opus/machinery,
opus/bench, opus/brokkr-config.

## VER-015 - Tests run only under the dev profile; consumers ship release

The check builds and tests dev only (overflow checks and debug assertions on).
pbfhogg and elivagar run release, where: `read_varint_unchecked_slow` with a
too-long varint masks the shift instead of panicking (VER-020);
`get_unchecked` `ub_checks` are off (including the one in `Cursor::rest` that
backs its field invariant); the optimizer may act on UB
in the unsafe paths.

A second, related divergence: `brokkr test NAME` defaults to release while
`brokkr check` runs dev, and AGENTS.md documents both side by side. The first
focused run after a check rebuilds protohoggr and the whole dev-dependency tree
in release, and tests an artifact other than the one the check produced
(opus/bench, opus/brokkr-config).

The two hunters that proposed config differ:

- opus/bench: set `[test] debug = true` so focused runs reuse the check's
  debug artifacts.
- opus/brokkr-config: `[test] debug` becomes irrelevant once both sweeps pin
  `profile`; proposes two explicit sweeps and a complete gate profile, so
  `brokkr test NAME` runs the name under both:

```toml
[[check]]
name = "dev"
profile = "dev"

[[check]]
name = "release"
profile = "release"

[test]
default_package = "protohoggr"
default_profile = "gate"
gate_profile = "gate"

[test.profiles.gate]
description = "Both profiles, doctest carriers, coverage audit"
sweeps = ["dev", "release"]
certifies = "complete"
```

opus/brokkr-config also notes this makes `brokkr check --gate` work (today a
load-time error because no gate profile exists), and under
`certifies = "complete"` an unreferenced `[[check]]` entry is a load error, so
the release sweep cannot be quietly dropped. Cost: a release clippy and a
release build of the test graph including every dev-dependency (cold: tens of
seconds once; warm: a few hundred ms, estimated). opus/machinery alternatively
suggests a lane with `-C overflow-checks=off -C debug-assertions=off`.

Reported by: opus/tests, opus/machinery, opus/bench, opus/brokkr-config.

## VER-016 - Bench-only dev-dependencies are built into every test and clippy run of the library

`[dev-dependencies]` holds `criterion` (with `html_reports`; default features
pull rayon and plotters) and `varint-simd`. Cargo builds dev-dependencies for
every test target, so `tests/wire.rs`, which uses neither, pays for them:
`Cargo.lock` has 78 packages, 77 of them from these two; `target/debug/build/`
has 57 entries, none protohoggr's; and `alloca` (via criterion 0.8) compiles C
through `cc`, so the test suite of this pure-std crate needs a C compiler.
`clippy --all-targets` also type-checks the bench. Warm runs hide it (about
30 ms); the cost is paid on every cold build (fresh clone, `cargo clean`,
toolchain bump, lockfile update, any rustflags change). The cold cost was not
measured by any hunter. Every lockfile diff in the repo is in practice bench
churn (opus/bench). Downstream effects filed elsewhere: the SSSE3 requirement
(VER-017), cross-target Miri (VER-013), and the "no external dependencies"
claim (VER-033).

Proposed, by order of payoff (opus/tests): delete the varint-simd comparison
(the research is closed, per the doc comments' "P3-20, closed"); move the
remaining bench into a `publish = false` workspace member (for example
`bench/`) with its own dependencies, checked in a separate explicit lane; or
use `#![feature(test)]` benches on nightly. Interim: `criterion` with
`default-features = false, features = ["cargo_bench_support"]` (opus/bench), or
at least drop `html_reports` (opus/machinery). `brokkr deps` would flag the two
`syn` majors, both bench-only (opus/bench).

Enforceable by a dependency rule once the bench moves. opus/brokkr-config
proposes, as an interim dev boundary:

```toml
[[dependency_rule]]
name = "dev-dependencies-are-bench-only"
from = "protohoggr"
allow = ["criterion", "varint-simd"]
kinds = ["dev"]
```

tightened to `allow = []` after the move.

Reported by: codex/tests, codex/bench, codex/machinery, opus/tests, opus/bench,
opus/machinery, opus/brokkr-config.

## VER-017 - The check only compiles because the host enables SSSE3

`varint-simd` 0.4.1 exposes `decode_two_unsafe` / `decode_four_unsafe` only
under `cfg(target_feature = "ssse3")` (`cfg(any(..., doc))`), and the bench
calls them unconditionally. Baseline x86_64 has no SSSE3, so the bench - and
therefore `brokkr check`'s `clippy --all-targets` - compiles only because
`~/.cargo/config.toml` sets `-Ctarget-cpu=native`. On a default host or CI
image clippy fails with an unresolved-function error (a refusal, not a silent
degradation, per opus/machinery). On aarch64 varint-simd's x86 API is absent;
whether the library itself builds there was not verified (opus/bench).
codex/bench: the dependency has no portable architecture fallback.
`-Ctarget-cpu=native` also turns on AVX2 here, which switches varint-simd's
`u64` paths (`num.rs`), so `simd_single` and the encode side run AVX2 code
under labels that say SSSE3/SSE2 (opus/bench). Latent: varint-simd's
`build.rs` runs `cpuid` when `native-optimizations` is on (it is not), which
would make behaviour depend on the build host's CPU outside the rustflags
digest `brokkr bench` records (opus/bench).

Proposed: isolate the comparison in its own package (VER-016) with explicit
build requirements; gate the SIMD half on `cfg(target_feature = "ssse3")` with
a `compile_error!` or a skipped group that says so; or declare rustflags for
the bench crate in a repo-local `.cargo/config.toml`. Enforceable by a
baseline-x86_64 sweep (brokkr supports `rustflags-*` sweeps) and a non-x86
check.

Reported by: codex/bench, opus/bench, opus/machinery.

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
- The doc-comment benchmark numbers carry the same hidden condition (VER-024).

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

## VER-020 - `read_varint_unchecked`'s doc promises behaviour outside its contract that is false in debug

The safety doc says violating condition 2 (over-long or overflowing) "produces
an unspecified value (not UB, but meaningless)", and the summary says
"Infallible". An over-long terminated sequence makes
`read_varint_unchecked_slow` compute `<< 70`: in debug (the only profile the
tests run) that panics with "attempt to shift left with overflow"; in release
the shift is masked. The ignored `.plans/dynamic-beaming-giraffe.md`
contradicts the doc by calling it UB (opus/machinery).

Proposed: reword ("may panic in debug builds or return an unspecified value"),
remove the behavioural promise for invalid input (codex/machinery), or cap the
slow loop at 10 bytes, which costs nothing on the hot path (opus/machinery).
codex/machinery: do not add tests that violate an unsafe precondition just to
preserve the sentence. opus/tests and opus/machinery note a `#[should_panic]`
test under `debug_assertions` would document rather than guard it; capping the
loop holds it structurally.

Reported by: codex/machinery, opus/tests, opus/machinery.

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
- `encode_varint_to_slice`, the like-for-like counterpart to
  `encode_to_slice`, is never measured.

Proposed: separate raw-varint and complete-packed-field comparisons with
identical output contracts and byte-for-byte equality checked outside timing;
same input wrapping and padding on both sides; observe written slices the same
way; compare `encode_varint_to_slice` with `encode_unsafe` plus a 16-byte
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

## VER-024 - Durable performance and workload claims rest on no recorded, reproducible measurement

Claims: `Cursor::read_varint` doc (scalar 2.3x faster than batch4 for 1-byte,
tied for 3-byte, "perfectly predicted"); `encode_varint` doc (3.5x and 1.5x);
CHANGELOG 0.2.0 ("2-6x on decode, 1.5-3.5x on encode");
`encode_varint_to_slice` doc, README and CHANGELOG 0.4.0 ("~95% of
zigzag-encoded OSM way-ref deltas"). Reported problems:

- No retained result names hardware, compiler, flags, confidence intervals or
  bench revision (codex/bench, opus/machinery). The numbers arrived with
  `fcad0e7` (2026-03-02), before the tail-bias fix in `3219f18` (2026-04-12),
  and nothing re-measured since, so they come from the bench the project calls
  biased (opus/bench). The 0.3.0 CHANGELOG entry does not say the 0.2.0 numbers
  were measured under that bias.
- The ISA labels (SSSE3, SSE2) do not describe what runs under
  `-Ctarget-cpu=native` (VER-017).
- "tied for 3-byte" is the 2.6-byte mixed set (VER-023); the encode ratios
  compare unequal work (VER-022); the decode bench measures iterator traversal
  plus zigzag, not an isolated `read_varint` (codex/bench); "6x" is against
  `simd_single` (opus/bench).
- "tied" vs "2-6x" read as inconsistent (opus/machinery).
- The cited research doc (`dd7f69a:notes/SIMD.md` in pbfhogg) says node ID
  deltas are "mostly 1-3 bytes", lat/lon "mostly 1-2 bytes" and way ref deltas
  "2-4 bytes", contradicting the "1-byte dominant" and "~95% under 16384"
  claims; 60% of the bench's own "way ref" fixture is at or above 16384
  (opus/bench). codex/bench: the fixture cannot support the percentage, which
  does not disprove the real-world figure.
- "perfectly predicted": the data is 100% 1-byte in a period-10 pattern and
  nothing measured branch misses.
- 0.4.0's hot-path primitives (`decode_packed_sint64_cumulative`,
  `count_packed_varints`, `read_varint_unchecked`, `encode_varint_to_slice`)
  were added as performance work and none is benchmarked; `scalar_iter` still
  times the `PackedSint64Iter` path the 0.4.0 entry says is being replaced; the
  justification lives in an ignored `.plans/` file (codex/bench, opus/bench).
- The research context (planet-scale volume, the P3-20 decision and its
  reversibility) exists only in another repo's history (opus/bench).
- criterion baselines live in `target/criterion`, which `cargo clean` deletes
  (VER-026).

Proposed: `reference/performance.md` (the folder AGENTS.md prescribes, absent
here) holding qualified measurements with host, flags, toolchain, command, date
and the `brokkr bench` environment stamp; doc comments state the decision and
point there or at the bench; bench the production entry points whose
performance motivated them, against the baselines they replace. Enforceable
partly: a textlint rule rejecting speed-ratio patterns (`\d(\.\d)?x faster`)
in `src/` doc comments (opus/bench); numeric claims referencing result records
(codex/bench). Universal ratios and "perfect" prediction cannot be enforced by
a portable build; representativeness needs a documented corpus and review.

Reported by: codex/bench, codex/machinery, codex/tests, opus/bench,
opus/machinery, opus/brokkr-config.

## VER-025 - Durable source comments cite `notes/` in another repository

`Cursor::read_varint` and `encode_varint` doc comments say "See
`notes/SIMD.md` in pbfhogg (dd7f69a) for the full research doc (P3-20,
closed)". AGENTS.md: nothing durable may cite `notes/`, and a code comment must
carry its full context. The citation is cross-repository and pins a sha, and
`notes/SIMD.md` is no longer present at pbfhogg HEAD - reachable only through
history (opus/bench).

Proposed: carry the decision inline and move the evidence to
`reference/performance.md` (VER-024). Enforceable by text rule. Proposed by
opus/brokkr-config:

```toml
[[textlint]]
name = "durable-text-does-not-cite-notes"
pattern = '\bnotes/'
paths = ["src/**/*.rs", "tests/**/*.rs", "benches/**/*.rs", "README.md", "CHANGELOG.md", "docs/**", "reference/**"]
must_scan = ["src/lib.rs"]
message = "durable text must not cite notes/; carry the context inline"
```

opus/machinery additionally proposes forbidding 7-to-40-hex-digit sha-like
tokens in doc comments. Open intent question: does the rule cover another
repository's notes?

Reported by: codex/tests, codex/bench, codex/machinery, opus/tests, opus/bench,
opus/machinery, opus/brokkr-config.

## VER-026 - The bench header sends readers to raw `cargo bench` and cargo's scratch directory

`benches/varint.rs` says "Run with: cargo bench --bench varint", against
AGENTS.md's "never run raw `cargo`". Raw `cargo bench` writes criterion data
(and, with `html_reports`, an HTML tree) to `target/criterion/` under the
rolling name `base`: each run overwrites the last and `cargo clean` /
`brokkr clean` deletes it, along with the only record of the measurements the
doc comments cite. Criterion also picks Gnuplot or Plotters from installed
tools. `brokkr bench varint` sets `CRITERION_HOME` to `.brokkr/bench/`, which
brokkr owns and its clean spares, with commit-named baselines, an environment
stamp and refusal of cross-environment comparison.

Proposed: document `brokkr bench varint`; drop `html_reports`; set the report
backend explicitly if reproducible reports matter. Enforceable by text rule;
proposed by opus/brokkr-config:

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

## VER-027 - `#[allow]` attributes suppress nothing and would hide future casts

`src/lib.rs`: `cast_possible_truncation` on `read_varint_unchecked` and
`read_varint_unchecked_slow` (no casts); both allows on
`decode_packed_sint64_cumulative` (no `as` casts); `cast_possible_truncation`
on `encode_int32_field` / `_always` (`i32 as i64 as u64` widens; only sign-loss
applies); probably `cast_possible_truncation` on `encode_bytes_field`,
`_always` and `encode_packed_bool` (`usize as u64`; whether clippy lints that
direction is unverified). `benches/varint.rs` carries crate-wide
`#![allow(clippy::unwrap_used, cast_possible_truncation, cast_sign_loss,
cast_possible_wrap)]` with no `.unwrap()` and only `N as u64`, so all four look
unused and would hide a real truncating cast added later, for example while
reworking the `u8` SIMD widths (codex/bench, opus/bench). An unused `#[allow]`
is silent: a suppression keyed on a lint name keeps suppressing whether or not
its target remains. AGENTS.md's "use `#[allow(...)]` locally with care" is the
advice that produces these.

Proposed: replace every `#[allow]` with `#[expect]` (stable since 1.81) and add
`allow_attributes = "deny"` (optionally `allow_attributes_without_reason`) to
`[lints.clippy]`; `unfulfilled_lint_expectations` then flags stale ones and
brokkr fails on it. Fully enforceable by lint. Caveat from opus/brokkr-config:
with a cross-target clippy lane (VER-014), an expectation that fires on one
target only needs `cfg_attr`. codex/bench also suggests a syntax rule rejecting
crate-wide allows of these lints and checked conversions in fixtures.

Reported by: codex/bench, opus/tests, opus/bench, opus/machinery,
opus/brokkr-config.

## VER-028 - The clippy deny list is a copied template that misses the lints this crate needs

`[lints.clippy]` includes lints that cannot fire here
(`regex_creation_in_loops`, `await_holding_lock`, `await_holding_refcell_ref`,
`large_enum_variant`, `clone_on_ref_ptr`), which makes the list read as
curated while lints the crate does need are absent:
`undocumented_unsafe_blocks` and `multiple_unsafe_ops_per_block` (VER-013),
`allow_attributes` (VER-027), `arithmetic_side_effects` on the cursor
arithmetic and `indexing_slicing` on the decoder (bounded reads now go
through `Cursor::take`, but the varint paths and `read_raw_field` still index),
`missing_debug_implementations` (VER-035).

Proposed: curate the list for a decoder of untrusted lengths with unsafe hot
paths. The list is its own enforcement.

Reported by: opus/machinery; individual lints proposed by opus/tests,
opus/bench, opus/brokkr-config.

## Text checks

## VER-029 - The gremlins check is a denylist, narrower than the rule, and has let corruption through

AGENTS.md: "Em-dash, en-dash, strange quotes, whatever - they're all
verboten." brokkr's gremlins check bans named codepoints plus pictograph
ranges and deliberately spares arrows (`brokkr/src/gremlins.rs`,
`pictograph_name`). It passes, in tracked files today:

- U+FFFD REPLACEMENT CHARACTER, twice, in the `encode_tag_standalone` comment
  in `tests/wire.rs` - a mangled arrow, i.e. corruption, not style.
- U+2212 MINUS SIGN in the `encode_tag` Panics doc ("2^29 - 1").
- U+00D7 MULTIPLICATION SIGN in the `read_varint` and `encode_varint` docs,
  CHANGELOG 0.2.0 and the bench doc.
- U+2026 HORIZONTAL ELLIPSIS in the `zigzag_encode_64` doc.
- U+2264 LESS-THAN OR EQUAL in the bench doc.
- U+2192 RIGHTWARDS ARROW in many test comments, `lib.rs` and the bench.

The scanner also accepts a fixed extension list, so extensionless files such
as `LICENSE`, or a file renamed to an unrecognized extension, are not scanned
(codex/machinery); opus/machinery says it scans tracked plus
untracked-not-ignored `.rs`, `.md` and `.toml`; opus/tests could not tell
whether untracked files are scanned. Separately, an earlier `--fix-gremlins`
run rewrote the bench doc's check and cross marks to `[x]` and `[ ]`, turning
"does not fit" into what reads as an unticked checklist item - a silent change
of meaning (opus/machinery, opus/brokkr-config).

Proposed: an allowlist (ASCII-only for `.rs`, `.toml`, `.md`, with explicit
per-file exemptions), with U+FFFD a hard error everywhere; classify owned text
inputs explicitly and report unclassified files instead of exempting them
(codex/machinery); or narrow AGENTS.md to what the check enforces. brokkr's
`[gremlins] ban` is scan-only (`--fix-gremlins` has no ASCII mapping for extra
codepoints), so each hit is fixed by hand once. opus/brokkr-config proposes at
minimum `ban = ["U+FFFD"]`, extended per intent. opus/tests offers a fallback: a
short test in `tests/` rejecting any byte >= 0x80 in tracked text files. Open
intent question: which characters beyond U+FFFD count as "strange" (U+00D7,
U+2212, U+2026, U+2264/U+2265, arrows)?

Reported by: codex/tests, codex/machinery, opus/tests, opus/machinery,
opus/brokkr-config.

## Documentation claims

## VER-030 - README's Usage example and any doc examples are compiled by nothing

The check runs `cargo test --tests`, which excludes doctests (`doc_carrier:
false` in the plan). There are no doctests today, so the gap is latent, but
README's Usage block has never been compiled by anything; opus/brokkr-config
reads it as compiling, with an unused `wire_type` binding that shows it has not
run under `-D warnings`. brokkr's default `[test] doctests = false` is
justified in its manual by "CI runs under nextest"; this repo has no CI, so
that premise does not hold (opus/brokkr-config).

Proposed: `#![doc = include_str!("../README.md")]` in `src/lib.rs` (or a
`#[cfg(doctest)]` module) and a doctest-running check:
`[test] doctests = true` plus the complete gate profile in VER-015, whose
doctest carrier accounting reports a missing rustdoc stream as `missing`
(opus/brokkr-config). Caveat: markdown never counts as code for brokkr's
markdown-only shortcut, so a README-only edit would not trigger the build
unless a complete default profile waives the shortcut (unverified). Unverified:
whether a carrier with zero doctests passes as `no tests ran`.

Reported by: codex/machinery, opus/tests, opus/machinery, opus/brokkr-config.

## VER-031 - Intra-doc links and other rustdoc lints are evaluated nowhere

The rustdoc phase prints `started` and does nothing, because `brokkr.toml` has
no `[rustdoc]` table. `src/lib.rs` has intra-doc links (`[`read_varint`]
(Cursor::read_varint)`, `[`zigzag_encode_32`]`, `[`Cursor::read_sint32`]`,
`[`PackedSint32Iter`]`, `[`zigzag_decode_32`]`) that a rename would break
silently; clippy does not run rustdoc's link resolver. Private items carry doc
comments too.

Proposed by opus/brokkr-config: `[rustdoc]` with
`document_private_items = true`; sub-second on nightly. Enforced by the rustdoc
phase.

Reported by: opus/machinery, opus/brokkr-config.

## VER-032 - README and AGENTS.md hand-maintain inventories the code defines

README's "What's in the box" restates the public API and is already
incomplete (no `encode_tag`, `zigzag_decode_64`, `zigzag_decode_32`,
`WireError`, `WireResult` or the `WIRE_*` constants, per opus/brokkr-config).
README and AGENTS.md also state each field encoder has a skip-zero default and
an `_always` variant - true today for all twelve, held by nothing.

Proposed: cut the list to categories and link generated docs, or hold it with
a script check extracting `pub` item names from `src/lib.rs` and requiring each
in README (opus/tests, opus/brokkr-config); generation with a stale-output
check (codex/tests).

Reported by: codex/tests, codex/machinery, opus/tests, opus/brokkr-config.

## VER-033 - "No external dependencies" is enforced by nothing, and is true only for consumers

Stated in README, AGENTS.md, the `src/lib.rs` crate doc and CHANGELOG 0.2.0.
True for `[dependencies]` today; nothing would notice a dependency being added.
The test build pulls 78 packages and needs a C compiler (VER-016), so it is
false for contributors (opus/bench). The crate doc's second half, "no std
beyond default", has no checkable meaning: the crate uses `std::fmt`,
`std::error::Error` and `Vec`; if no-std plus `alloc` is the intent,
`#![no_std]` + `extern crate alloc` makes the compiler enforce it
(`core::error::Error` stable since 1.81), otherwise drop the phrase
(opus/machinery).

Proposed by opus/brokkr-config (an allow list fails closed):

```toml
[[dependency_rule]]
name = "no-external-dependencies"
from = "protohoggr"
allow = []
kinds = ["normal", "build"]
```

Alternatively a test parsing `Cargo.toml` via `env!("CARGO_MANIFEST_DIR")`
(opus/machinery). After the bench moves (VER-016), tightening to all kinds
makes the claim true for contributors too.

Reported by: codex/machinery, opus/tests, opus/bench, opus/machinery,
opus/brokkr-config.

## VER-034 - `count_packed_varints_sse2` carries `unsafe`, `target_feature` and a cfg it does not need

SSE2 is baseline on x86_64, so `#[target_feature(enable = "sse2")]` adds
nothing; on Rust 1.87+ `_mm_movemask_epi8` is safe in that context, leaving one
raw-pointer load whose safety follows from `chunks_exact(16)`. The function
could be safe, removing the `unsafe` call site in `count_packed_varints`; the
declared MSRV (1.87) no longer stands in the way (opus/tests, opus/machinery).
The `use
core::arch::x86_64::...` inside repeats the function's own
`#[cfg(target_arch = "x86_64")]` (opus/tests, opus/bench, opus/brokkr-config;
cosmetic). codex/machinery confirms the SSE2 safety justification and load
bounds hold for the selected branch.

Reported by: codex/machinery, opus/tests, opus/bench, opus/machinery,
opus/brokkr-config.

## VER-035 - Packed iterator types derive `Clone` but not `Debug`

`Cursor` derives both. `missing_debug_implementations` would hold it.

Reported by: opus/tests.

## VER-036 - Smaller README and source claims that are false or unenforced

- README: "All encoding functions skip zero/empty/false values by default"
  (repeated in AGENTS.md). `encode_varint(0)`, `encode_tag` and
  `encode_varint_to_slice` do not; the policy holds for field encoders.
  Behaviour tables can hold it (codex/tests, codex/machinery, opus/machinery).
- README: "see the doc comments on `PackedIter::next`, `skip_varint`, and
  `read_tag`". The `PackedIter::next` rationale is a `//` comment in the body,
  invisible in rustdoc. Move it to `///` on `PackedIter`; README-as-crate-docs
  with an intra-doc link would make a move fail rustdoc (opus/tests,
  opus/machinery).
- README: "rejects malformed sequences" can be read as covering non-canonical
  encodings; `read_varint` accepts `[0x80, 0x00]` as 0, which protobuf permits
  (opus/machinery, wording only).
- "branchless" 1-byte and 2-byte fast path (`encode_varint_to_slice` doc,
  README, CHANGELOG 0.4.0): the code is two `if` early returns; whether LLVM
  emits a cmov is unchecked, and no benchmark exercises the function. Reword
  ("1-byte and 2-byte fast paths"); an asm snapshot test could hold it but would
  be fragile across nightly bumps (codex/bench, codex/machinery, opus/tests,
  opus/bench, opus/machinery).

Reported by: codex/tests, codex/bench, codex/machinery, opus/tests,
opus/bench, opus/machinery.

## VER-037 - AGENTS.md, CLAUDE.md and LLM.md statements that are false or drift

- AGENTS.md: "`brokkr check` # gremlins + clippy + all tests". Doctests are
  excluded, benches are only linted, there is no fmt check. Reword without
  enumerating (opus/tests, opus/machinery, opus/brokkr-config).
- AGENTS.md: "30+ lints set to `deny`". A drifting count; "every lint in
  `[lints.clippy]` is denied" says it without drifting (opus/machinery,
  opus/brokkr-config).
- AGENTS.md: "Test module uses `#[allow(clippy::unwrap_used)]`". It is a
  crate-level inner attribute in `tests/wire.rs` that also allows
  `missing_docs`, which cannot fire on private test fns (opus/tests,
  opus/machinery).
- AGENTS.md: "Packed encoders take a `&mut Vec<u8>` scratch buffer".
  `encode_packed_bool` does not (opus/machinery).
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
- LLM.md: "This separation is enforced by tooling (review), not by convention
  alone" and the absolute claim about what development agents never see. The
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

## VER-038 - `.gitignore` entries that say something false or match nothing

- `Cargo.lock` is listed and tracked. The line is a no-op for the tracked
  file, reads as a "don't commit the lockfile" policy the repo does not follow,
  contradicts the commit-lockfiles rule, and would silently keep a regenerated
  lockfile out of `git add -A` after any `git rm --cached`. Agents told to
  commit lockfiles "unless they're .gitignored" are misled (opus/brokkr-config).
- `data` matches nothing; inherited from pbfhogg, and a future `data/` of
  fixtures would be silently ignored.
- `.plans/` hides `.plans/dynamic-beaming-giraffe.md` from review and gremlins
  (it has em-dashes); AGENTS.md retires `plans/` in favour of `notes/`, and the
  plan contradicts `lib.rs` on `read_varint_unchecked` (VER-020) and carries the
  only justification for the 0.4.0 API (VER-024).

Proposed: delete the `Cargo.lock` and `data` lines; move or delete the plan and
drop `.plans/`. Enforceable: a script check that no tracked file matches
`git check-ignore --no-index`, and that every pattern matches a path or is
allowlisted (opus/machinery).

Reported by: codex/machinery, opus/tests, opus/bench, opus/machinery,
opus/brokkr-config.

## VER-039 - `.brokkr/` is written on every run and is not ignored

Each check writes `.brokkr/check-logs/check-<ms>.log` and
`.brokkr/accounting/<run>/{plan.json, journal.jsonl}` (one run's plan 5,592
bytes, journal 95,745 bytes; the directory about 804 KiB, per codex/machinery).
`.brokkr/` shows as untracked in every `git status`; a `git add -A` would
commit run journals containing absolute paths; once `brokkr bench` runs,
baselines land in `.brokkr/bench/` too. pbfhogg and elivagar ignore
`.brokkr/*` and un-ignore `results.db`; brokkr's own docs describe
`.brokkr/*.db` as ignored (opus/brokkr-config, opus/machinery).

Interactions reported: brokkr's markdown-only shortcut classifies
untracked-not-ignored paths, so with `.brokkr/` present the tree may always
classify as code and the shortcut may be dead (opus/brokkr-config, unverified
whether brokkr excludes its own directory); gremlins and textlint read
untracked-not-ignored files, and brokkr writes `.toml` files there in other
configurations.

Retention readings differ: opus/machinery says logs and accounting are each
kept to the newest 10 (`run_log.rs`, `ACCOUNTING_RUNS_KEPT`); opus/bench could
not see retention for `accounting/`; codex/machinery says both retention paths
discard removal errors, so failed cleanup can silently defeat the bound.

Proposed: add `.brokkr/` (or the sibling `.brokkr/*` pattern) to
`.gitignore`; whether bench baselines should be kept durably is a policy
decision (`brokkr man bench` says they are not reconstructible). brokkr-side:
write a self-ignoring `.brokkr/.gitignore`, warn when its state root is not
ignored, report pruning failures. Enforceable by a script check
(`git check-ignore -q .brokkr && echo brokkr-state-ignored`, which fails closed
if the line is removed) or a brokkr preflight.

Reported by: codex/machinery, opus/tests, opus/bench, opus/machinery,
opus/brokkr-config.

## VER-040 - The default check sweep is labelled `all-features` for a crate with no features

With no `[[check]]` entry brokkr synthesizes one sweep named `all-features`
and passes `--all-features` to clippy and test. The crate has no features, so
the label reads as coverage of a feature matrix that does not exist, and it
fails open: a feature added later silently joins the only sweep and nothing
ever builds without it. The brokkr manual rejects `features = "all"` in
`[[check]]` for this reason (opus/brokkr-config). opus/tests: `--all-features`
is a no-op sweep here.

Proposed: explicit `[[check]]` entries (VER-015); a `no_default_features`
entry once a feature exists. Enforced by the presence of `[[check]]`.
opus/brokkr-config also lists, as free: `[manifest] sort_dependencies = true`.

Reported by: opus/tests, opus/brokkr-config.

## VER-041 - Unconfigured convention phases report `started` and nothing else

`header`, `textlint`, `manifest`, `script_check`, `dependency_rules` and
`rustdoc` print `phase X: started` on every check and do nothing, because they
are unconfigured; only `member_check` and `fixture_lint` say "not applicable".
A log reader infers they checked something; the README's dependency claim, for
example, looks held when it is not. The consolidated line `gremlins (11 files),
publish cycle: ok` is the only honest statement of coverage.

Proposed (brokkr-side): print "not configured" for inert phases. Enforceable by
brokkr's own tests.

Reported by: opus/bench, opus/machinery.

## VER-042 - Each check enters cargo three times for tests and runs an empty harness

Per run: `cargo test --no-run ... --tests` in prepare, the same again in the
test phase, then `cargo test ... --tests -- --test-threads=1`. Three cargo
startups and fingerprint walks (about 30 ms each warm), not three
compilations; prepare took 364 ms in one run and 415 ms in another
(codex/machinery). The lib unit harness has 0 tests (no `#[cfg(test)]` in
`src/`) and is built, linked and spawned every run.

Readings differ on the serial run: codex/tests and codex/machinery see no reason
for serial scheduling but say to measure before choosing a thread policy;
opus/tests and opus/machinery say serial costs nothing measurable here and the
suite would be sound in parallel or merged.

Proposed: brokkr-side, prepare once and execute the inventoried artifacts
directly (brokkr already does this for other lanes), enforced by an
orchestration test counting build invocations (codex/machinery). For the
empty harness: use it rather than disable it - the differential tests in
VER-007 and VER-014 and tests of private items (`sint32_wire_bits`,
`read_varint_slow`'s branches) need a `#[cfg(test)]` module (opus/tests,
opus/machinery); otherwise `[lib] test = false`. brokkr could warn on a harness
that always reports zero tests.

Reported by: codex/tests, codex/machinery, opus/tests, opus/machinery.

## VER-043 - brokkr's test runner polls for child exit every 250 ms

`wait_child` (`brokkr/src/test_runner/run.rs`) polls process completion at a
250 ms interval, and its watchdog sleeps and is joined during shutdown without
an immediate wakeup. Retained test phases take 306-307 ms consistently,
including one reporting 30 ms to build binaries, consistent with polling
dominating; the logs do not isolate it.

Proposed: child-exit notification and a wakeable watchdog with timed waits for
deadlines; enforced by runner tests showing completion wakes the waiter.

Reported by: codex/machinery.

## VER-044 - brokkr's markdown-only shortcut trusts git dirt, not a recorded successful run

`brokkr/src/scope.rs` skips Rust phases when the only uncommitted changes are
Markdown, justified by "the last full run already checked the same code", but
classification consults git dirt rather than a success record. Checking out an
unchecked commit and editing README skips compilation and tests. Markdown that
is compiled into the crate is also treated as prose.

Proposed: key reuse on a successful result for the source inputs, toolchain,
dependencies and build shape, or report a prose-only result without implying
full verification; enforced by a scenario test. See also VER-039 on whether the
shortcut fires here at all.

Reported by: codex/machinery.

## VER-045 - `brokkr check` needs more host than the library does, and its lock is global

- Gremlins enumerates with `git ls-files` and refuses outside a git
  repository; the serial harness uses Linux `/proc`, Unix sockets, peer
  credentials and pidfds, with a socket directory under a writable `$HOME`
  (long home paths can exceed the socket path limit). A portable library's
  standard verifier therefore needs a Linux development host. Proposed:
  separate portable crate verification from optional Linux supervision, with
  explicit state paths and capability probes before building.
- The lock lives under `$HOME/.brokkr` and is described as global, so a check
  of this crate can wait behind unrelated work in another checkout. Proposed:
  lock by actual resource ownership; enforced by concurrency tests.

Reported by: codex/machinery.

## VER-046 - `brokkr bench` can save an empty baseline, and its environment gate passes on missing fields

- Criterion filters bench IDs without failing when none match; brokkr forwards
  the filter and writes a baseline stamp after a successful exit without
  confirming any measurement exists. A mistyped filter or renamed ID saves an
  empty baseline. Proposed: require a non-empty selection and present results
  before publishing; test an unmatched filter.
- Stamp comparison checks only fields present on both sides, so a missing CPU,
  compiler, flags variable or config digest is not a mismatch. Proposed: record
  explicit absence and capture failure, version the stamp schema, require
  complete provenance by default.
- opus/bench: `brokkr bench --commit`, the only way to measure a historical
  commit (needed to re-measure the numbers in VER-024), uses git worktrees,
  which the user's global instructions forbid. Needs a decision before anyone
  re-measures.

Reported by: codex/bench, opus/bench.

## VER-047 - Published package contents are implicit

`Cargo.toml` has no `include` or `exclude`, so `cargo publish` ships
`AGENTS.md`, `CLAUDE.md`, `LLM.md`, `.review.toml` (with its audit id),
`brokkr.toml`, `benches/` and `tests/`. brokkr's `publish_cycle` checks
publication cycles, not contents. Proposed:
`include = ["src/**", "README.md", "CHANGELOG.md", "LICENSE*"]`; enforceable by
`cargo package --list` in a script check.

Reported by: opus/machinery.

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
