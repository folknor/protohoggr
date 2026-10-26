# Verification hunt: `tests/wire.rs` against `src/lib.rs`

Scope: the integration suite (`tests/wire.rs`, 156 tests, one binary) judged
against the behaviour in `src/lib.rs` it claims to cover, plus the check
machinery (`brokkr check`) and host configuration that its results depend on.
Lateral findings outside the scope are included and marked as such.

Short version of the shape: the suite is pure. No clock, environment, network,
randomness, threads or shared state, so question 4 mostly comes back empty.
The weaknesses are of other kinds:

- byte output that is never pinned, so encoder and decoder can drift together
  (the `zigzag_encode_32` bug fixed in 496598c is the proof that this happens);
- error assertions that pass on any error;
- skip-zero variants that are never called with non-zero input;
- a scratch-reuse contract that no test exercises;
- tests that run one profile on one CPU, with a host-global `target-cpu=native`;
- a dev-dependency tree (criterion and varint-simd) that every test build pays
  for and that needs a C compiler;
- a gremlins guard that fails open, and has already let a corrupted byte
  sequence into the test file.

Line numbers are deliberately not cited. Tests and functions are named instead.

---

## 1. Tests that prove nothing

### 1.1 Roundtrip tests whose two sides come from the same crate

Many tests encode with protohoggr, decode with protohoggr, and compare. If the
encoder and decoder go wrong in the same way, these tests cannot fail. This is
not hypothetical. Before 496598c, `zigzag_encode_32` sign-extended into 10-byte
varints and `sint32_field_encode_decode_roundtrip` passed, because `read_sint32`
truncates to 32 bits. The fix added byte-pinned tests for sint32 only
(`sint32_field_extremes_are_five_bytes`, `packed_sint32_extremes_are_five_bytes`).
The same exposure remains for:

- `int64_field_encode_decode_roundtrip`: encoder `as u64`, decoder `as i64`. No
  literal bytes for a negative int64. Only `int32_field_negative_sign_extends`
  pins anything, and it pins the length (11), not the bytes.
- `packed_sint64_encode_decode_roundtrip`, `packed_int32_encode_decode_roundtrip`,
  `packed_bool_encode_decode_roundtrip`: no literal bytes. `packed_int32_negative`
  checks the tag, the length prefix and the total length, but not the payload.
- `fixed32_field_encode_decode_roundtrip`, `fixed64_...`, `float_...`, `double_...`:
  no literal bytes for any fixed-width encoder. Byte order is pinned only
  transitively, because `read_fixed32` and `read_fixed64` are tested against
  `to_le_bytes` input. A change to `read_fixed32` (for example a fast path that
  is also wrong in the encoder) would break the chain silently.
- `encode_to_slice_*` and `unchecked_*`: the output is checked only by feeding
  it back through `read_varint`. That is acceptable because `read_varint` is
  pinned by literal tests (`decode_varint_*`), but the dependency is implicit.
- `cumulative_roundtrip`, `cumulative_roundtrip_with_base`,
  `cumulative_boundary_values`, `cumulative_extreme_deltas`: the input is
  produced by `encode_packed_sint64`, so the cumulative decoder is checked only
  against the crate's own encoder.

Fix: give every encoder at least one golden-bytes assertion on a value that
crosses an interesting threshold (negative, bit 31 or bit 63 set, a multi-byte
tag). Keep the roundtrips as a second layer. The most durable way to hold this
is a table-driven golden test: rows of (encoder call, expected bytes), with the
bytes taken from the protobuf spec or from `protoc --encode` output checked in as
literals. Enforceable only by convention, or by a structural rule (see 2.8)
that generates skip/always pairs, so one golden row per type covers both.

### 1.2 Error assertions that pass on any error

Every negative test is `assert!(x.is_err())`. `WireError` is
`{ msg: &'static str }` with no kind, no `PartialEq` and no `Clone`. A test
therefore cannot say which failure it expects without string matching, and none
of them does. Concrete cases where this makes a test unable to fail:

- `skip_field_unknown_wire_type` and `read_raw_field_unknown_wire_type` call
  `skip_field(3)`, `skip_field(4)` and so on on an empty cursor. If wire type 3
  were accidentally accepted and routed to `skip_varint` or to a fixed-width
  skip, the call would still fail on EOF and the test would still pass. As
  written, these tests cannot detect acceptance of reserved wire types. Wire
  type 7 and values above 7 are not tried at all.
- `decode_varint_11byte_rejected` says "too long regardless of final byte". The
  input is rejected by the 10th-byte overflow check (`0x80 > 1`), not by any
  length check, and the test cannot tell which (see 2.3: the length check is
  dead code).
- `decode_varint_10byte_overflow_high` uses the same path. It is
  indistinguishable from `decode_varint_10byte_overflow`.
- `read_fixed32_truncated`, `read_raw_field_truncated_*` and similar tests would
  all pass if the reader failed for an unrelated reason.

Fix: make `WireError` an enum of kinds (`Copy`, `PartialEq`, still zero-cost)
with the message produced by `Display`. Tests then assert
`Err(WireError::UnknownWireType(3))`, `Err(WireError::VarintOverflow)` and so
on. For the wire-type tests, supply input that would be valid for any accepted
type (for example 16 zero bytes), so the only possible failure is the one under
test. Enforceable by type: once errors are an enum, `assert_eq!` on the kind is
the natural spelling, and a dead kind shows up as an unused variant (rustc
`dead_code` does not fire on pub enum variants, so a grep-style check, or a test
that constructs every variant from input, holds it).

### 1.3 Tests that pass vacuously

- `int64_field_positive` hand-decodes the varint after the tag and asserts only
  inside the loop when it finds a terminal byte. If the encoder emitted the tag
  and then only continuation bytes, or the tag alone, the loop would finish
  without asserting and the test would pass. Replace it with
  `assert_eq!(buf, [0x08, 0x89, 0x27])`.
- `wire_error_is_error` contains `let _: &dyn std::error::Error = &err;`. It is
  a compile-time assertion dressed as a runtime test and cannot fail once it
  compiles. Its comment talks about `source()` returning `None`, which it never
  asserts. Either assert `err.source().is_none()` or turn it into a `const`
  static assertion with no `#[test]`, so it does not count as a test.
- `wire_error_display` asserts only the `"wire format error:"` prefix.

### 1.4 Tests whose names claim something they do not do

- `zigzag_decode_roundtrip` checks known values and never roundtrips.
- `zigzag_encode_decode_roundtrip` covers only the 64-bit pair. The 32-bit pair,
  which is the one CHANGELOG now calls "a pure 32-bit bijection", has no
  roundtrip test at all. It has a handful of known values in
  `zigzag_encode_32_known_values` and `zigzag_decode_roundtrip`. The bijection
  claim is cheap to check: a strided sweep over `u32` (every 2^12-th value plus
  the edges) in debug, or exhaustively in a release-only lane.
- `int32_field_positive_roundtrip` decodes with `read_varint` (u64). That is
  forced, because `Cursor` has no int32 reader even though it has
  `read_varint_i64`. The asymmetry is a small API gap: the int32 decode path that
  consumers actually write is `as i32` on the caller side, and it is untested.
- `cumulative_stops_matches_packed_iter_on_overflow` says it verifies that the
  batch decoder and `PackedSint64Iter` "produce the same output". It compares
  each one to a literal. It never derives one from the other, so the "mirrors"
  claim is held for one input.
- `count_varints_17_bytes` and `count_varints_32_bytes` say they exercise the
  SIMD chunk "on x86-64". On every other architecture the same names run the
  scalar fallback (see 5.2).
- `packed_typed_iter_size_hint` says "all typed wrappers delegate to
  `PackedIter::size_hint`" and checks this for one 5-byte input.

### 1.5 Setup that silently does nothing: the scratch buffer and append semantics

AGENTS.md states that "packed encoders take a `&mut Vec<u8>` scratch buffer to
avoid repeated allocation". Every packed-encoder test passes a fresh
`Vec::new()` as scratch, and every encoder test starts from an empty `buf`. So:

- if `scratch.clear()` were removed from `encode_packed_uint32`, `_int32`,
  `_sint64` or `_sint32`, stale scratch content would be emitted and no test
  would fail;
- if any encoder cleared or overwrote `buf` instead of appending, no test would
  fail. `multi_field_message_roundtrip` and `read_raw_field_roundtrip` cover
  appends indirectly, but only for a few field encoders and none of the packed
  ones.

Fix: one test per packed encoder that reuses a dirty scratch (pre-filled with
junk) and a pre-filled `buf`, and asserts the exact output after the prefix. A
fixture helper `fn dirty() -> Vec<u8>` makes this the default spelling for new
tests. Enforceable only by test convention. A structural alternative is to make
scratch an owned `PackedEncoder` type that clears internally, which removes the
contract from callers.

### 1.6 Skip-zero variants that are never called with a non-zero value

README: "each with a skip-zero default and an `_always` variant". Coverage by
pair:

| encoder | skip variant, zero | skip variant, non-zero | always, zero | always, non-zero |
|---|---|---|---|---|
| varint | yes | yes | yes | roundtrip |
| int64 | yes | positive only (vacuous, 1.3) | yes | roundtrip |
| int32 | **no** | positive (roundtrip), negative (length only) | yes | **no** |
| uint32 | **no** | yes | yes | **no** |
| bool | yes | yes | yes | yes |
| bytes | yes | yes | yes | roundtrip |
| sint64 | yes | yes | yes | yes |
| sint32 | yes | yes | yes | yes |
| fixed32 | yes | **no** | roundtrip | roundtrip |
| fixed64 | yes | **no** | roundtrip | roundtrip |
| float | yes | only -0.0 | roundtrip | roundtrip |
| double | yes | only -0.0 | roundtrip | roundtrip |

Consequence: if `encode_fixed32_field` wrote a `WIRE_64BIT` tag, or 8 bytes, for
non-zero input, nothing would fail. The skip variants duplicate the body of
their `_always` sibling instead of calling it (see 2.8), so the two can diverge.

Packed encoders: the empty-input skip is tested only for `encode_packed_uint32`
and `encode_packed_bool`. `encode_packed_int32`, `_sint64` and `_sint32` have no
empty test.

### 1.7 Approximate float comparisons where exact equality is the contract

`read_float` and `read_double` compare with `(decoded - val).abs() < EPSILON`.
At these magnitudes that happens to imply bit equality, but it reads as a
tolerance. The contract is bit-exact, which the later `*_encode_decode_roundtrip`
tests already spell as `to_bits()` equality. `float_nan_roundtrip` and
`double_nan_roundtrip` assert only `is_nan()`, so NaN payload and sign
preservation are untested even though the code does preserve them. Both tests
also need `#[allow(clippy::approx_constant)]` only because they chose 3.14 and
2.718281828 as fixtures. Any non-constant-looking value removes the allow.

---

## 2. Guards and claims that have stopped holding

### 2.1 The gremlins check is a denylist, and it has already let corruption through

The test file contains two U+FFFD REPLACEMENT CHARACTERs in the
`encode_tag_standalone` comment (`// field 1, WIRE_LEN ?? (1 << 3) | 2`). An
arrow (U+2192) was mangled into invalid UTF-8 at some point and then
re-encoded. `brokkr check` passes. The first check log in `.brokkr/check-logs/`
shows what the guard looks for: U+2014 EM DASH and U+2713/U+2717 DINGBAT. It
does not flag:

- U+2192 RIGHTWARDS ARROW: about a dozen occurrences in `tests/wire.rs` (comments
  in `decode_sint32_standalone`, `packed_sint32_iter`, `packed_iter_size_hint`,
  `encode_tag_standalone`, section headers, the cumulative tests) and one in
  `src/lib.rs`;
- U+00D7 MULTIPLICATION SIGN in the `read_varint` and `encode_varint` doc
  comments;
- U+2026 HORIZONTAL ELLIPSIS in the `zigzag_encode_64` doc;
- U+2212 MINUS SIGN in the `encode_tag` panics doc ("2^29 - 1" uses U+2212, a
  classic gremlin);
- U+FFFD itself.

AGENTS.md says "Em-dash, en-dash, strange quotes, whatever - they're all
verboten", which is an allowlist intent. The guard is keyed on a fixed list of
names, so it fails open for every character not on the list and reports
nothing. Fix: make the guard an allowlist: ASCII-only for `.rs`, `.toml` and
`.md`, with an explicit per-file exemption if any file ever needs non-ASCII.
U+FFFD should be a hard error everywhere regardless, because it always means
corruption. Enforceable mechanically: this is the gremlins check, inverted. If
brokkr cannot be configured for this, a 10-line test in `tests/` that walks the
tracked text files and rejects any byte >= 0x80 holds it without brokkr.

The guard also scanned "11 files". Whether untracked files (such as this
`notes/` file before it is committed) are scanned is not visible from the repo.
If selection is keyed on `git ls-files`, a file is checked only after it has
been committed.

### 2.2 `README.md` claims a doc comment that is a plain comment

README: "These are intentional trade-offs documented in the source - see the doc
comments on `PackedIter::next`, `skip_varint`, and `read_tag`." The rationale on
`PackedIter::next` is a `//` comment inside the function body, not a `///` doc
comment. It does not appear in rustdoc. False today. Fix: move it to `///` on
`PackedIter` (the type, since `next` is a trait impl). Not mechanically
enforceable as stated. Linking README to rustdoc with
`#![doc = include_str!("../README.md")]` would at least make the intra-doc link
`[PackedIter::next]` fail rustdoc if it moved.

### 2.3 Dead error path: "varint too long" is unreachable

In both `read_varint_slow` and `decode_packed_sint64_cumulative`,
`shift` steps 7, 14, ..., 63. At 63 the `shift == 63` branch always returns or
breaks before the increment, so `if shift > 63 { ... "varint too long" ... }`
can never execute. Every over-long varint is reported as "varint overflows u64"
instead. The test comment in `decode_varint_11byte_rejected` describes a
length-based rejection that does not exist. No coverage run is part of the
check, so nothing notices. Fix: delete the branch, or restructure so that one
branch owns over-long and one owns overflow, and assert the kind (1.2).
Enforceable by an error enum plus a test that produces each kind. Running
`cargo llvm-cov` in a periodic lane would also surface it.

### 2.4 `decode_packed_sint64_cumulative` "mirrors `PackedSint64Iter`": held by two tests and a hand copy

The batch decoder re-implements `read_varint`'s loop inline. "Mirrors" is held
only by `cumulative_stops_on_overflow_varint` and
`cumulative_stops_matches_packed_iter_on_overflow`. Untested divergence
surfaces:

- a truncated multi-byte tail after valid values (`[0x02, 0x80]`);
- an over-long sequence (shares the dead branch above);
- a body that `count_packed_varints` counts as zero but that contains bytes
  (only `[0x80]`-style data; behaviour matches today by accident of the early
  return);
- the iterator not being fused (2.5). The batch decoder stops for good; the
  iterator resumes.

Fix, structural: a single private varint-step function
(`fn decode_varint_at(data, pos) -> Option<(u64, usize)>`, `#[inline]`) used by
`Cursor::read_varint`, `PackedIter::next` and the cumulative decoder. "Mirrors"
then becomes true by construction, and the duplicated `#[cold]` slow path goes
away. Then a differential test: a deterministic in-file PRNG (xorshift, no
dependency) generating packed bodies, valid and corrupted, asserting that
`decode_packed_sint64_cumulative(body, base)` equals the prefix-summed output of
`PackedSint64Iter`, for a few thousand cases. Enforceable by test, and the shared
core makes the property structural.

### 2.5 "Errors are swallowed as None, ending iteration": false on a second `next()`

`PackedIter::next` returns `self.cursor.read_varint().ok()`. On the overflow
error the cursor has already advanced past the 10 bad bytes, so a second
`next()` resumes decoding from the following byte. The iterator is not fused,
and does not implement `FusedIterator`. In
`cumulative_stops_matches_packed_iter_on_overflow` the trailing `0x02` "should
NOT be reached". It is reached by any consumer that calls `next()` after `None`
(for example `by_ref()` chains or manual loops). The two error kinds also leave
different observable state:

- after a truncated tail, `is_empty()` is true, so the error is undetectable;
- after an overflow, `is_empty()` is false.

`size_hint`'s lower bound (`remaining / 10`) is also violated on malformed
input. For example, 20 continuation bytes give a lower bound of 2 and yield
nothing. Not UB, but a broken `Iterator` contract.

Fix: on error, set the cursor to the end (`pos = data.len()`), implement
`FusedIterator` for all seven iterator types, and add a test that calls `next()`
after `None`. If error detection is wanted, expose it explicitly
(`fn errored(&self) -> bool` or a `try_` iterator) rather than leaving it to
`is_empty()` side effects. Enforceable by test, plus the `FusedIterator` impl as
a type-level promise.

### 2.6 `read_varint_unchecked` is documented "Infallible": it panics in debug

Safety doc: violating condition 2 (over-long or overflowing) "produces an
unspecified value (not UB, but meaningless)". With an 11+ byte sequence,
`read_varint_unchecked_slow` computes `<< shift` with `shift >= 64`. In debug
builds (the only profile the tests run) that panics with "attempt to shift
left with overflow". In release it is a masked shift. The one-word summary
"Infallible" is therefore false in debug. No test covers it, which is fair since
it is outside the contract. The doc should still say "may panic in debug
builds". Not mechanically enforceable beyond a `#[should_panic]` test gated on
`debug_assertions`, which would document the behaviour rather than guard it.

### 2.7 `read_len_delimited` panics on a huge length instead of returning `Err`

`let len = self.read_varint()? as usize; if self.pos + len > self.data.len()`:

- for a length near `u64::MAX`, debug panics on the add overflow;
- release wraps, and then the slice `data[pos..pos+len]` panics because end <
  start;
- on 32-bit targets the `as usize` (with `cast_possible_truncation` allowed)
  silently truncates, so a 2^32 + 3 length reads as 3: a wrong answer, not an
  error.

`skip_field(WIRE_LEN)` and `read_raw_field(WIRE_LEN)` inherit this. AGENTS.md:
"Use `WireResult<T>` / `WireError` for fallible operations, not panics". README:
"varint/tag decoding validates overflow and rejects malformed sequences". No
test feeds a length prefix larger than the remaining input by more than a few
bytes (`read_raw_field_truncated_len_payload` uses 5 vs 2).

Fix: `let len = usize::try_from(v).map_err(..)?; if len > self.remaining() {
Err }`, plus a test with `encode_varint(u64::MAX)` as the length prefix.
Enforceable: the test, plus denying `clippy::arithmetic_side_effects` (restriction
lint) in `src/`, which flags every unchecked `pos + n` in the decoder. There are
a handful (`read_fixed32`, `read_fixed64`, `skip_field`), all of which can be
written as `n > self.remaining()`. The `cast_possible_truncation` allow on
`read_len_delimited` is the local exemption that hid the 32-bit case.

### 2.8 Twelve skip/always pairs and six packed wrappers kept in sync by hand

The 24 field encoders are 12 pairs where the skip variant duplicates the
always body instead of being `if v != default { X_always(..) }`. The six typed
packed iterators are six copies of the same 50 lines. Each copy is a place the
pair can diverge (1.6 is that divergence going untested). Each new wrapper
needs hand-written tests that nothing forces: `packed_typed_iter_empty`,
`_remaining_bytes` and `_size_hint` list the six types by hand, so a seventh
type gets no coverage and no warning.

Fix, structural: generate the pairs with one `macro_rules!` (or define skip
variants as calls to always variants), and generate the typed iterators as
`PackedTyped<'a, D: WireDecode>` or with a macro that also emits the
`FusedIterator` impl. The tests then become one generic or macro-driven test
per behaviour, and new types inherit them. Enforceable by structure: the bad
spelling (a hand-copied body) stops being the easy one. README's
"What's in the box" list (iterator and encoder names) restates what the code
defines. It is the same finding in prose. Either cut it to categories, or hold
it with a test that greps README for each `pub` item name in `src/lib.rs`.

### 2.9 Durable source cites `notes/` in another repository

`read_varint` and `encode_varint` doc comments: "See `notes/SIMD.md` in pbfhogg
(dd7f69a) for the full research doc (P3-20, closed)." AGENTS.md: "nothing
durable may cite `notes/` - not a code comment". The citation is also
cross-repository and SHA-pinned. The benchmark numbers it backs (2.3x, 3.5x,
1.5x, "varint-simd v0.4.1 SSSE3") were produced on an unrecorded host and,
given 5.1, almost certainly under `-Ctarget-cpu=native`. `encode_varint_to_slice`
and CHANGELOG 0.4.0 also claim "~95% of zigzag-encoded OSM way-ref deltas",
which nothing in this repo measures. Fix: move the measured numbers, with host,
flags and date, to `reference/performance.md` (the folder AGENTS.md prescribes,
which does not exist yet), and make the doc comments carry the conclusion
without the citation. Enforceable by a text rule: reject `notes/` in `src/**`.

### 2.10 "Branchless fast path": the fast path is two `if`s

`encode_varint_to_slice` doc, README and CHANGELOG 0.4.0 all say "branchless
1-byte and 2-byte fast paths". The code is
`if value < 0x80 { ... return 1 } if value < 0x4000 { ... return 2 }`. Those
are branches. Whether the compiler makes them branchless is not guaranteed
and nothing checks it. Reword ("early-return fast paths"). Not enforceable
short of an asm snapshot test, which would not be worth it.

### 2.11 Toolchain, MSRV and dependency claims

- AGENTS.md: "Rust 2024 edition, nightly toolchain". There is no
  `rust-toolchain.toml`. `Cargo.toml` declares `rust-version = "1.85"` (stable).
  The real nightly requirement comes from the host's global
  `~/.cargo/config.toml` (`-Zthreads=16`), not from the crate (5.1). So the claim
  describes one developer's machine.
- `rust-version = "1.85"` is never checked. Two likely problems, unverified
  because no MSRV run exists:
  - `count_packed_varints_sse2` calls `_mm_movemask_epi8` outside an `unsafe`
    block. That is only accepted (without an `unsafe_op_in_unsafe_fn` warning)
    on toolchains where the intrinsic is a safe `#[target_feature]` fn, which
    I believe arrived after 1.85;
  - criterion 0.8's MSRV may exceed 1.85, which would break `cargo test` (not
    the library) at the declared MSRV.

  Fix: an MSRV lane (`cargo +1.85 check --lib`) or bump `rust-version` to what
  is actually tested. Enforceable by a check lane.
- AGENTS.md, README, the crate doc and CHANGELOG all say "No external
  dependencies". True for consumers. `Cargo.lock` has 78 packages, all
  dev-dependencies (3.1). "std only" is accurate for the library only.
- AGENTS.md: "brokkr check # gremlins + clippy + all tests". Brokkr runs
  `cargo test --tests`, which excludes doctests (`"doc_carrier": false` in the
  plan). The library has no doctests today, so the gap is latent. The README
  usage example is compiled by nothing (README is not included as crate docs).
  If `read_tag`'s signature changes, README goes stale silently. Fix:
  `#![doc = include_str!("../README.md")]` and make sure the check runs
  doctests. Enforceable by the check.
- AGENTS.md: "Test module uses `#[allow(clippy::unwrap_used)]`". It is a
  crate-level inner attribute on the integration test file (which also allows
  `missing_docs`). Wording only.

### 2.12 `.gitignore` entries that no longer mean anything

- `Cargo.lock` is listed in `.gitignore` and is tracked. The rule is a no-op for
  the tracked file, but would hide it again after any `git rm --cached`. It
  contradicts the owner's "always commit lockfiles" rule. Remove the line.
- `data` matches nothing in this repo (it is inherited from pbfhogg).
- `.plans/` is ignored and holds `dynamic-beaming-giraffe.md`. AGENTS.md says
  `plans/` is retired and transient plans go in `notes/`. The ignore rule keeps
  an invisible document alive.
- `.brokkr/` is *not* ignored and shows as untracked in every `git status` (5.4).

### 2.13 Stale counts in the auto-memory file (lateral, outside the repo)

`~/.claude/projects/-home-folk-Programs-protohoggr/memory/MEMORY.md` says "78
integration tests" and "~810 lines". Today it is 156 tests and about 1300
lines. The owner's rules say not to use that memory store and not to hard-code
drifting counts. The file is loaded into every session and is now misleading.
It should be deleted, or its counts reworded away.

### 2.14 `.claude/settings.local.json` allows exactly what AGENTS forbids (lateral)

It allowlists `Bash(cargo:*)`, `Bash(cargo test:*)` and `Bash(cargo clippy:*)`,
while AGENTS.md says "Never run raw `cargo` ... Use `brokkr`." The rule is held
by nothing, and the permission layer actively permits the violation. Not a
test finding, but it is the one place this rule could be enforced mechanically.

---

## 3. The test suite as a system

### 3.1 Every test build compiles criterion, varint-simd and a C toolchain dependency

`[dev-dependencies]` is `criterion = { version = "0.8.2", features =
["html_reports"] }` and `varint-simd = "0.4"`. Cargo builds all dev-dependencies
for every test target, so `brokkr check`'s
`cargo test --no-run --all-features --tests` compiles 57 build directories for
a zero-dependency crate: syn, serde_derive, serde_json, regex (all three
crates), rayon, crossbeam, clap, plotters, ciborium, half, zerocopy and others.
`alloca` (pulled in by criterion 0.8) depends on `cc` and compiles C in its
build script. So:

- a cold `brokkr check` (fresh clone, `cargo clean`, toolchain bump, lockfile
  update) pays a full criterion build before the first test runs. Estimate: tens
  of seconds on this 16-core host, minutes on a small CI runner. The warm path
  (30 ms) hides it;
- the test suite of a pure-std library cannot be built on a host without a C
  compiler (a refusal, see 5.3);
- `clippy --all-targets` also checks the bench target, so criterion is
  type-checked as well.

The varint-simd comparison is a closed research item ("P3-20, closed" in the
doc comments). It exists to back numbers that live in doc comments.

Fix, in order of payoff:

1. Delete the varint-simd benches and dev-dependency. The research is closed,
   and the conclusion can live in `reference/performance.md`.
2. Move the remaining benches to a separate `publish = false` workspace member
   (`bench/`) that depends on protohoggr. The library crate then has zero
   dev-dependencies, `cargo test -p protohoggr` builds three artifacts, and
   brokkr can check the bench crate in a separate, optional lane.
3. Alternatively, given that the host is on nightly anyway, use
   `#![feature(test)]` benches, which need nothing.

Enforceable: a dependency rule (brokkr has a `dependency_rules` phase) that
rejects dev-dependencies on the library package once the benches move.

### 3.2 An empty unit-test binary is built and run on every check

The plan lists two artifacts: the `lib` unittest binary (0 tests, because
`src/lib.rs` has no `#[cfg(test)]`) and `wire`. Building and linking the empty
lib test binary is a small recurring cost. The better fix is not
`[lib] test = false` but to *use* it. The private items that matter most and are
unreachable from `tests/` belong there:

- `sint32_wire_bits`;
- `read_varint_slow`'s branches;
- the non-x86 `count_packed_varints_scalar`, which is not even compiled on x86
  (5.2).

### 3.3 Test isolation and timing: clean

No environment writes, globals, loggers, runtimes, sleeps, timeouts, child
processes or file I/O. `brokkr` runs the suite with `--test-threads=1`
(156 tests in about 0.3 s). Serial execution is unnecessary here but costs
nothing measurable, and nothing in the suite would break if it ran in parallel or
were merged into one binary. Single integration binary: good, keeps link cost at
one. No test invokes the build tool or needs another binary.

### 3.4 Check machinery redundancy (small, recurring)

The log shows `cargo test --no-run --message-format=json --all-features --tests`
twice per check (prepare and test phases), plus `cargo metadata`. Each costs
about 30 ms when warm. That is brokkr's concern, but it is paid on every run.
`--all-features` is a no-op sweep here (the crate has no features).

### 3.5 Unsafe code with no Miri lane

`read_varint_unchecked`, `encode_varint_to_slice` and
`count_packed_varints_sse2` use `get_unchecked` and raw pointers. The tests are
well shaped for Miri: they slice exactly to `n` bytes, so an over-read would be
out of bounds rather than inside slack. But no Miri run exists. Debug `ub_checks`
on `get_unchecked` catch some over-reads under the normal test profile. The raw
`ptr.add` reads in the SSE2 path are not covered. Fix: a periodic
`cargo +nightly miri test` lane restricted to `unchecked_`, `encode_to_slice_`
and `count_varints_` (Miri supports SSE2 intrinsics). Also: the tests' `unsafe`
blocks carry no `// SAFETY:` comments, while `src/` does so consistently by
convention. Denying `clippy::undocumented_unsafe_blocks` (and optionally
`multiple_unsafe_ops_per_block`) in `[lints.clippy]` makes it a rule. `src/`
already complies.

### 3.6 No property or exhaustive tests where they would be cheap

Everything is hand-picked points. Cheap, dependency-free additions that would
hold most of sections 1 and 2:

- all 2^16 two-byte inputs through `read_varint`, `read_varint_unchecked` (where
  valid), `skip_varint` and `read_raw_field(WIRE_VARINT)`, cross-checked for
  agreement on length and value;
- a strided `u32` sweep for the zigzag-32 bijection;
- a seeded xorshift differential for cumulative vs iterator (2.4), and for SSE2
  vs scalar counting (5.2).

All run in milliseconds in debug.

---

## 4. What the tests reach that they should have been handed

### 4.1 Ambient dependencies in tests: none

No clock, randomness, identifiers, environment, working directory or file
system. The suite is fully hermetic at runtime. (Its *build* is not; see 5.1.)

### 4.2 Production values with no injection point: the SIMD/scalar choice

`count_packed_varints` selects its implementation with `cfg(target_arch)`. Tests
cannot reach the other implementation on any host, and on x86-64 the scalar
version does not exist in the compiled crate at all. This is the one production
choice the tests are forced to accept from their surroundings (5.2 gives the
consequences). Fix: compile both implementations on every target (scalar
unconditionally; SSE2 under `cfg(target_arch = "x86_64")`), keep the dispatcher
as is, and test the two against each other in unit tests or via a
`#[doc(hidden)] pub mod __test` surface.

### 4.3 Build profile as an implicit input

The behaviour of `read_len_delimited` on huge lengths (2.7) and of
`read_varint_unchecked` on over-long input (2.6) depends on overflow checks, and
`get_unchecked` checking depends on `debug_assertions`. The check runs only the
dev profile. Consumers (pbfhogg, elivagar) run release. The fix in 2.7 removes
the dependence for the safe API. For the rest, a release-profile test sweep
(`--release`, or `[profile.test-release] inherits = "release",
overflow-checks = false`) catches profile-dependent behaviour. Enforceable as a
second check sweep.

### 4.4 Test-only shortcuts reachable from production: none

None found. `WireError::msg` is a public field, so anyone can construct
arbitrary errors. That is not a test shortcut, but it is one more reason for the
enum in 1.2.

---

## 5. Where the tests assume they run, and what they touch

### 5.1 The check tests a host-tuned artifact, built under a user-global config

`~/.cargo/config.toml` on this host sets, for `x86_64-unknown-linux-gnu`:

- `-Ctarget-cpu=native` (a Zen 5 part with AVX-512);
- `-Zthreads=16` (nightly-only);
- `-Clink-arg=-fuse-ld=wild` (needs gcc >= 16.1);
- `rustc-wrapper = brokkr-rustc-guard`;
- `profile.dev.debug = "line-tables-only"`.

None of this is declared in the repository, and all of it shapes what
`brokkr check` builds and runs:

- **Wrong artifact.** Tests validate code compiled for this CPU. crates.io
  consumers and other developers get baseline x86-64 (SSE2 only). Scalar loops
  such as the SSE2 tail, the cumulative decoder and `encode_varint` may be
  auto-vectorized or scheduled differently. A codegen-dependent bug would pass
  here and fail elsewhere, or the reverse.
- **varint-simd only works here.** Its SSSE3 paths are enabled because native
  implies SSSE3. On a baseline build, varint-simd's behaviour (and possibly
  whether the bench and test build compiles at all, if its functions are gated
  on `target_feature = "ssse3"`; unverified) differs. The doc-comment benchmark
  numbers carry the same hidden condition.
- **Nightly by accident.** `-Zthreads` is why "nightly toolchain" appears in
  AGENTS.md (2.11). On a stable toolchain with this config, every build fails.
  On another host, stable works and the claim is wrong.
- **On a different host:** a host without wild or gcc 16 fails at link time
  (refusal). A host with a different CPU silently tests a different artifact
  (silent degradation). Nobody notices either case, because no check records
  the effective flags.

Fix: make the check's target explicit. A project `.cargo/config.toml` with
`[target.x86_64-unknown-linux-gnu] rustflags = ["-Ctarget-cpu=x86-64"]` wins,
because cargo joins config arrays with higher-precedence entries later and the
last `-Ctarget-cpu` wins. Note that this changes it for every build in this
repo, which is the point for a library. Better still, brokkr adds a baseline
sweep that sets `CARGO_ENCODED_RUSTFLAGS` to a known value and records the
flags in the plan. Enforceable by the check (the sweep) and by config (the
project file).

### 5.2 Architecture: half of `count_packed_varints` is untested on every host

- On x86-64 (the dev host), `count_packed_varints_scalar` is `cfg`'d out: never
  compiled, never linted by clippy, never tested.
- On aarch64 or 32-bit x86, the SSE2 path is absent, and
  `count_varints_17_bytes` and `count_varints_32_bytes` test the scalar loop
  while their comments describe SIMD chunking.
- Clippy runs only for the host target, so the scalar fallback has never seen
  the denied lints.

Fix: 4.2 (compile both, test both everywhere). Optionally add a cross-target
clippy sweep (`--target aarch64-unknown-linux-gnu`, `--target
i686-unknown-linux-gnu`). That needs the rustup targets installed, which is
host configuration the check should detect and report rather than silently skip.

### 5.3 Host tools the test build needs

- A C compiler (`alloca` -> `cc`, via criterion). This is a refusal on hosts
  without one. It disappears with 3.1.
- Possibly x86 only, via varint-simd (unverified). Also disappears with 3.1.
- Pointer width: on 32-bit targets `read_len_delimited` silently truncates
  lengths (2.7), a wrong answer, and no test would notice because every test
  length is small.

### 5.4 `brokkr` writes its state into the repository root, unignored

Each `brokkr check` adds a log under `.brokkr/check-logs/` and a directory under
`.brokkr/accounting/<run-id>/` (`plan.json`, `journal.jsonl`). In this session
there were 10 logs and 7 accounting directories in about nine minutes, with no
retention visible. `.brokkr/` is neither tracked nor ignored, so:

- it appears in every `git status`;
- a `git add -A` would commit run journals;
- it survives `cargo clean`.

That is not wrong for a tool-owned directory, but no repository rule says who
owns it. It belongs to brokkr. The conventional fixes are for brokkr to write
a self-ignoring `.brokkr/.gitignore` containing `*` when it creates the
directory (as pytest, ruff and venv do), or to keep per-run state under
`$XDG_STATE_HOME/brokkr/<project>/` and only config in the repo, plus a
retention cap. Short of that, add `.brokkr/` to this repo's `.gitignore`.

Other writes: the tests write nothing, and `target/tmp` (cargo's
`CARGO_TARGET_TMPDIR`) stays empty. criterion, when the benches run, writes
baselines to `target/criterion`. That is a foreign tool writing into cargo's
directory, so `cargo clean` destroys the only record of the measurements that
the doc comments cite (2.9). The durable record belongs in
`reference/performance.md`.

---

## Enforceability summary

| finding | can be held by |
|---|---|
| 1.1 golden bytes | test convention; structural if pairs are generated (2.8) |
| 1.2 error kinds | type (`WireError` enum) plus tests asserting kinds |
| 1.3, 1.4, 1.7 vacuous or misnamed tests | one-off rewrite only; not mechanically holdable |
| 1.5 scratch and append | test; structural if scratch becomes an owned encoder |
| 1.6 skip-variant coverage | structural (skip defined via always) plus a macro-generated test per type |
| 2.1 gremlins allowlist | check (allowlist or ASCII-only test) |
| 2.2 README doc claim | partially, by README-as-crate-docs with intra-doc links |
| 2.3 dead branch | error enum plus per-kind test; coverage lane |
| 2.4 cumulative mirrors iterator | structural (shared varint core) plus differential test |
| 2.5 fused iteration | type (`FusedIterator`) plus test |
| 2.6 "Infallible" | not enforceable; reword |
| 2.7 huge length panic | test plus `clippy::arithmetic_side_effects` in `src/` |
| 2.8 hand-synced copies | structural (macro or generic) |
| 2.9 `notes/` citation | text rule on `src/**` |
| 2.10 "branchless" | not enforceable; reword |
| 2.11 toolchain and MSRV | MSRV check lane; doctest-running check; `rust-toolchain.toml` if nightly is truly required |
| 2.12 `.gitignore` | one-off |
| 3.1 dev-deps | dependency rule once benches move |
| 3.5 unsafe | `undocumented_unsafe_blocks` lint; Miri lane |
| 4.2 and 5.2 SIMD/scalar | structural (compile both) plus differential test; cross-target clippy sweep |
| 4.3 profile | release-profile sweep |
| 5.1 host flags | project `.cargo/config.toml` and/or a baseline sweep in brokkr that records flags |
| 5.4 `.brokkr/` | brokkr self-ignore, or `.gitignore` |

### Lateral notes (small, outside the test scope)

- Several `#[allow(...)]` attributes in `src/lib.rs` suppress nothing:
  - `cast_possible_truncation` on `read_varint_unchecked` and its slow path (no
    casts there);
  - `cast_possible_truncation` and `cast_possible_wrap` on
    `decode_packed_sint64_cumulative` (no `as` casts);
  - likely `cast_possible_truncation` on the int32 encoders (`i32 as i64 as u64`
    does not truncate).

  Denying `clippy::allow_attributes` and switching to `#[expect(...)]` makes
  stale exemptions fail the build, so each one becomes a self-checking claim.
- `count_packed_varints_sse2` has a redundant inner
  `#[cfg(target_arch = "x86_64")]` on its `use`. Its `#[target_feature(enable =
  "sse2")]` plus `unsafe fn` is unnecessary for a baseline feature: it could be
  a safe fn, which removes the `unsafe` call site in `count_packed_varints`.
- The packed iterator types derive `Clone` but not `Debug` (`Cursor` derives
  both). `missing_debug_implementations` would hold this.
- `benches/varint.rs` says "Run with: cargo bench --bench varint" (raw cargo,
  against AGENTS.md), and hand-strips the tag and length with byte loops instead
  of using `Cursor`.
