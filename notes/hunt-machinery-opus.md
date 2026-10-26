# Verification hunt: machinery

Scope: `Cargo.toml`, what `brokkr check` runs and writes (including `.brokkr/`),
`.gitignore`, the `unsafe` contracts and comment-level invariants in
`src/lib.rs`, and the claims in `README.md`, `CHANGELOG.md`, `AGENTS.md` and
`LLM.md`. Where a finding depends on the test file or on host configuration,
it is followed there.

Everything below was established by reading the files. The only commands run
were `git ls-files`, `git status --ignored`, `git check-ignore`, and
`rustup show active-toolchain`, plus reading the `.brokkr/` logs, the plan
and journal files, `~/.cargo/config.toml`, the varint-simd 0.4.1 source in the
cargo registry, and the brokkr source and docs that describe the phases.

## What `brokkr check` does today (baseline)

From `.brokkr/check-logs/check-001792993691821.log` and
`.brokkr/accounting/*/plan.json`:

- Convention phases: `gremlins`, `header`, `textlint`, `manifest`,
  `script_check`, `dependency_rules`, `publish_cycle`. `brokkr.toml` holds only
  `project = "protohoggr"`, so only gremlins (11 files: the tracked and
  untracked-not-ignored `.rs`, `.md` and `.toml` files) and publish cycle do
  any work. Header, textlint, manifest, script_check and dependency_rules are
  inert without config, and the log still prints `phase X: started` for each.
- `cargo clippy --keep-going --all-targets --message-format=json --all-features -- --cap-lints=warn`.
  brokkr fails the phase on any diagnostic, warnings included (per
  `brokkr/reference/check-internals.md`), so `--cap-lints=warn` does not
  weaken the `deny` entries in `Cargo.toml` under brokkr. They still matter
  for a plain `cargo build` by a consumer or an IDE.
- `rustdoc`: prints `started`, then nothing. It is disabled because there is
  no `[rustdoc]` table, so rustdoc lints (broken intra-doc links and the
  like) are never checked.
- `prepare`: `cargo test --no-run --all-features --tests`, plus a listing, to
  write `plan.json` (156 expected executions).
- `test`: `cargo test --no-run ... --tests` again, then
  `cargo test --all-features --no-fail-fast --tests -- --test-threads=1`.
  It runs the lib harness (0 tests) and `tests/wire.rs` (156 tests), serially.
  `--tests` means no doctests run, and the plan says `doc_carrier: false`.
- `member_check` and `fixture_lint`: reported "not applicable".
- Warm total about 0.93 s: clippy 150 ms, prepare 364 ms, test 306 ms.

There is no CI (`.github/` is absent) and no git hook (only `*.sample` in
`.git/hooks`). The only enforcement is someone choosing to run
`brokkr check` on this one host.

---

## 1. Tests that prove nothing

### 1.1 `decode_varint_11byte_rejected` names a code path that cannot run

In `read_varint_slow`, `shift` takes the values 7, 14, ..., 63, and at
`shift == 63` the function returns on both branches. So the
`if shift > 63 { return Err("varint too long") }` branch is dead: `shift`
never exceeds 63 after `shift += 7`. The test comment says "11 continuation
bytes - too long regardless of final byte". In fact the input is rejected by
the 10th-byte overflow check (`0x80 > 1`), which `decode_varint_10byte_overflow`
already covers. The "too long" path the test name describes does not exist.
`decode_packed_sint64_cumulative` has the same dead `shift > 63` branch
("Overlong varint - stop silently").

- Fix: delete both dead branches, and rename or drop the test.
- Enforceable: a coverage gate would have shown both branches never execute.
  Making the error a typed kind (see 1.2) would also make the test assert
  *which* rejection happened.

### 1.2 `is_err()` everywhere: tests cannot tell one failure from another

`WireError` is `{ msg: &'static str }`, and nearly every negative test only
asserts `is_err()`. Cases where this hides a wrong answer:

- `skip_field_unknown_wire_type` and `read_raw_field_unknown_wire_type` run on
  an *empty* cursor. If wire type 3 were wrongly treated as `WIRE_64BIT`, the
  call would fail with "unexpected end of input" and the test would still pass.
  The tests cannot distinguish "unknown wire type" from truncation.
- `decode_varint_11byte_rejected` (1.1) passes on the overflow error rather
  than the error it names.
- `read_raw_field_truncated_*` and `read_fixed*_truncated` would pass for any
  error at all.

- Fix: make `WireError` carry an enum kind (it can keep `&'static str`
  messages for `Display`), and have the tests assert the kind. Give the
  unknown-wire-type tests enough bytes that truncation cannot be the reason.
- Enforceable: by type. Once a kind exists, `assert!(matches!(e.kind, ...))`
  is the natural spelling. A textlint rule banning bare `.is_err())` in
  `tests/` would hold it.

### 1.3 `int64_field_positive` can pass with no assertion executed

It hand-decodes the varint in a loop and asserts only when it finds a byte
`< 0x80`. If the encoder wrote no terminal byte, or nothing after the tag, the
loop ends and the test passes without asserting anything. It also duplicates
`read_varint`.

- Fix: decode with `Cursor` and assert the cursor is empty afterwards, as the
  other roundtrip tests do.
- Enforceable: no general lint. A review rule against asserts that sit only
  inside loop conditionals.

### 1.4 `wire_error_is_error` is a compile-time fact presented as a runtime test

The body `let _: &dyn std::error::Error = &err;` cannot fail at runtime. The
comment claims "source() returns None for simple errors", and nothing asserts
that.

- Fix: either assert `err.source().is_none()`, or turn it into a
  `const _: fn() = || { fn assert_error<E: std::error::Error>() {} assert_error::<WireError>(); };`
  static assertion in `lib.rs`, where it reads as what it is.

### 1.5 The scalar `count_packed_varints` is never compiled, linted or tested on the dev host

`count_packed_varints_scalar` is `#[cfg(not(target_arch = "x86_64"))]`. On the
only host that runs the check (x86_64), clippy never sees it and no test runs
it. Several tests claim to exercise configurations ("Exercises SIMD 16-byte
chunk + 1-byte scalar tail on x86-64", "Two full SIMD iterations"), and
nothing cross-checks the SSE2 result against a reference. Integration tests
in `tests/wire.rs` can only reach the public API, so they cannot select an
implementation.

- Fix: compile the scalar version unconditionally, as a private function and
  the fallback, and add a differential test in a `#[cfg(test)]` unit module.
  For every length 0..=64 and a set of byte patterns, assert
  `sse2 == scalar`. The rule then holds on every architecture.
- Enforceable: by structure. If both implementations always compile, clippy
  covers both, and the differential test holds them equal. A cross-target
  `cargo clippy --target aarch64-unknown-linux-gnu` lane would also catch the
  cfg'd-out branch (see 5.3).

### 1.6 `decode_packed_sint64_cumulative` "mirrors PackedSint64Iter" is tested on one case only

The doc and CHANGELOG 0.4.0 promise identical stop semantics to
`PackedSint64Iter`. Only the overflow-at-10th-byte case is cross-checked
(`cumulative_stops_matches_packed_iter_on_overflow`). The truncated-tail case
the doc names ("decode errors (truncated tail) are silently swallowed") has no
cumulative test at all. Nor does a mid-stream truncation followed by valid
bytes.

- Fix: one differential test replaces the example tests and the claim: for
  all byte strings up to length about 4 (exhaustive) plus seeded random
  longer ones, assert
  `cumulative(data, base) == PackedSint64Iter::new(data).scan(base, wrapping_add)`.
  The same approach works for `read_varint_unchecked` vs `read_varint` on
  well-formed inputs, and for `encode_varint_to_slice` vs `encode_varint`.
- Enforceable: by the test itself. It makes the "mirrors" claim a checked
  invariant rather than prose.

### 1.7 Float read tests are weaker than they look, and the lint pushes them there

`read_float` and `read_double` assert `(decoded - val).abs() < EPSILON`.
`float_cmp = "deny"` pushes tests toward approximate comparison, but this is
a bit-exact decode where `to_bits()` equality is the right assertion (the
roundtrip tests already do it). Meanwhile `float_infinity_roundtrip` and the
`-0.0` tests use `assert_eq!` on floats, which `float_cmp` does not see
inside the macro. So the lint is enforced inconsistently, and where it is
obeyed it makes the assertion weaker.

- Fix: compare `to_bits()` everywhere in tests.
- Enforceable: a textlint rule against `EPSILON` in `tests/`.

### 1.8 Tests only run under the dev profile, and the hot paths ship in release

The check runs tests only with `debug-assertions` and `overflow-checks` on
(the dev profile; `~/.cargo/config.toml` keeps those defaults). The
consumers (pbfhogg, elivagar) run this code in release, where:

- `read_varint_unchecked_slow` with a too-long varint hits `u64 << 70`, which
  panics in debug but silently masks the shift in release (see 2.4).
- `slice::get_unchecked` precondition checks (`ub_checks`) are active in
  debug only.
- `self.pos + len` in `read_len_delimited` panics in debug but wraps in
  release (see the lateral bug L1).

The test that claims to cover "unchecked" behaviour runs under a
configuration the production code never runs under.

- Fix: add a release-profile test lane, or a lane with
  `-C overflow-checks=off -C debug-assertions=off`, and a Miri lane for the
  unsafe paths (2.3).
- Enforceable: yes, as a brokkr sweep. The lane configuration is the
  brokkr-config hunter's scope; the need is stated here.

### 1.9 The bench's correctness claim is not checked

CHANGELOG 0.3.0: "SIMD benchmark tail-byte bias: batch loops now hand off
remaining bytes to a scalar tail, so all strategies decode the same values."
Nothing asserts that. `benches/varint.rs` throws every decoded value into
`black_box`, and the batch4 path ignores varint-simd's `_overflow` flag. The
performance claims in `lib.rs` and the CHANGELOG (2.6) rest on this bench
decoding the same data as the scalar path.

- Fix: in each bench's setup, decode once with every strategy and
  `assert_eq!` the resulting vectors before timing. Run benches in test mode
  (`cargo bench -- --test`, which criterion supports, runs each bench once) as
  a check lane, or move the equality assertion into a normal test.
- Enforceable: yes, as a test.

---

## 2. Guards and claims that have stopped holding

### 2.1 `.gitignore` ignores `Cargo.lock`, which is tracked

`git check-ignore --no-index Cargo.lock` matches `.gitignore:2`, yet
`Cargo.lock` is in `git ls-files`. The project rules (CLAUDE.md "Has
Cargo.lock changed? Commit it") say it should be tracked. Today git keeps
tracking it only because it was added before the rule. If it is ever
`git rm --cached` or deleted and regenerated, `git add -A` will silently
never re-add it.

- Fix: delete the `Cargo.lock` line.
- Enforceable: yes. A script check asserting `git check-ignore --no-index`
  finds nothing for any tracked file catches every tracked-but-ignored path,
  not just this one.

### 2.2 `.gitignore` is a pbfhogg leftover in other ways

- `data`: there is no `data/` here. It is a pbfhogg dataset entry, and a
  future `data/` (fixtures, say) would be silently ignored.
- `.plans/`: AGENTS.md says `plans/` is retired and transient docs go in
  `notes/`. `.plans/dynamic-beaming-giraffe.md` still exists, ignored and so
  invisible to review and to gremlins (it has em-dashes). It also contradicts
  `lib.rs`: it says violating `read_varint_unchecked` condition 2 "is UB".
- `.brokkr/` is *not* ignored, though brokkr writes into it on every run (see
  5.4).

- Fix: drop `data` and `.plans/` (move or delete the plan), add `.brokkr/`.
- Enforceable: a script check that every `.gitignore` pattern matches at
  least one path or is on an allowlist. That catches dead entries. The tracked
  check in 2.1 catches the inverted case.

### 2.3 `unsafe` contracts: stated, partly true, never checked by any tool

Three `unsafe` surfaces:

- `Cursor::read_varint_unchecked`: contract condition 1 (a terminal byte
  exists before the end) is the memory-safety condition. Nothing tests a
  violation (correctly, per the contract), and nothing runs Miri, so the
  `SAFETY:` comments in `read_varint_unchecked_slow` ("slow path won't read
  OOB") are unverified.
- `encode_varint_to_slice`: contract `buf.len() >= 10`. The comment
  `// SAFETY: i < 10 at this point.` is true (u64::MAX writes indices 0..=9)
  but proven by nobody. **This contract can be removed by type**: take
  `buf: &mut [u8; 10]`. Then the function is safe, the bounds are statically
  known, and callers with a slice do one `try_into()` per call site (or one
  per chunk). The type makes the bad call impossible to write.
- `count_packed_varints_sse2`: `unsafe` only because of
  `#[target_feature(enable = "sse2")]`, with a SAFETY comment
  ("SSE2 is baseline on x86-64"). On x86_64 SSE2 is statically enabled, so
  the attribute adds nothing. On Rust 1.87+ `_mm_movemask_epi8` is safe in
  that context, leaving one raw-pointer load whose safety follows locally
  from `chunks_exact(16)`. The function's `unsafe` and its contract go away;
  the current MSRV (2.5) is what keeps them.

Conventions that nothing enforces:

- Every `unsafe` block in `src/lib.rs` has a `// SAFETY:` comment. Nothing
  requires it, and `tests/wire.rs` has many `unsafe` blocks without one.
  Fix: `undocumented_unsafe_blocks = "deny"` (and optionally
  `multiple_unsafe_ops_per_block`) in `[lints.clippy]`.
- Private `unsafe fn read_varint_unchecked_slow` has no `# Safety` section.
  `missing_safety_doc` only covers public items. The same lint set plus
  `clippy::missing_safety_doc` on private items is not available, but
  `unsafe_op_in_unsafe_fn` is already warn-by-default in edition 2024, and the
  slow path could take its contract in a doc comment by convention.
- Miri: a Miri lane over `tests/wire.rs` (the nightly toolchain is already
  the default) would check every unsafe test call against the stated
  contract. Enforceable as a brokkr script check or sweep.

### 2.4 `read_varint_unchecked` doc: "Violating condition 2 produces an unspecified value (not UB, but meaningless)" is false in debug builds

A varint longer than 10 bytes with a later terminal makes
`read_varint_unchecked_slow` compute `u64::from(b & 0x7F) << 70`. In the dev
profile (overflow checks on) that is a panic, "attempt to shift left with
overflow". In release the shift amount is masked and the value is garbage.
"Not UB" is correct; "produces a value" is not true in debug.

- Fix: reword ("may panic in debug builds or return an unspecified value"),
  or cap the loop at 10 bytes, which costs nothing on the hot 1-byte path
  because it lives in the cold slow path.
- Enforceable: a test is allowed here (condition 2 is not a memory-safety
  condition), e.g. `#[should_panic]` under debug, but that pins the debug
  behaviour. Capping the loop is the version that holds structurally.

### 2.5 `rust-version = "1.85"` is unverified, probably warns at its own MSRV, and cannot be tested on this host

- Nothing builds with 1.85. AGENTS.md says "nightly toolchain", but there is
  no `rust-toolchain.toml`. Nightly comes from the user-wide rustup default
  (`nightly-x86_64-unknown-linux-gnu (default)`).
- `count_packed_varints_sse2` calls `_mm_movemask_epi8` outside an `unsafe`
  block. Before 1.87 that intrinsic is an `unsafe fn`, so on 1.85 and 1.86 this
  triggers `unsafe_op_in_unsafe_fn` (warn in edition 2024), and brokkr fails
  on warnings. Clippy's `incompatible_msrv` does not catch it, because it
  checks stabilized std APIs rather than lint behaviour.
- `~/.cargo/config.toml` sets `-Zthreads=16` for
  `x86_64-unknown-linux-gnu`, so any stable toolchain refuses to build on
  this host at all. Checking the MSRV here needs the host rustflags
  stripped.
- Several `[lints.clippy]` names (for example `regex_creation_in_loops`) are
  newer than 1.85's clippy and would be `unknown_lints` warnings there.

- Fix: decide what the MSRV is *for*. If downstream is nightly-only, raising
  it to 1.87+ removes the `unsafe` in 2.3. Pin the dev toolchain with a
  `rust-toolchain.toml` rather than inheriting the rustup default. Add an
  MSRV lane (`cargo +1.85 check --lib`, or whatever the floor becomes) with
  the host rustflags neutralized.
- Enforceable: yes, as an MSRV lane. Without one the field is a published
  claim (crates.io shows it) that nobody checks.

### 2.6 Performance and statistics claims in durable docs have no reproduction record, and contradict each other

- `Cursor::read_varint` doc: "scalar is 2.3x faster than SIMD batch4 decode
  for 1-byte varints ... tied for 3-byte varints". `encode_varint` doc:
  "3.5x faster for 1-byte and 1.5x faster for 3-byte". CHANGELOG 0.2.0:
  "scalar wins 2-6x on decode, 1.5-3.5x on encode". These numbers disagree
  ("tied" vs "2-6x"), and none names the host or CPU flags. This host builds
  with `-Ctarget-cpu=native` (5.1), which changes both sides.
- Both doc comments cite "`notes/SIMD.md` in pbfhogg (dd7f69a) ... (P3-20,
  closed)". That is a durable doc pointing into another repo's `notes/`,
  which AGENTS.md forbids ("nothing durable may cite `notes/`"), and it pins
  a sha. The comparison is reproducible from this repo's own
  `benches/varint.rs`, which is what should be cited.
- "~95% of zigzag-encoded OSM way-ref deltas" (`encode_varint_to_slice` doc,
  README, CHANGELOG 0.4.0) is a pbfhogg dataset statistic. Nothing here
  measures it.
- AGENTS.md's folder table says `reference/performance.md` is "the durable
  record of measured numbers over time". This repo has no `reference/`, so
  the numbers live in doc comments with no host, date or command, and
  criterion's baselines live in `target/criterion/`, which `cargo clean`
  deletes.

- Fix: move the numbers into `reference/performance.md` with host, flags,
  toolchain, the command and a date. Have doc comments state the design
  decision and point at the bench, and drop the pbfhogg `notes/` citations
  and the sha.
- Enforceable: the citation rule is: a textlint rule forbidding `notes/` in
  `src/`, `README.md` and `CHANGELOG.md`, and forbidding 7-to-40-hex-digit
  sha-like tokens in doc comments. The numbers themselves are not
  mechanically checkable; keeping them in one dated file is what stops them
  drifting silently.

### 2.7 "branchless" is false

The `encode_varint_to_slice` doc ("Includes a branchless fast path"), README
("branchless 1-2 byte fast path") and CHANGELOG 0.4.0 ("branchless 1-byte and
2-byte fast paths") all say branchless. The code is two `if` branches with
early returns. The `.plans/` doc only hoped "the compiler can emit cmov".

- Fix: say "1-byte and 2-byte fast paths".
- Enforceable: not practically. Codegen inspection could pin it but would be
  fragile. This is a wording fix.

### 2.8 Smaller false or unenforced claims

- README: "These are intentional trade-offs documented in the source - see
  the doc comments on `PackedIter::next`...". `PackedIter::next` has a `//`
  comment, not a doc comment, so it is invisible in rustdoc.
- README: "All encoding functions skip zero/empty/false values by default".
  `encode_varint`, `encode_tag` and `encode_varint_to_slice` do not. The
  claim holds for *field* encoders.
- README Usage example: never compiled. There are no doctests anywhere, and
  the check passes `--tests`, which excludes doctests. Fix:
  `#![doc = include_str!("../README.md")]` in `lib.rs` (or a
  `#[cfg(doctest)]` module), plus a doctest lane. Enforceable: yes.
- Crate doc in `lib.rs`: "No external dependencies - pure Rust, no std beyond
  default." The second half has no checkable meaning. The crate uses `std`
  (`std::fmt`, `std::error::Error`, `Vec`). If no-std plus `alloc` is the
  intent, `#![no_std]` + `extern crate alloc` makes it enforced by the
  compiler (`core::error::Error` is stable since 1.81). Otherwise drop the
  phrase.
- "No external dependencies" (crate doc, README, AGENTS.md, CHANGELOG 0.2.0)
  is true for `[dependencies]` today, and nothing enforces it.
  `Cargo.lock` has 78 packages, all from dev-dependencies. Enforceable: a
  brokkr `[[dependency_rule]]` with `allow = []` and
  `kinds = ["normal", "build"]` for `protohoggr` (the brokkr-config hunter
  owns the spelling), or a test that parses `Cargo.toml` via
  `env!("CARGO_MANIFEST_DIR")`.
- AGENTS.md: "`brokkr check` # gremlins + clippy + all tests". Doctests are
  not run (none exist, and `--tests` would exclude them), benches are only
  linted, and there is no fmt check. "All tests" overstates.
- AGENTS.md: "Very strict clippy: 30+ lints set to `deny`". This is a drifting
  count (36 clippy + 1 rustc today). Per the user's documentation rule,
  reword it without the number.
- AGENTS.md: "use `#[allow(...)]` locally with care". This advice produces
  the stale allows in 2.9. It should say `#[expect(...)]`.
- AGENTS.md: "Test module uses `#[allow(clippy::unwrap_used)]`". It is a
  crate-level inner attribute in `tests/wire.rs` that also allows
  `missing_docs`, which cannot fire on private test fns, so it is dead.
- AGENTS.md: "Packed encoders take a `&mut Vec<u8>` scratch buffer".
  `encode_packed_bool` does not (documented in its own doc).
- CLAUDE.md: "Always run `brokkr fmt` before a commit". `brokkr check` has no
  formatting phase and there is no hook, so an unformatted commit passes
  everything. Enforceable: a `cargo fmt --check` script check (brokkr-config
  scope) or a pre-commit hook.
- `PackedIter::size_hint` comment: "min elements = remaining / 10". This is
  false on malformed input: ten `0x80` bytes give `(1, Some(10))` and the
  iterator yields 0. It is not unsound (no `TrustedLen`), but the lower bound
  is a contract `Iterator` documents and this type breaks on exactly the
  inputs it promises to tolerate. Fix: return `0` as the lower bound, or
  document it.
- `cumulative_stops_on_overflow_varint` comment says "A valid varint [0x01]",
  but the data is `[0x02]`.
- LLM.md: "This separation is enforced by tooling (review), not by convention
  alone." Nothing in this repo shows it. `.review.toml` holds only an
  `[_audit] id`, with archetypes and providers commented out. LLM.md is
  byte-identical in size to brokkr's copy, so it is a template. The claim is
  not checkable by this build. Either state which review sessions apply to
  protohoggr, or soften it for this repo.
- CHANGELOG Unreleased: the `zigzag_encode_32`/`zigzag_decode_32` signature
  change is breaking, and `Cargo.toml` still says `0.4.0`. That is fine until
  release, but nothing ties the CHANGELOG's "Breaking" section to a version
  bump. (Enforceable with a release-time script check: a "Breaking" entry
  under Unreleased requires a minor bump relative to the last tag.)
- CHANGELOG Unreleased claim "readers should keep accepting it" (the legacy
  10-byte sint32 form) **is** enforced, by
  `sint32_decode_accepts_sign_extended_ten_byte_form`. Noted as the model
  the other claims should follow.

### 2.9 Stale `#[allow]` attributes, which nothing can detect

The cast lints are denied and suppressed locally with `#[allow]`. Several
allows suppress nothing:

- `cast_possible_truncation` on `read_varint_unchecked` and
  `read_varint_unchecked_slow` (no casts in either body).
- `cast_possible_truncation` on `encode_int32_field` and
  `encode_int32_field_always` (`i32 as i64` cannot truncate; only the
  `cast_sign_loss` half applies).
- `cast_possible_truncation` on `encode_bytes_field`,
  `encode_bytes_field_always` and `encode_packed_bool` (`usize as u64`, which
  clippy does not treat as truncating).
- Both allows on `decode_packed_sint64_cumulative` (no `as` casts in the
  body).

An unused `#[allow]` is silent, so each of these is a future cast in that
function that will go unlinted. This is the general fail-open shape: a
suppression keyed to a lint name keeps suppressing whether or not the thing
it was written for is still there.

- Fix: replace every `#[allow]` with `#[expect]` (stable since 1.81, within
  MSRV) and add `allow_attributes = "deny"` to `[lints.clippy]`.
  `unfulfilled_lint_expectations` then flags each stale one.
- Enforceable: yes, fully, by lint.

### 2.10 The gremlins check and the gremlins rule disagree

AGENTS.md: "Em-dash, en-dash, strange quotes, whatever - they're all
verboten." The brokkr gremlins check is a denylist: named codepoints plus
pictograph ranges, with arrows spared on purpose (`brokkr/src/gremlins.rs`,
`pictograph_name`). It passes all of these in tracked files today:

- U+2212 MINUS SIGN in the `encode_tag` doc ("2^29 - 1" uses a minus-sign
  lookalike). This is a hyphen lookalike, exactly the class the rule exists
  for.
- U+00D7 MULTIPLICATION SIGN in the `read_varint` and `encode_varint` docs,
  the CHANGELOG and the bench.
- U+2192 RIGHTWARDS ARROW in `lib.rs`, the bench and many test comments.
- U+2026 ELLIPSIS in the `zigzag_encode_64` doc.
- U+2264 LESS-THAN OR EQUAL TO in the bench docs.

Separately, the earlier `--fix-gremlins` run rewrote the bench doc's
check/cross marks to `[x]` and `[ ]`. That turned "u32 -> 4x5=20 (does not
fit)" into what reads as an unticked checklist item, a silent change of
meaning that no review step catches.

- Fix: either narrow AGENTS.md to what the check enforces, or extend the
  check. brokkr supports a `[gremlins] ban` list; spelling it is
  brokkr-config scope. The strongest version is ASCII-only for `.rs` and
  `.toml`, which is a short allowlist instead of a denylist that can never be
  complete.
- Enforceable: yes, via `[gremlins] ban` (or allow-only mode if brokkr grows
  one).

### 2.11 Phases keyed on config presence go silent without saying so

In the check log, `header`, `textlint`, `manifest`, `script_check`,
`dependency_rules` and `rustdoc` each print `phase X: started` and then do
nothing, because they are unconfigured. Only `member_check` and
`fixture_lint` print "not applicable". A reader of the log sees nine phases
start and reasonably infers nine phases checked something. Today the
consolidated line `gremlins (11 files), publish cycle: ok` is the only honest
statement of coverage.

- Fix (brokkr-side, flagged here because it is what `brokkr check` does
  today): print `not configured` for an inert phase, as member_check does.
- Enforceable: in brokkr, by its own tests.

### 2.12 The lint list is a copied template

`[lints.clippy]` includes lints that cannot fire in this crate:
`regex_creation_in_loops` (no regex), `await_holding_lock` and
`await_holding_refcell_ref` (no async), `large_enum_variant` (no enums),
`clone_on_ref_ptr` (no Rc/Arc). This is harmless on its own. The cost is that
the list reads as curated for this crate, while the lints this crate *does*
need are absent: `undocumented_unsafe_blocks`, `allow_attributes`,
`multiple_unsafe_ops_per_block`, `indexing_slicing` on the decoder (where an
index panic on malformed input is a bug, see L1), and
`arithmetic_side_effects` on the cursor arithmetic.

- Fix: curate the list against what the crate is: a decoder of untrusted
  lengths with `unsafe` hot paths.
- Enforceable: the list itself is the enforcement. Nothing keeps it in sync
  with pbfhogg's copy, and nothing needs to.

---

## 3. The test suite as a system

### 3.1 No process-global state, no clock, no sleeps, no fixtures, no fs

`tests/wire.rs` touches no environment variables, globals, filesystem,
clock, randomness or subprocesses. The serial `--test-threads=1` lane is
therefore pure policy: these tests would be equally sound in parallel or
merged. Stated so the absence is on record.

### 3.2 The check builds criterion and its plotting stack to run 156 pure functions

All 78 packages in `Cargo.lock` come from dev-dependencies: `criterion` with
`html_reports`, and `varint-simd`. Cargo builds dev-dependencies for every
test target, so `cargo test --tests` (prepare and test phases) and
`cargo clippy --all-targets` both compile criterion even though no test uses
it. The warm cost is invisible (about 30 ms). The cold cost (fresh clone,
`cargo clean`, a toolchain bump, a dev-dep bump, or any rustflags change such
as brokkr's lint injection, which re-fingerprints) is a full criterion build,
for a crate whose own build is one file.

- Fix: move the bench into a separate `publish = false` crate (for example
  `benches/` as a workspace member, or `xtask/bench`) that depends on
  protohoggr by path. protohoggr's own dev-dependencies become empty, its
  `Cargo.lock` shrinks to one package, the test build compiles one crate,
  and the "no external dependencies" claim becomes literally true for the
  crate a consumer sees. At minimum drop the `html_reports` feature.
- Enforceable: by a dependency rule forbidding all kinds, including dev, for
  `protohoggr` once the bench has moved.

### 3.3 Three `cargo test` invocations and an empty harness per check

Per run: `cargo test --no-run` (prepare), `cargo test --no-run` again
(test-phase pre-build), then `cargo test`. Each is a separate cargo startup
and fingerprint walk (about 30 ms warm each), and each runs the lib harness,
which has 0 tests, through link and spawn. The empty harness is also the one
the journal records first (`suite_started test_count: 0`).

- Fix: if tests stay integration-only, `[lib] test = false` removes the empty
  harness. If unit tests are added for 1.5 and 1.6 (recommended), the lib
  harness earns its keep and this goes away. The duplicate `--no-run` is
  brokkr's pipeline and its fix is brokkr-side.
- Enforceable: brokkr could warn when a harness reports zero tests on every
  run, a cheap "dead harness" signal.

### 3.4 Test layout: one integration binary and no unit-test module

Everything is in `tests/wire.rs`, so private items (`sint32_wire_bits`,
`read_varint_slow`, `read_varint_unchecked_slow`, the scalar and SSE2 count
implementations) are reachable only through the public API. This is why the
differential tests in 1.5 and 1.6 cannot be written today. Focused runs
(`brokkr test NAME`) are cheap with one binary, and that should be kept:
adding a `#[cfg(test)] mod tests;` in `src/` (in its own file) gives one lib
harness plus one integration harness, not more.

---

## 4. What the tests reach that they should have been handed

### 4.1 `count_packed_varints` has no injection point for its implementation

The implementation is chosen by `#[cfg(target_arch)]` at compile time, so a
test cannot pick the scalar or the SSE2 version, and a host can only ever
test one of them. This is the "production value with no injection point"
shape, and it is the root of 1.5.

- Fix: as in 1.5. Both implementations always compile as private functions,
  the public function dispatches, and unit tests call each directly.

### 4.2 Ambient dependencies

None in tests or production: no clock, randomness, env, cwd or ids. The bench
uses a fixed `N = 8000` and fixed delta patterns, which is deterministic and
fine. Recorded as checked.

### 4.3 Test-only shortcuts reachable from production

None found. `read_varint_unchecked` and `encode_varint_to_slice` are
production APIs used by pbfhogg, not test hooks.

---

## 5. Where the tests assume they run, and what they touch

### 5.1 The check passes only because of `~/.cargo/config.toml`

`~/.cargo/config.toml` (user-wide, not in the repo) sets, for
`x86_64-unknown-linux-gnu`: `-Zthreads=16`, `-Ctarget-cpu=native`,
`-Clink-arg=-fuse-ld=wild`, plus `rustc-wrapper = brokkr-rustc-guard` and
`jobs = 12`. Consequences:

- **The benches only compile because of `target-cpu=native`.** In
  varint-simd 0.4.1, `decode_two_unsafe` and `decode_four_unsafe` are
  `#[cfg(any(target_feature = "ssse3", doc))]`. Baseline x86_64 has no SSSE3,
  so on any host without native or SSSE3 rustflags (a CI runner, a colleague,
  this host with the config moved),
  `cargo clippy --all-targets` fails to compile `benches/varint.rs`, and
  `brokkr check` fails at clippy. That is a refusal, at least, not a silent
  degradation. On aarch64, varint-simd's x86 API is absent entirely.
  Fix: gate the bench (or the SIMD half of it) on
  `#[cfg(target_feature = "ssse3")]` with a scalar-only fallback, or set
  `rustflags` for the bench crate in a repo-local `.cargo/config.toml` once
  the bench is its own crate (3.2), so the requirement is declared where the
  code is.
- **Stable toolchains cannot build here at all** (`-Zthreads`), which is what
  makes the MSRV claim untestable on this host (2.5).
- **All tests run on native codegen** (znver-class AVX2/AVX-512). The SSE2
  path is exercised with the compiler free to auto-vectorize around it, and
  the scalar path is never built (1.5). A difference between baseline and
  native codegen would be a silent degradation: nobody would notice.
- **`wild` via gcc's `-fuse-ld=wild`** (gcc >= 16.1 per the comment) is a
  linker requirement on every test binary link. A host without it gets a
  link error. That is a refusal, but one whose cause is outside the repo.

None of these are visible from the repo. A repo-local `.cargo/config.toml`
or `rust-toolchain.toml` stating what the project needs (nightly, and
SSSE3 for the bench) would make the dependency explicit. A lane that builds
with host rustflags stripped would prove the crate does not need them.

### 5.2 The toolchain comes from the user's rustup default

AGENTS.md says "nightly toolchain", and `rustup show active-toolchain` says
`nightly-x86_64-unknown-linux-gnu (default)`. No file in the repo pins it.
Which nightly runs is whatever the user last installed, and nightly clippy
adds and renames lints, so a `brokkr check` result is not reproducible
across days. Fix: `rust-toolchain.toml` with a dated nightly, bumped
deliberately. Enforceable: yes, by the file itself (rustup honours it).

### 5.3 Single architecture

Every check runs on x86_64. The `cfg(not(target_arch = "x86_64"))` code
(the scalar count) has never been compiled by anyone on this project, so a
typo there would ship. Fix: the always-compiled refactor in 1.5 removes the
need. Otherwise, a `cargo clippy --target aarch64-unknown-linux-gnu --lib`
lane needs only the target's std, not a cross linker.

### 5.4 `brokkr check` writes into `.brokkr/` in the repo, which is not ignored

Each run writes `.brokkr/check-logs/check-<ms>.log` (kept to the newest 10,
`run_log.rs`) and `.brokkr/accounting/<run>/{plan.json,journal.jsonl}`
(about 100 KB per run, newest 10 kept, `ACCOUNTING_RUNS_KEPT`). Retention is
bounded, so the size is fine. But:

- `.brokkr/` shows as `??` in `git status` permanently. An agent following
  "commit lockfiles and dirty markdown" with `git add -A` commits brokkr's
  journals, including absolute paths such as
  `/home/folk/Programs/protohoggr/target/debug/build/...` in `plan.json`.
- brokkr's own docs (`docs/commands/measure.md`, `output-channels.md`)
  describe `.brokkr/*.db` as gitignored, so they assume an ignore rule this
  repo does not have.
- gremlins scans "tracked plus untracked-not-ignored" files. Today brokkr
  writes only `.log`, `.json` and `.jsonl` there, which are not scanned
  extensions. If brokkr ever writes a `.md` or `.toml` into `.brokkr/`, the
  check would start scanning its own output.

- Fix: add `.brokkr/` to `.gitignore`. `.brokkr/` is brokkr's directory by
  convention across projects, so that is the owner and the location is
  right; it just needs to be declared ignored. Better still, brokkr could
  refuse or warn when its state root is not ignored (brokkr-side).
- Enforceable: a script check asserting
  `git check-ignore -q .brokkr` succeeds, or a brokkr preflight.

### 5.5 What tests write

The tests write nothing. Benches (criterion) write `target/criterion/`
reports and baselines inside cargo's `target/`. That is criterion's
convention, but it puts the only record of measured numbers into a directory
`cargo clean` and brokkr's `clean` destroy (see 2.6). The durable record
belongs in `reference/performance.md`, with criterion's output treated as
scratch.

### 5.6 Locale, timezone, filesystem, user

Nothing in the tests or the crate depends on them. The check depends on
brokkr's state under `~/.brokkr/` (`compile.lock`, `test-runs/`), which
belongs to brokkr and is outside this repo's responsibility.

---

## Lateral findings (outside the immediate scope)

### L1. Bug: a malformed length prefix panics instead of returning `Err`

`Cursor::read_len_delimited` does
`let len = self.read_varint()? as usize; if self.pos + len > self.data.len()`.
A length varint near `u64::MAX` (for example `[0xFF; 9] + [0x01]`) makes
`self.pos + len` overflow:

- dev profile: panic "attempt to add with overflow";
- release: wraps to a small number, the check passes, and
  `&self.data[self.pos..self.pos + len]` panics on a reversed range.

The same function backs `skip_field(WIRE_LEN)` and `read_raw_field(WIRE_LEN)`.
It contradicts AGENTS.md ("Use `WireResult<T>` / `WireError` for fallible
operations, not panics") and README ("rejects malformed sequences"). It is
not memory-unsafe, but a single corrupt byte in a PBF blob aborts pbfhogg or
elivagar rather than surfacing an error. No test feeds a huge length.

- Fix: `if len > self.remaining()`, plus a test with a `u64::MAX` length.
- Enforceable: `clippy::arithmetic_side_effects` scoped to `Cursor`, or a
  fuzz target. A fuzz lane with `cargo fuzz` (nightly is already the default)
  over `Cursor` would find this class in seconds.

`read_fixed32`, `read_fixed64` and `skip_field`'s fixed arms use
`self.pos + 4` / `+ 8`, which cannot overflow while `pos <= len`. But `pos`
can exceed `len` after a contract-violating `read_varint_unchecked`, which is
why `remaining()` uses `saturating_sub`. Writing every bound as
`n > self.remaining()` removes the question.

### L2. `read_varint` accepts non-canonical encodings

`[0x80, 0x00]` decodes to 0. Protobuf permits this, so it is not a bug. But
"rejects malformed sequences" in the README could be read as including it.
Noted for wording only.

### L3. The harness memory file is stale and against the user's rules

`~/.claude/projects/-home-folk-Programs-protohoggr/memory/MEMORY.md` says
"78 integration tests" and "~810 lines" (today: 156 tests and about 1300
lines in `lib.rs`), and lists the API as of an older version. The user's
global rules say never to use the harness memory directory. It is loaded
into every session's context as if authoritative. It should be deleted,
with anything worth keeping moved into AGENTS.md.

### L4. Publish contents

`Cargo.toml` has no `include` or `exclude`, so `cargo publish` ships
`AGENTS.md`, `CLAUDE.md`, `LLM.md`, `.review.toml` (with its audit id),
`brokkr.toml`, `benches/` and `tests/` to crates.io. brokkr's
`publish_cycle` phase checks publication cycles, not contents. An
`include = ["src/**", "README.md", "CHANGELOG.md", "LICENSE*"]` list makes
the published surface explicit. It is enforceable by `cargo package --list`
in a script check.

### L5. `.claude/settings.local.json` allowlists raw `cargo`

The project rules say never to run raw `cargo`, and the local allowlist
permits `Bash(cargo:*)`, `Bash(cargo test:*)` and `Bash(cargo clippy:*)`.
The file is ignored by the user's global git ignore, so this is local only,
but the allowlist and the rule disagree.

### L6. The bench label "large_3B" is not accurate

The large deltas include 5000 (zigzag 10000, 2 bytes) next to 3-byte values.
The label overstates the varint width, which feeds the "tied for 3-byte"
claim in 2.6.
