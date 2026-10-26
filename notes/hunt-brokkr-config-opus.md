# Hunt: brokkr-config - how brokkr.toml should be configured for protohoggr

Scope: which `brokkr.toml` settings exist, which this project should set and to
what, which defaults are wrong for it, and which verification gaps a setting
would close or hold mechanically. Sources read: every `brokkr man` topic that
bears on configuration or on what the check phases do (`config`, `conventions`,
`sweeps`, `check`, `test-lanes`, `hygiene`, `test`, `clippy`, `bench`, `clean`,
all in `--full`), `brokkr.toml`, `Cargo.toml`, `.gitignore`, `src/lib.rs`,
`tests/wire.rs`, `benches/varint.rs`, `README.md`, `CHANGELOG.md`, `AGENTS.md`,
`LLM.md`, `.review.toml`, the ten retained run logs under `.brokkr/check-logs/`,
and pbfhogg's `brokkr.toml` and the sibling `.gitignore` files for the
conventions this user already runs elsewhere.

No brokkr or cargo command other than `brokkr man` was run, so every cost figure
below is either read from the retained run logs or labelled as an estimate.

## 1. What brokkr check does here today (from the run logs)

With only `project = "protohoggr"`, `brokkr check` takes the legacy path: no
`[[check]]`, so it synthesizes one sweep named `all-features`.

- Convention line: `gremlins (11 files), publish cycle: ok`. header, textlint,
  manifest, script_check and dependency_rules start and do nothing (no config).
- clippy: `cargo clippy --keep-going --all-targets --message-format=json
  --all-features -- --cap-lints=warn`, one sweep, warm in about 0.1 to 0.15 s.
- rustdoc: phase starts, inert (no `[rustdoc]` table).
- prepare + test: `cargo test --all-features --tests -- --test-threads=1`, dev
  profile only, 156 executions, about 0.3 s warm.
- member_check and fixture_lint: not applicable.
- Whole run: about 0.9 to 2.3 s warm.

So the entire gate is one dev-profile, x86_64-host, doctest-free build. Every
recommendation below is weighed against that: the current check is so cheap that
almost any added sweep or phase is affordable, and the dominant cost of the
proposed config is Miri (section 4), not the sweeps.

## 2. Setting-by-setting inventory

Every top-level key the manual documents, with a verdict for this repository.

### Keys this project should set

| Key | Recommendation | Why |
|---|---|---|
| `[[check]]` | Two explicit entries, `dev` (`profile = "dev"`) and `release` (`profile = "release"`) | Replaces the legacy synthesized `--all-features` sweep (see 3.1) and adds the profile consumers actually ship (see 3.2). |
| `[test] default_package` | `"protohoggr"` | Removes `brokkr test`'s fallback guess (`Project::cli_package()` then error). Harmless, makes resolution explicit. |
| `[test] default_profile` | `"gate"` | The whole check costs about a second; there is no reason for the routine run to certify less than the gate. |
| `[test] gate_profile` | `"gate"` | Makes `brokkr check --gate` work at all (today it is a load-time error because no gate profile exists). |
| `[test.profiles.gate]` | `sweeps = ["dev", "release"]`, `certifies = "complete"` | Coverage audit, execution accounting, doctest carriers for each tested build, dead-filter audit for any filter added later. |
| `[test] doctests` | `true` | The default `false` is justified in the manual by "CI runs under nextest". This repo has no CI at all; `brokkr check` is the only gate, so the default's premise does not hold (see 3.3). Under a complete default profile the flag only matters for ad-hoc runs, but it should state the truth. |
| `[rustdoc]` | Present, `document_private_items = true` | `src/lib.rs` carries intra-doc links (`[`read_varint`](Cursor::read_varint)`, `[`zigzag_encode_32`]`, `[`Cursor::read_sint32`]`, `[`PackedSint32Iter`]`, `[`zigzag_decode_32`]`). Today nothing evaluates `rustdoc::` lints, so a rename breaks these silently. Private items carry doc comments too (`sint32_wire_bits`, `read_varint_slow`), hence the private flag. Nightly is detected and the phase lints with `--check`, so the cost is sub-second. |
| `[[dependency_rule]]` | `from = "protohoggr"`, `allow = []`, `kinds = ["normal", "build"]` | The central claim of the crate ("No external dependencies", stated in `README.md`, `AGENTS.md`, the `src/lib.rs` crate doc and `CHANGELOG.md` 0.2.0) is enforced by nothing today. An `allow` list fails closed: any dependency added later is a violation. |
| `[[dependency_rule]]` (second) | `from = "protohoggr"`, `allow = ["criterion", "varint-simd"]`, `kinds = ["dev"]` | Optional. Closes the dev boundary so a new dev-dependency is a conscious edit of `brokkr.toml`. Matters because dev-dependencies are compiled into every test build (see 6.1). |
| `[gremlins] ban` | at least `["U+FFFD"]`; see 3.6 for the rest | `tests/wire.rs` contains two literal U+FFFD replacement characters inside the comment of `encode_tag_standalone` (a mangled arrow). The built-in set does not flag U+FFFD, so the corruption passes every check today. |
| `[manifest] sort_dependencies` | `true` | Free; the one dependency table is already sorted, so this costs nothing and holds the order. Low value, listed because smallness is not a filter. |
| `[[textlint]]` | Three rules, see 3.5 | Hold AGENTS.md rules that are text-shaped. |
| `[[script_check]]` | rustfmt, cross-target lib clippy, Miri (host and cross targets) | The gaps no native phase can express, see section 4. |

### Keys that exist and should stay unset, with the reason

| Key | Why not |
|---|---|
| `include` | Single repository, nothing to compose. (See 5.4 for the one case where it could carry user-wide conventions, and why the user-wide file is the better carrier.) |
| host sections (`[<host>]`, `[host.<name>]`) | No datasets, no port, no host features. `brokkr env` would warn about nothing. |
| `worktree_keep` | Only matters for `--commit` worktrees (`brokkr bench --commit`); default 6 is fine for a crate whose cold build is seconds. |
| `disable_toolchain` | No `rust-toolchain.toml` exists to disable (see 6.5 for whether one should). |
| `strip_rustflags` | No `.cargo/config.toml` in the tree. |
| `[cargo_env]` | No build script. |
| `[deps] workspace_dep_ignore` | Not a workspace; the key only applies to `[workspace.dependencies]`. |
| `[bin]`, `[member_check]` | No binaries. `[member_check]` would compile the lib under package-mode resolution, which for a single package with zero normal dependencies is identical to the ordinary build: pure cost, no signal. |
| `capture_env` | For measured runs; nothing here is measured through brokkr's results store. |
| `[lints] allow` / `allow_exact` | Nothing needs suppressing. Every entry would also change every unit's fingerprint in the test phase. |
| `[header]` | No license header convention exists. |
| `[[fixture_lint]]` | No `disallowed_*` clippy configuration to prove. |
| `[[quarantine]]` | No test needs one. |
| `[[check]] parallel` | One integration-test binary (plus the lib's empty unit harness). The fan-out has nothing to overlap. |
| `[[check]] harness = "nextest"` | Process-per-test buys nothing for 156 sub-millisecond pure tests and would retire the shared-process detector for free. |
| `isolation = "process"` | No process-global state in the tests. |
| `feature_unification`, `packages`, `build_packages`, `test_exclude_packages` | Single package, no features, no CLI. |
| `[[check]] rustflags` | Would isolate into `target/rustflags-<hash>` and recompile everything; nothing needs a cfg flag. |
| `[[check]] target` | Desirable in principle (see 4.2) but not runnable on this host for any triple that changes `target_arch`: brokkr executes test binaries itself and refuses emulated runners, `aarch64-unknown-linux-musl` (whose std is installed) cannot execute, and `i686-unknown-linux-gnu` needs 32-bit link files this host lacks (`/usr/lib32` has runtime `.so` files only; there is no gcc `32/` multilib directory). It would fail loudly at link or listing time, not silently, but it would fail. Miri covers the same ground without a linker. |
| `[test] serial_builds` | No build scripts writing outside `OUT_DIR`. |
| `[test] debug` | Irrelevant once both sweeps pin `profile` explicitly: `brokkr test NAME` then runs the name under both dev and release (sweep `profile` outranks `[test] debug`). |
| `test_threads`, `include_ignored`, `skip`, `only`, `lanes`, `curated` | No filters, no ignored tests, one lane. |

## 3. Defaults that are wrong for this project, and gaps a setting closes

### 3.1 The legacy `--all-features` sweep names a configuration that does not exist

With no `[[check]]` entry the run is labelled `all-features` and passes
`--all-features` to clippy and cargo test. The crate has no features. The label
reads as coverage of a feature matrix; it is the default build under another
name. It is also fail-open in the direction the manual warns about: the moment a
feature is added (a `simd` or `std` toggle is the obvious candidate for this
crate), the legacy sweep silently widens to it and nothing ever builds the crate
without it. The manual rejects `features = "all"` in `[[check]]` for exactly
this reason.

Fix: explicit `[[check]]` entries with `features = []` (implicit). When a
feature arrives, adding it is an explicit edit, and a `no_default_features`
entry becomes an obvious companion. Enforced by: the presence of `[[check]]`
itself (brokkr only synthesizes the legacy sweep when there is none).

### 3.2 Only the dev profile is ever tested; consumers ship release

`brokkr check`'s test phase builds dev unless a sweep says otherwise. pbfhogg
and elivagar consume this crate in release builds, where overflow checks are
off and the optimizer is free to exploit undefined behaviour in the `unsafe`
paths (`read_varint_unchecked`, `encode_varint_to_slice`, the SSE2 loop in
`count_packed_varints_sse2`). The concrete semantic delta today is arithmetic
overflow: `read_len_delimited` computes `self.pos + len` with `len` taken from
an untrusted varint. In dev that panics with "attempt to add with overflow"; in
release it wraps and then panics later inside the slice index (see 7.1). No
test exercises it today, but the dev-only gate means a test written against one
behaviour can never be seen to diverge in the other.

Second divergence, a usability trap: `brokkr test NAME` defaults to release
while `brokkr check` runs dev, and AGENTS.md documents both commands side by
side without saying so. A failure that depends on the profile shows up in one
command and not the other. Pinning `profile` on both sweeps makes `brokkr test`
run the name under both.

Cost: a release clippy run (the profile is part of the dedupe key, so it is not
shared with dev; the lint surface is identical here since nothing reads
`cfg(debug_assertions)`), and a release build of the test graph including every
dev-dependency (criterion with `html_reports`, varint-simd). Cold that is tens of
seconds once; warm, the logs suggest a few hundred milliseconds. Enforced by:
the sweep and the complete claim (an unreferenced `[[check]]` entry is a load
error under `certifies = "complete"`, so the release sweep cannot be quietly
dropped from the gate).

### 3.3 Doctests are excluded by a default whose premise is false here

`brokkr check` scopes every sweep to `--tests` because "every brokkr-managed
project runs its CI under cargo-nextest". protohoggr has no CI directory at all.
Today `src/lib.rs` has no doc examples, so the exclusion costs nothing yet, but
`README.md` carries a Usage example that has never been compiled by anything:
it is documentation that reads as working code with no evidence that it is.
(It does compile in my reading, but an unused `wire_type` binding shows nobody
ran it under `-D warnings`.)

Fix: `[test] doctests = true`, plus the complete default profile (which runs a
doctest carrier per tested build regardless), plus a code change outside
`brokkr.toml`: `#![doc = include_str!("../README.md")]` in `src/lib.rs`, so the
README example becomes a doctest. Caveat from the manual: markdown never counts
as code for the markdown-only shortcut, so a README-only edit would not trigger
the build. Under a complete default profile the shortcut is probably waived
anyway (see 3.7). Enforced by: the doctest carrier under the complete claim; the
carrier accounting reports a missing rustdoc stream as `missing`.

To verify on the first run: whether a carrier with zero doctests reads as
`no tests ran` and passes, as the manual's zero-test-unit rule suggests.

### 3.4 rustdoc lints are declared nowhere and evaluated nowhere

`missing_docs` (rust) and `doc_markdown` (clippy) are denied in `Cargo.toml`, so
the crate takes documentation seriously, yet broken intra-doc links are
invisible: clippy does not run rustdoc's link resolver. `[rustdoc]` closes it.
Enforced by: the rustdoc phase, any diagnostic fails.

### 3.5 AGENTS.md rules that are text-shaped and held by nothing

Three rules, each currently either false or unguarded:

1. **Durable text citing `notes/`.** AGENTS.md: nothing durable may cite
   `notes/`, and "a code comment must carry its full context, because it
   outlives the note". The doc comments on `Cursor::read_varint` and
   `encode_varint` both cite "`notes/SIMD.md` in pbfhogg (dd7f69a)". That is
   another repository's notes, pinned at a sha, so whether the rule covers it is
   an intent question (see section 8); read literally, the rule is false today
   in two places, and the pinned sha is exactly the drifting specific the global
   documentation rule warns about. pbfhogg holds the same rule with a Python
   script (`scripts/check_doc_links.py`); a textlint rule is the native
   equivalent here:

   ```toml
   [[textlint]]
   name = "durable-text-does-not-cite-notes"
   pattern = '\bnotes/'
   paths = ["src/**/*.rs", "tests/**/*.rs", "benches/**/*.rs", "README.md", "CHANGELOG.md", "docs/**", "reference/**"]
   must_scan = ["src/lib.rs"]
   message = "durable text must not cite notes/; carry the context inline"
   ```

   `must_scan` is the guard against the glob silently stopping to cover
   `src/lib.rs` (a rename of the file fails the rule rather than passing it).
   `docs/**` and `reference/**` select nothing today; that is not an error, and
   `brokkr check --audit` reports it.

2. **Instructions to run raw cargo.** AGENTS.md: never run raw `cargo`, use
   brokkr. The module doc of `benches/varint.rs` says "Run with: cargo bench
   --bench varint". Beyond contradicting the rule, that instruction writes
   criterion baselines into `target/criterion`, cargo's directory, under the
   rolling name `base`, where `cargo clean` destroys them and every run
   overwrites the last; `brokkr bench` exists precisely to move them to
   `.brokkr/bench/` under commit-named baselines with an environment stamp.
   Two rules, because `region` is defined for Rust files only:

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

   False today in `benches/varint.rs`.

3. **Escaping `unwrap_used` in production code.** AGENTS.md: `unwrap_used` is
   denied, tests get the allow. Nothing stops a `#[allow(clippy::unwrap_used)]`
   (or a crate-level `#![allow(...)]`) landing in `src/`:

   ```toml
   [[textlint]]
   name = "no-unwrap-escape-in-src"
   pattern = 'allow\([^)]*clippy::(?:unwrap_used|expect_used|unwrap_in_result)'
   paths = ["src/**/*.rs"]
   region = "code"
   message = "unwrap_used is denied in library code; return WireResult instead"
   ```

   Holds today (no violation).

The better mechanism for two neighbouring rules is not brokkr but `Cargo.toml`
(see 6.2 and 6.3): stale `#[allow]` attributes and unsafe blocks without
`SAFETY:` comments are clippy restriction lints, and brokkr's
any-diagnostic-fails rule turns them into hard failures at no extra config.

### 3.6 The gremlin set is narrower than AGENTS.md's rule

AGENTS.md: "Em-dash, en-dash, strange quotes, whatever - they're all verboten."
The built-in set bans dashes, quotes, invisibles, emoji and dingbats, and
deliberately spares the Arrows block. What passes today:

- U+FFFD REPLACEMENT CHARACTER, twice, in `tests/wire.rs` (`encode_tag_standalone`
  comment). This is corruption, not style; ban it unconditionally.
- U+00D7 MULTIPLICATION SIGN in the `Cursor::read_varint` and `encode_varint`
  doc comments, in `CHANGELOG.md` 0.2.0, and throughout the `benches/varint.rs`
  module doc. Note the bench doc's `4x3=12 [x]` lines are the residue of an
  earlier `--fix-gremlins` run that rewrote the check-mark dingbats but left the
  multiplication signs beside them.
- U+2212 MINUS SIGN in the `encode_tag` Panics section ("2^29 - 1" with a
  typographic minus).
- U+2026 HORIZONTAL ELLIPSIS in the `zigzag_encode_64` doc.
- U+2264 LESS-THAN OR EQUAL in the `benches/varint.rs` module doc.
- U+2192 RIGHTWARDS ARROW in many test comments and in the
  `decode_packed_sint64_cumulative` body (spared by brokkr on purpose).

`ban` is scan-only (`--fix-gremlins` has no ASCII mapping for extra
codepoints), so each must be fixed by hand once. Which of these the user
considers "strange" is an intent question (section 8); U+FFFD is not. The `U+`
spelling keeps `brokkr.toml` itself free of the characters. Enforced by: the
gremlins phase.

### 3.7 `.brokkr/` is untracked and unignored here, unlike every sibling

`git status` shows `?? .brokkr/`. pbfhogg and elivagar both ignore `.brokkr/*`
(un-ignoring `results.db`). Consequences in this repo:

- **The markdown-only shortcut is probably dead.** Its classifier counts
  "staged, unstaged and untracked-not-ignored paths"; `.brokkr/check-logs/*.log`
  and `.brokkr/accounting/*/plan.json` are untracked non-markdown files that
  exist after the first check, so the tree should always classify as `Code`.
  I could not verify whether brokkr excludes its own state directory from that
  classifier; the test is a markdown-only edit and a look for the
  `markdown-only tree:` line. (Moot if the default profile is complete and that
  waives the shortcut; the manual says any `--profile` waives it but is silent
  on `default_profile`.)
- **State leaks into scans.** gremlins and textlint read untracked-not-ignored
  files. `.brokkr/` holds no `.md` or `.toml` today, but brokkr writes
  `.brokkr/parallel-timings.toml`, `.brokkr/worktrees.toml` and
  `.brokkr/nextest-synth.toml` in other configurations.
- **Baselines.** `brokkr bench` writes criterion baselines to `.brokkr/bench/`;
  unignored, they show in every `git status` and are one `git add -A` from being
  committed.

Fix: add `.brokkr/` (or `.brokkr/*` with the sibling exception pattern) to
`.gitignore`. Not a `brokkr.toml` setting; listed because it decides how several
settings behave. Enforceable by a `[[script_check]]` running
`git check-ignore -q .brokkr && echo brokkr-state-ignored`, which fails closed
if the line is ever removed.

## 4. Gaps only a `[[script_check]]` can close

### 4.1 Formatting

CLAUDE.md: "Always run `brokkr fmt` before a commit." Nothing checks it. A
pre-clippy script check holds it mechanically and costs about a hundred
milliseconds (rustfmt takes no build lock and is never reaped as a stray):

```toml
[[script_check]]
name = "rustfmt"
command = "cargo fmt --all --check && echo rustfmt-clean"
expect = "rustfmt-clean"
stage = "pre-clippy"
```

`--all` rather than a file list, so a new target cannot fall outside it.

### 4.2 The non-x86_64 code path is never compiled, linted or run

`count_packed_varints` dispatches on `cfg(target_arch = "x86_64")`;
`count_packed_varints_scalar` exists only under `cfg(not(target_arch =
"x86_64"))`. On this host it is dead code to every phase: clippy does not see
it, no test runs it, and `count_varints_17_bytes` / `count_varints_32_bytes`
claim in their comments to exercise the SIMD/scalar split only on x86-64. The
README advertises a "scalar fallback elsewhere" that has never been built.

The same is true of everything 32-bit: `read_len_delimited` and
`read_varint_unchecked`-adjacent code cast `u64` to `usize`, which truncates on
a 32-bit target (see 7.1 for the resulting bug).

Two script checks close it with what is already installed (the nightly toolchain
has the aarch64-musl std and the miri component with rust-src):

```toml
# Lint the cfg(not(x86_64)) branch. --lib keeps dev-dependencies (criterion,
# varint-simd) out of the build; no linker is needed for clippy.
[[script_check]]
name = "clippy-aarch64-lib"
command = "cargo clippy --target aarch64-unknown-linux-musl --lib -- -D warnings 2>&1 && echo cross-clippy-ok"
expect = "cross-clippy-ok"
stage = "pre-test"
diagnostics = "rustc"
```

`-D warnings` reproduces brokkr's any-diagnostic-fails rule. `pre-test` rather
than `background` because it shares `target/` with the run (its artifacts land
in `target/aarch64-unknown-linux-musl/`, a directory cargo owns and `cargo
clean` may remove, which is correct for a build cache).

brokkr gap worth naming: there is no clippy-only sweep shape. A `[[check]]
target` always runs the test phase too, which cannot execute for a non-native
triple, so cross-target linting has to leave the native pipeline (and with it
the JSON diagnostic rendering, the dedupe and the `[lints]` plumbing).

### 4.3 The unsafe code has no undefined-behaviour check, on any target

The crate's public `unsafe` API (`Cursor::read_varint_unchecked`,
`encode_varint_to_slice`) and the raw-pointer SSE2 loop are tested only by
running them natively, where an out-of-bounds read of one byte does not crash
and so proves nothing. Miri is installed. Running the suite under Miri on the
host and on foreign targets covers UB, 32-bit `usize`, big-endian byte order
(every fixed-width path uses `to_le_bytes`/`from_le_bytes`; nothing tests that
on a big-endian target) and the scalar fallback at once, with no linker:

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

Notes and costs:

- Miri writes to `target/miri/` (cargo-miri's own default, which no brokkr name
  collides with: brokkr reserves `rustflags-*`, `unify-*`, `fixture-*`,
  `brokkr-worktrees`, `verify`) and builds a sysroot per target into
  `~/.cache/miri`, the miri tool's own cache. No write lands in a directory
  another tool owns. `background` is legal because none of it touches the
  target dirs the main run builds into.
- Unmeasured. The first run builds a sysroot per target (my estimate: tens of
  seconds each); warm, 156 tiny tests should take seconds per target. Because
  background checks are joined before any test is listed, Miri's wall time adds
  directly to every check. Measure before deciding it belongs in the routine
  run.
- **Risk:** `cargo miri test --tests` builds every dev-dependency for the
  target. varint-simd is an x86 SIMD crate; whether it compiles (or compiles
  empty) for `s390x` and `i686` is unknown to me. If it does not, the cross Miri
  entries fail on a bench dependency, not on protohoggr. The structural fix is
  6.1 (move the benches out), which makes the library's test graph
  dependency-free and every cross check cheap.
- The 20 s per-test cap does not apply to script checks; each entry gets the
  five-minute `script_check` ceiling from its own start.
- Miri runs outside brokkr's execution accounting, so its tests are not in the
  complete claim's ledger; the sentinel is the whole verdict.
- brokkr gap: `[[script_check]]` has no `when = "gate"` key (member_check and
  fixture_lint have one). An expensive check cannot be confined to the gate
  except by making the routine profile `partial` with `skip_phases =
  ["script_check"]`, which also drops the cheap ones (rustfmt) and makes plain
  `brokkr check` exit 10. Also: script checks run under the markdown-only
  shortcut, so a background Miri would run on a README typo fix.

### 4.4 The MSRV claim is enforced only for library APIs

`Cargo.toml` declares `rust-version = "1.85"`; AGENTS.md says the toolchain is
nightly; no 1.85 toolchain is installed. clippy's default-warn
`incompatible_msrv` lint reads `rust-version` and flags std APIs stabilized
after it, and under brokkr any warning fails, so API-level drift is already
caught. Language-feature drift (a syntax stabilized after 1.85) is not. A
`cargo +1.85 check --lib` script check would hold it but fails on any host
without that toolchain (a loud failure, not a silent one). Whether the field is
load-bearing for crates.io consumers or vestigial is an intent question.

## 5. Proposed brokkr.toml

```toml
project = "protohoggr"

# Two sweeps, one build each. dev is what the edit loop compiles; release is
# what pbfhogg and elivagar ship (overflow checks off, optimizer free to act on
# UB). Pinning profile on both makes `brokkr test NAME` run the name in both.
# Explicit entries also retire the legacy synthesized --all-features sweep:
# the crate has no features, and a feature added later must not silently join
# the only sweep.
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
# No CI exists; brokkr check is the only gate, so the nextest-parity reason for
# the default (false) does not apply.
doctests = true

[test.profiles.gate]
description = "Both profiles, doctest carriers, coverage audit"
sweeps = ["dev", "release"]
certifies = "complete"

[rustdoc]
document_private_items = true

[[dependency_rule]]
name = "no-external-dependencies"
from = "protohoggr"
allow = []
kinds = ["normal", "build"]

[[dependency_rule]]
name = "dev-dependencies-are-bench-only"
from = "protohoggr"
allow = ["criterion", "varint-simd"]
kinds = ["dev"]

[manifest]
sort_dependencies = true

[gremlins]
# U+FFFD is corruption. Extend per the intent question in the hunt notes
# (U+00D7, U+2212, U+2026, U+2264, U+2265, arrows U+2190..U+21FF).
ban = ["U+FFFD"]

# ... the three [[textlint]] rules from section 3.5 ...
# ... the rustfmt, clippy-aarch64-lib and miri-* [[script_check]] entries
#     from section 4, plus optionally the .brokkr ignore guard from 3.7 ...
```

Load-time checks this layout must pass, from the manual: a complete profile
must reference every `[[check]]` entry (it does); it may not use `extends` or
`skip_phases` (it does not); `test_threads` must be unset or 1 (it is);
`doctests = true` needs a non-parallel, non-nextest entry (both are). After
writing it, run `brokkr check --audit` once to catch selectors that match
nothing.

## 6. Lateral findings outside brokkr.toml

### 6.1 Bench-only dev-dependencies are compiled into every test build

Cargo links all dev-dependencies into every test target, so criterion (with
`html_reports`, which pulls a plotting stack) and varint-simd are compiled for
`tests/wire.rs` although only `benches/varint.rs` uses them. That is the bulk of
every cold build, it doubles with the release sweep, it is what would break the
cross-target Miri runs, and it is what a 1.85 MSRV check would trip on first
(criterion 0.8's own MSRV). A separate bench package (a two-member workspace,
or a standalone `benches/` crate with a path dependency on protohoggr) makes
the library's test graph empty, lets the dev `[[dependency_rule]]` tighten to
`allow = []`, and moves `brokkr bench` onto the bench package unchanged.
Enforceable afterwards by the tightened dependency rule.

### 6.2 Stale `#[allow]` attributes

Several local allows suppress lints that cannot fire, which is the drift the
denied cast lints were meant to prevent from going unnoticed:

- `read_varint_unchecked` and `read_varint_unchecked_slow` allow
  `cast_possible_truncation` and contain no `as` cast.
- `decode_packed_sint64_cumulative` allows `cast_possible_truncation` and
  `cast_possible_wrap` and contains no `as` cast.
- `encode_int32_field` and `encode_int32_field_always` allow
  `cast_possible_truncation` for `value as i64 as u64`, which widens; only the
  sign-loss allow is live.
- `encode_bytes_field`, `encode_bytes_field_always` and `encode_packed_bool`
  allow `cast_possible_truncation` for `usize as u64`; I believe clippy does not
  lint that direction, so these are probably stale too.

Mechanical hold: `allow_attributes = "deny"` (and optionally
`allow_attributes_without_reason`) in `Cargo.toml`'s `[lints.clippy]`, which
forces `#[expect(...)]`; an expectation that no longer fires raises
`unfulfilled_lint_expectations`, and brokkr fails on it. One caveat with the
cross-target clippy of 4.2: an expectation for a lint that fires on one target
and not the other becomes unfulfilled there, so such sites need `cfg_attr`.

### 6.3 `SAFETY:` comments are a convention nothing enforces

`src/lib.rs` comments every unsafe block; the tests' `unsafe { ... }` calls to
`encode_varint_to_slice` and `read_varint_unchecked` carry none.
`clippy::undocumented_unsafe_blocks` holds the convention; a textlint
`except_above` window could approximate it, but the lint is exact.

### 6.4 `.gitignore` lists `Cargo.lock`, which is tracked

The ignore line is inert for a tracked file, so it fails open and says
something false. It is also a hazard for agents: the user's global rule is to
commit lockfiles "unless they're .gitignored", and this one is listed. Delete
the line. (CLAUDE.md already says "Has `Cargo.lock` changed? Commit it.")

### 6.5 "nightly toolchain" is held only by rustup's default

No `rust-toolchain.toml` exists. brokkr test needs nightly (`-Z unstable-options
--format json`), the rustdoc phase picks `--check` only on nightly, and Miri is
nightly-only, so a host whose default is stable degrades in three different
ways. A floating nightly also means new clippy lints arrive unannounced and,
under any-diagnostic-fails, break the check in code nobody touched. Pinning a
dated nightly trades that for manual bumps. Intent question.

### 6.6 Durable documentation restating what the code generates

- AGENTS.md: "`brokkr check` # gremlins + clippy + all tests. Replaces
  build/test/clippy". "All tests" is false today (doctests excluded, benches
  never run), and with the proposed config the list of phases grows. Reword to
  not enumerate (for example "the full validation pass; see `brokkr man
  check`").
- AGENTS.md: "30+ lints set to `deny`". True (35 clippy plus `missing_docs`),
  but a drifting count; "every lint in `[lints.clippy]` is denied" says the
  same without drifting.
- README "What's in the box" is a hand-maintained restatement of the public
  API. It is already incomplete (no `encode_tag`, `zigzag_decode_64`,
  `zigzag_decode_32`, `WireError`, `WireResult`, or the `WIRE_*` constants) and
  nothing would notice another omission. Either drop it in favour of rustdoc,
  or hold it with a script check that extracts `pub fn` and `pub struct` names
  from `src/lib.rs` and requires each in the README.
- README and AGENTS.md both state "each [field encoder] with a skip-zero
  default and an `_always` variant". True today for all twelve; checkable by
  the same kind of script, or by a test, but held by nothing.
- The `Cursor::read_varint` and `encode_varint` doc comments carry measured
  speedups (2.3x, 3.5x, 1.5x) against varint-simd 0.4.1. Nothing re-measures
  them, and no brokkr setting can: `brokkr bench --compare` has an environment
  gate but no threshold gate. AGENTS.md's own layout puts measured numbers in
  `reference/performance.md`; the comments could cite the benchmark target
  instead of numbers.
- The harness memory file for this project states "78 integration tests"; the
  check logs record 156 executions. The global rule is not to use that file at
  all; it is stale either way.

### 6.7 `.plans/` is in use although `plans/` is retired

`.plans/dynamic-beaming-giraffe.md` sits in an ignored directory. AGENTS.md
retires `plans/` in favour of `notes/`. Because it is ignored, gremlins and
textlint never see it and no review does either.

## 7. Bugs found along the way

### 7.1 `read_len_delimited` panics or misreads instead of returning `Err`

`let len = self.read_varint()? as usize;` then `if self.pos + len >
self.data.len()`.

- 64-bit, dev: a length varint near `u64::MAX` overflows the addition and
  panics ("attempt to add with overflow").
- 64-bit, release: the addition wraps to a small value, the bounds check
  passes, and the slice `self.data[self.pos..self.pos + len]` panics with an
  end before its start.
- 32-bit: `as usize` truncates. A length of 2^32 + 3 reads as 3; the check
  passes, the cursor returns a 3-byte slice, and decoding continues
  desynchronized. That is a silent wrong answer, not a panic, and it
  contradicts the README's statement that length-delimited reads are checked.

The crate disclaims adversarial input, but the function's own error message
("length-delimited field extends past end") is the check it fails to make.
`len > self.remaining()` (with the `u64` compared before narrowing) fixes all
three. Nothing in the current gate can see the 32-bit case; the Miri i686 entry
of 4.3 can, once a test feeds it such a length. `skip_field` inherits the same
path through `read_len_delimited`.

### 7.2 Redundant nested `cfg` in `count_packed_varints_sse2`

The function is already `#[cfg(target_arch = "x86_64")]`; the `use` inside it
repeats the attribute. Cosmetic.

## 8. Intent questions the code cannot answer

1. Does "nothing durable may cite `notes/`" cover another repository's notes
   (`notes/SIMD.md` in pbfhogg, cited from two doc comments with a pinned sha)?
2. Which characters beyond U+FFFD count as "strange": U+00D7, U+2212, U+2026,
   U+2264/U+2265, and the arrows brokkr spares by default?
3. Is `rust-version = "1.85"` a promise to crates.io consumers (then install
   1.85 and add the script check) or vestigial (then drop it)?
4. Should the toolchain be pinned to a dated nightly?
5. Is Miri's measured cost acceptable in the routine run, given that brokkr
   offers no gate-only switch for script checks?
6. Where should the cross-project AGENTS.md conventions live as config? The
   user-wide `~/.config/brokkr/brokkr.toml` (which does not exist on this host)
   applies them to every tree at once, but it is host-local in the same way the
   harness memory directory is: on a host without the file the rules silently
   stop applying. A shared file pulled in with `include = ["../shared/..."]`
   assumes a sibling checkout and makes every brokkr command fail where it is
   missing (loud, but total). A per-project copy, as pbfhogg does with its
   script, is the only form that travels with the repository.

## 9. What I could not verify

- Every cost for the proposed additions (release cold build, rustdoc, Miri,
  cross clippy): no cargo or brokkr build command was permitted.
- Whether brokkr excludes `.brokkr/` from the markdown-only classifier.
- Whether `default_profile` (as opposed to `--profile`) waives the markdown-only
  shortcut.
- Whether varint-simd compiles for `i686` and `s390x` under Miri.
- Whether clippy's `cast_possible_truncation` fires on `usize as u64` (affects
  three of the stale-allow candidates in 6.2).
- Whether a doctest carrier with zero doctests passes cleanly.
