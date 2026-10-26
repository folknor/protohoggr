# protohoggr

Zero-copy protobuf wire-format primitives for Rust. No external dependencies.
Extracted from [pbfhogg](https://github.com/folknor/pbfhogg) (OpenStreetMap PBF reader/writer).

This crate is optimized for **speed on well-formed protobuf data**, not for adversarial input validation.

## Project structure

Single-library crate. Implementation in `src/lib.rs`, integration tests in `tests/wire.rs`.
Benchmarks live in `bench/`, an unpublished workspace member: criterion targets
plus `examples/ab.rs`, a same-binary A/B against a pinned baseline revision.
How to measure, and why it is done that way, is in `reference/performance.md`.

Benchmarks live in `bench/`, a separate unpublished workspace member
(`protohoggr-bench`) that owns criterion and varint-simd, so the library's
tests never compile them. `default-members` keeps the tested sweeps on the
library alone; `brokkr check` lints and documents the bench through its own
`[[lint_sweep]]` entries. Run it with `brokkr bench varint`. The varint-simd
batch comparisons need SSSE3 and are left out (with a stderr notice) on builds
without it.

## Build & test

Use `brokkr` (not raw `cargo`). `brokkr.toml` is the source of truth for what
each command runs.

```sh
brokkr check        # edit loop
brokkr check --gate # landing gate: everything the edit loop runs, plus the slow lanes
brokkr test <NAME>  # run one test by substring filter, under dev and release
brokkr fmt          # format
```

A green `brokkr check --gate` on the exact contents being committed is required
before every commit. Plain `brokkr check` skips the build on a markdown-only
tree, so a README edit's doctest is compiled only by the gate (or
`brokkr check --force-rust`). Miri needs the `miri` and `rust-src` rustup
components; the aarch64 lint sweep needs the `aarch64-unknown-linux-musl`
target.

## Code conventions

- Rust 2024 edition, nightly toolchain
- No external dependencies of any kind, dev included - pure Rust, std only. Enforced by the `no-external-dependencies` rule in `brokkr.toml`; anything a bench needs goes in `bench/Cargo.toml`
- Very strict clippy: 30+ lints set to `deny` in `Cargo.toml` under `[workspace.lints.clippy]`, inherited by both packages
  - `unwrap_used` is denied - enforced via `Cargo.toml`
  - `cast_sign_loss`, `cast_possible_truncation`, `cast_possible_wrap` are denied - use `#[expect(...)]` locally with care (`allow_attributes` is denied, and a stale expectation fails the build)
  - `cognitive_complexity` and `too_many_lines` are denied - keep functions small
  - `undocumented_unsafe_blocks` is denied - every `unsafe` block carries a `// SAFETY:` comment; the gate runs the test suite under Miri to check the unsafe paths for UB
- Test module uses `#[allow(clippy::unwrap_used)]` so `.unwrap()` is fine in tests
- Use `WireResult<T>` / `WireError` for fallible operations, not panics
- Encoding functions skip zero/empty/false values by default (protobuf convention); `_always` variants write unconditionally
- Packed encoders take a `&mut Vec<u8>` scratch buffer to avoid repeated allocation
- Heavy use of `#[inline]` on hot-path functions

## Rules

### General rules

- Don't use gremlins! Em-dash, en-dash, strange quotes, whatever - they're all verboten. `brokkr.toml` bans every non-ASCII character in scanned files.
- Don't remind the user of the rules. They wrote them, so they know them.
- The user can exempt you from any rule at any time.

### Bash rules

- Never read or write from `/tmp`. All data lives in the project.
- Never run raw `cargo`, `curl`, `pkill`. Use `brokkr`.

## Document folders

The standing layout, across every project. Three live folders plus one retired,
split by durability first, subject second.

| Folder | Contents | Rule |
|---|---|---|
| `reference/` | Durable in-repo reference for anyone working on or with the code - how the thing is built and why: `architecture.md`, `technical-implementation-spec.md`, `performance.md` (the durable record of measured numbers over time), invariants, protocol contracts | Citable from source as a source of truth. What it says must be true. |
| `docs/` | Durable in-repo documentation of how the thing is used - guides, CLI reference, the consumer-facing API surface. Sometimes exposed as a hand-edited VitePress gh-pages site | Same must-be-true rule. |
| `notes/` | Transient - work items (`todo.md`), future plans, hypotheticals, bug reports, research, analysis. Things that will die | No truth guarantee. Nothing durable cites it. |
| `plans/` | Retired | Plan documents are transient: they go in `notes/`. |

`reference/` and `docs/` are both durable and both binding. The difference is
subject, not audience: `reference/` covers how the thing is built and why - what
you need in order to change it safely - while `docs/` covers how it is used. A
developer or library consumer reads both. Where a project publishes a site,
`docs/` is what gets published; the folder means the same thing either way.
`notes/` is neither durable nor binding, which is the whole point of keeping it
separate: a document that may be wrong must not sit where a document that must
be right is expected.

The dependency direction is therefore one-way. `notes/` may cite `docs/` and
`reference/`; nothing durable may cite `notes/` - not a code comment, not
`docs/`, not `reference/`. A code comment must carry its full context, because
it outlives the note.

**Root-level convention files are exempt.** `AGENTS.md`, `CLAUDE.md`,
`README.md`, `LICENSE`, `CHANGELOG.md` and their kin are found by tooling and by
convention at the repository root, and stay there. These folders govern
documents we chose where to put, not files whose location is dictated.

In `notes/`, `docs/` and `reference/` alike, avoid citing source line numbers -
they drift fast.
