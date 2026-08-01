# protohoggr

Zero-copy protobuf wire-format primitives for Rust. No external dependencies.
Extracted from [pbfhogg](https://github.com/folknor/pbfhogg) (OpenStreetMap PBF reader/writer).

## git commit rules

- Always run `brokkr fmt` before a commit.
- Never commit markdown changes alone. Bundle them with upcoming code commits.
- When committing other changes: always tag along markdown files if dirty.
- Write substantive engineering-focused commit messages.
- Has `Cargo.lock` changed? Commit it.
- Never `git push` unless the user explicitly asks. Stop after the commit.
- Remember to update CHANGELOG.md for relevant commits (but not general small performance improvements.)

## Project structure

Single-library crate. Implementation in `src/lib.rs`, integration tests in `tests/wire.rs`.

## Build & test

Use `brokkr` (not raw `cargo`).

```sh
brokkr check       # gremlins + clippy + all tests (78 integration tests). Replaces build/test/clippy
brokkr check --all # every diagnostic, no cap, no changed-files scope
brokkr test <NAME> # run one test by substring filter
brokkr fmt         # format
```

## Code conventions

- Rust 2024 edition, nightly toolchain
- No external dependencies — pure Rust, std only
- Very strict clippy: 30+ lints set to `deny` in `Cargo.toml` under `[lints.clippy]`
  - `unwrap_used` is denied — enforced via `Cargo.toml`
  - `cast_sign_loss`, `cast_possible_truncation`, `cast_possible_wrap` are denied — use `#[allow(...)]` locally with care
  - `cognitive_complexity` and `too_many_lines` are denied — keep functions small
- Test module uses `#[allow(clippy::unwrap_used)]` so `.unwrap()` is fine in tests
- Use `WireResult<T>` / `WireError` for fallible operations, not panics
- Encoding functions skip zero/empty/false values by default (protobuf convention); `_always` variants write unconditionally
- Packed encoders take a `&mut Vec<u8>` scratch buffer to avoid repeated allocation
- Heavy use of `#[inline]` on hot-path functions

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
