# protohoggr

Zero-copy protobuf wire-format primitives for Rust. No external dependencies.
Extracted from [pbfhogg](https://github.com/folknor/pbfhogg) (OpenStreetMap PBF reader/writer).

## Project structure

Single-library crate. All code lives in `src/lib.rs` (~970 lines including tests).

## Build & test

```sh
cargo build        # build
cargo test         # run all tests (28 unit tests)
cargo clippy       # lint — must pass clean
```

## Code conventions

- Rust 2024 edition, nightly toolchain
- No external dependencies — pure Rust, std only
- Very strict clippy: 30+ lints set to `deny` in `Cargo.toml` under `[lints.clippy]`
  - `unwrap_used` is denied in non-test code (also enforced via `#![deny(clippy::unwrap_used)]`)
  - `cast_sign_loss`, `cast_possible_truncation`, `cast_possible_wrap` are denied — use `#[allow(...)]` locally with care
  - `cognitive_complexity` and `too_many_lines` are denied — keep functions small
- Test module uses `#[allow(clippy::unwrap_used)]` so `.unwrap()` is fine in tests
- Use `WireResult<T>` / `WireError` for fallible operations, not panics
- Encoding functions skip zero/empty/false values by default (protobuf convention); `_always` variants write unconditionally
- Packed encoders take a `&mut Vec<u8>` scratch buffer to avoid repeated allocation
- Heavy use of `#[inline]` on hot-path functions
