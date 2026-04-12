# Changelog

## 0.3.0

### Added
- `Cursor::read_raw_field(wire_type)` — returns raw value bytes without decoding, for verbatim field copying
- `#[must_use]` on all public constructors, accessors, and pure functions
- `missing_docs` (rust), `must_use_candidate`, `doc_markdown`, `inline_always`, `missing_safety_doc` (clippy) lints denied
- Doc comments on all public API items
- Documented `-0.0` behavior in float/double skip-zero encoders

### Breaking
- `read_varint` now rejects 10-byte varints whose final byte exceeds `0x01` (previously silently overflowed `u64`)
- `read_varint_u32` now returns `Err` for values exceeding `u32::MAX` (previously silently truncated); `read_tag` inherits this
- `read_tag` now rejects field number 0 (invalid per protobuf spec, previously returned `(0, wire_type)`)
- `encode_tag` now panics if `field` is 0 or exceeds `0x1FFF_FFFF`, or if `wire_type` exceeds 7

### Fixed
- SIMD benchmark tail-byte bias: batch loops now hand off remaining bytes to a scalar tail, so all strategies decode the same values

## 0.2.1

- Bump criterion dev-dependency from 0.5 to 0.8.2
- Switch benchmarks from deprecated `criterion::black_box` to `std::hint::black_box`

## 0.2.0

First standalone release, extracted from [pbfhogg](https://github.com/folknor/pbfhogg).

### Decoding
- `Cursor` — zero-copy reader over `&[u8]`: varints (LEB128), zigzag sint64/sint32, tags, length-delimited fields, fixed32/fixed64, float/double, skip, position tracking
- `PackedIter` — base packed varint iterator yielding raw `u64`
- Typed packed iterators: `PackedSint64Iter`, `PackedSint32Iter`, `PackedInt64Iter`, `PackedInt32Iter`, `PackedUint32Iter`, `PackedBoolIter`
- All packed iterators expose `new()`, `empty()`, `is_empty()`, `remaining_bytes()`

### Encoding
- `encode_varint` (LEB128), `zigzag_encode_64`, `zigzag_encode_32`
- Field encoders (skip-zero by default, `_always` variants write unconditionally):
  varint, int64, int32, uint32, bool, bytes, sint64, sint32, fixed32, fixed64, float, double
- Packed repeated encoders: uint32, int32, sint64, sint32, bool

### Other
- Zero external dependencies — pure Rust, std only
- Dual-licensed MIT OR Apache-2.0
- Benchmarked scalar vs varint-simd SSSE3/SSE2 — scalar wins 2-6× on decode, 1.5-3.5× on encode
