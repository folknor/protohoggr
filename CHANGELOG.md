# Changelog

## Unreleased

### Fixed
- `zigzag_encode_32` sign-extended results with bit 31 set (inputs `>= 2^30` or `<= -2^30 - 1`, e.g. `i32::MIN`) to `u64`, so `encode_sint32_field`, `encode_sint32_field_always` and `encode_packed_sint32` wrote those values as non-canonical 10-byte varints instead of 5 bytes. Both protohoggr `sint32` decoding paths truncate to 32 bits before zigzag decoding, so the values read back correctly, but data written by earlier versions can contain this form and readers should keep accepting it
- `Cursor::read_len_delimited` (and through it `skip_field(WIRE_LEN)` and `read_raw_field(WIRE_LEN)`) panicked on a length prefix near `u64::MAX` (`pos + len` overflowed), and on 32-bit targets truncated lengths `>= 2^32` and returned a short slice, leaving decoding desynchronized. Any length larger than the remaining input now returns `Err`, with the prefix consumed and the payload not
- The packed iterators (`PackedIter` and all six typed wrappers) resumed after a 10-byte varint overflowing `u64`: the first `next()` returned `None`, but a later call decoded from the byte after the bad varint and could return `Some`. They now stay finished and implement `FusedIterator`, and `is_empty()` / `remaining_bytes()` report the same exhausted state after an overflow as after a truncated tail

### Breaking
- A malformed varint (truncated, or a 10th byte overflowing `u64`) now leaves the `Cursor` at the end of its data on every read built on `read_varint` (`read_tag`, `read_len_delimited`, `read_varint_u32`, `read_sint64` and the rest). Truncation already did this; an overflow used to leave the cursor just past the ten bad bytes, where further reads would resume. A well-formed varint rejected for its value (a tag above `u32::MAX` or with field number 0, a length past the end) is still consumed and nothing more. Record `position()` before the read to locate a failed varint
- `zigzag_encode_32` now returns `u32` and `zigzag_decode_32` now takes `u32`, making the pair a pure 32-bit bijection. Widen encoder output with `u64::from`; narrow a raw varint with `as u32` before decoding. `Cursor::read_sint32` and `PackedSint32Iter` do this truncation themselves, per protobuf's rule that a `sint32` varint is truncated to 32 bits before zigzag decoding
- Minimum supported Rust version raised from 1.85 to 1.87, the release that made `core::arch` intrinsics safe to call where their target feature is enabled

## 0.4.0

### Added
- `count_packed_varints(data)` - count varint terminals in a packed field; SSE2 SIMD on x86-64, scalar fallback elsewhere
- `decode_packed_sint64_cumulative(data, base, out)` - batch decode an entire packed sint64 field with cumulative sum, replacing per-element `PackedSint64Iter` + manual accumulation; append semantics, wrapping i64 addition, mirrors packed iterator error-swallowing behavior
- `encode_varint_to_slice(buf, value)` - `unsafe` slice-based varint encode (contract: `buf.len() >= 10`), with branchless 1-byte and 2-byte fast paths for values < 16384 (~95% of zigzag-encoded OSM way-ref deltas)
- `Cursor::read_varint_unchecked()` - `unsafe` infallible varint read that skips all bounds checks; safety contract requires a complete well-formed varint at the current position

## 0.3.0

### Added
- `Cursor::read_raw_field(wire_type)` - returns raw value bytes without decoding, for verbatim field copying
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
- `Cursor` - zero-copy reader over `&[u8]`: varints (LEB128), zigzag sint64/sint32, tags, length-delimited fields, fixed32/fixed64, float/double, skip, position tracking
- `PackedIter` - base packed varint iterator yielding raw `u64`
- Typed packed iterators: `PackedSint64Iter`, `PackedSint32Iter`, `PackedInt64Iter`, `PackedInt32Iter`, `PackedUint32Iter`, `PackedBoolIter`
- All packed iterators expose `new()`, `empty()`, `is_empty()`, `remaining_bytes()`

### Encoding
- `encode_varint` (LEB128), `zigzag_encode_64`, `zigzag_encode_32`
- Field encoders (skip-zero by default, `_always` variants write unconditionally):
  varint, int64, int32, uint32, bool, bytes, sint64, sint32, fixed32, fixed64, float, double
- Packed repeated encoders: uint32, int32, sint64, sint32, bool

### Other
- Zero external dependencies - pure Rust, std only
- Dual-licensed MIT OR Apache-2.0
- Benchmarked scalar vs varint-simd SSSE3/SSE2 - scalar wins 2-6× on decode, 1.5-3.5× on encode
