# TODO

## Inconsistencies

- Packed iterator helper methods (`empty()`, `is_empty()`, `remaining_bytes()`) are
  present on some typed wrappers but not others. Either all should have them or none.
- `encode_sint64_field_always` exists but there is no `encode_sint64_field` (skip-zero).
- No `encode_sint32_field` or `encode_sint32_field_always`.

## Missing primitives

- Fixed-width decoders: `read_fixed32`, `read_fixed64`, `read_float`, `read_double`.
- Fixed-width encoders: `encode_fixed32_field`, `encode_fixed64_field`,
  `encode_float_field`, `encode_double_field` (and `_always` variants).
- `Cursor::position()` getter for offset tracking.

## Performance

- `encode_packed_bool` uses scratch buffer + `encode_varint` per bool, but bools are
  always exactly 1 byte. Could skip scratch entirely — length is `values.len()`, each
  value is `u8::from(v)`.
