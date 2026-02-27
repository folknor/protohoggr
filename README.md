# protohoggr

Zero-copy protobuf wire-format primitives for Rust. No external dependencies.

Extracted from [pbfhogg](https://github.com/folknor/pbfhogg), an OpenStreetMap PBF reader/writer.

## What's in the box

- **Cursor** — zero-copy reader over a byte slice: varints (LEB128), zigzag-decoded sint32/sint64, tags, length-delimited fields, field skipping
- **Packed iterators** — `PackedIter`, `PackedSint64Iter`, `PackedSint32Iter`, `PackedInt64Iter`, `PackedInt32Iter`, `PackedUint32Iter`, `PackedBoolIter`
- **Varint/zigzag encoding** — `encode_varint`, `zigzag_encode_64`, `zigzag_encode_32`
- **Field encoders** — `encode_varint_field`, `encode_int64_field`, `encode_int32_field`, `encode_uint32_field`, `encode_bool_field`, `encode_bytes_field`, `encode_bytes_field_always`, `encode_sint64_field_always`
- **Packed repeated field encoders** — `encode_packed_uint32`, `encode_packed_int32`, `encode_packed_sint64`, `encode_packed_sint32`, `encode_packed_bool`

All encoding functions skip zero/empty/false values by default (matching protobuf conventions), with `_always` variants for fields that must always be present.

## Usage

```rust
use protohoggr::{Cursor, encode_varint, encode_bytes_field};

// Decode
let data = [0x08, 0xac, 0x02]; // field 1, varint 300
let mut cursor = Cursor::new(&data);
let (field, wire_type) = cursor.read_tag().unwrap().unwrap();
let value = cursor.read_varint().unwrap();
assert_eq!((field, value), (1, 300));

// Encode
let mut buf = Vec::new();
encode_bytes_field(&mut buf, 1, b"hello");
```

## License

Apache-2.0
