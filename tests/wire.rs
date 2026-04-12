#![allow(clippy::unwrap_used)]

use protohoggr::*;

// ---------------------------------------------------------------------------
// Decode: varint
// ---------------------------------------------------------------------------

#[test]
fn decode_varint_single_byte() {
    let mut c = Cursor::new(&[0x00]);
    assert_eq!(c.read_varint().unwrap(), 0);

    let mut c = Cursor::new(&[0x01]);
    assert_eq!(c.read_varint().unwrap(), 1);

    let mut c = Cursor::new(&[0x7F]);
    assert_eq!(c.read_varint().unwrap(), 127);
}

#[test]
fn decode_varint_multi_byte() {
    let mut c = Cursor::new(&[0xAC, 0x02]);
    assert_eq!(c.read_varint().unwrap(), 300);

    let mut c = Cursor::new(&[0x96, 0x01]);
    assert_eq!(c.read_varint().unwrap(), 150);
}

#[test]
fn decode_varint_truncated() {
    let mut c = Cursor::new(&[0x80]);
    assert!(c.read_varint().is_err());
}

#[test]
fn decode_varint_empty() {
    let mut c = Cursor::new(&[]);
    assert!(c.read_varint().is_err());
}

// ---------------------------------------------------------------------------
// Decode: zigzag
// ---------------------------------------------------------------------------

#[test]
fn zigzag_decode_roundtrip() {
    assert_eq!(zigzag_decode_64(0), 0);
    assert_eq!(zigzag_decode_64(1), -1);
    assert_eq!(zigzag_decode_64(2), 1);
    assert_eq!(zigzag_decode_64(3), -2);
    assert_eq!(zigzag_decode_64(4294967294), 2147483647);
    assert_eq!(zigzag_decode_64(4294967295), -2147483648);

    assert_eq!(zigzag_decode_32(0), 0);
    assert_eq!(zigzag_decode_32(1), -1);
    assert_eq!(zigzag_decode_32(2), 1);
    assert_eq!(zigzag_decode_32(3), -2);
}

// ---------------------------------------------------------------------------
// Decode: packed iterators
// ---------------------------------------------------------------------------

#[test]
fn packed_sint64_iter() {
    let data = [0x02, 0x01, 0x00];
    let vals: Vec<i64> = PackedSint64Iter::new(&data).collect();
    assert_eq!(vals, vec![1, -1, 0]);
}

#[test]
fn packed_sint32_iter() {
    // zigzag: 0→0, 1→-1, 2→1, 3→-2
    let data = [0x00, 0x02, 0x01, 0x03];
    let vals: Vec<i32> = PackedSint32Iter::new(&data).collect();
    assert_eq!(vals, vec![0, 1, -1, -2]);
}

#[test]
fn packed_int64_iter() {
    let data = [0x00, 0x01, 0x7F, 0xAC, 0x02];
    let vals: Vec<i64> = PackedInt64Iter::new(&data).collect();
    assert_eq!(vals, vec![0, 1, 127, 300]);
}

#[test]
fn packed_int32_iter() {
    let data = [0x00, 0x05, 0x7F, 0xAC, 0x02];
    let vals: Vec<i32> = PackedInt32Iter::new(&data).collect();
    assert_eq!(vals, vec![0, 5, 127, 300]);
}

#[test]
fn packed_uint32_iter() {
    let data = [0x00, 0x01, 0x7F, 0xAC, 0x02];
    let vals: Vec<u32> = PackedUint32Iter::new(&data).collect();
    assert_eq!(vals, vec![0, 1, 127, 300]);
}

#[test]
fn packed_bool_iter() {
    let data = [0x01, 0x00, 0x01];
    let vals: Vec<bool> = PackedBoolIter::new(&data).collect();
    assert_eq!(vals, vec![true, false, true]);
}

#[test]
fn packed_iter_empty() {
    let vals: Vec<u64> = PackedIter::new(&[]).collect();
    assert!(vals.is_empty());
    assert!(PackedIter::empty().is_empty());
}

#[test]
fn packed_iter_size_hint() {
    // 5 bytes of single-byte varints → (0, Some(5)) since min is remaining/10
    let iter = PackedIter::new(&[0x01, 0x02, 0x03, 0x04, 0x05]);
    let (lo, hi) = iter.size_hint();
    assert_eq!(lo, 0); // 5 / 10 = 0
    assert_eq!(hi, Some(5));

    // 10 bytes → min is 1
    let iter = PackedIter::new(&[0x01; 10]);
    let (lo, hi) = iter.size_hint();
    assert_eq!(lo, 1);
    assert_eq!(hi, Some(10));
}

// ---------------------------------------------------------------------------
// Decode: tag + len_delimited + skip
// ---------------------------------------------------------------------------

#[test]
fn read_tag_and_len_delimited() {
    let data = [0x0A, 0x03, 0x41, 0x42, 0x43];
    let mut c = Cursor::new(&data);
    let (field, wt) = c.read_tag().unwrap().unwrap();
    assert_eq!(field, 1);
    assert_eq!(wt, WIRE_LEN);
    let bytes = c.read_len_delimited().unwrap();
    assert_eq!(bytes, b"ABC");
    assert!(c.is_empty());
}

#[test]
fn read_tag_at_eof_returns_none() {
    let mut c = Cursor::new(&[]);
    assert!(c.read_tag().unwrap().is_none());
}

#[test]
fn skip_field_varint() {
    // field 1, varint, value 300 (2-byte varint)
    let data = [0x08, 0xAC, 0x02];
    let mut c = Cursor::new(&data);
    let (_, wt) = c.read_tag().unwrap().unwrap();
    c.skip_field(wt).unwrap();
    assert!(c.is_empty());
}

#[test]
fn skip_field_64bit() {
    // field 1, WIRE_64BIT (tag = (1 << 3) | 1 = 0x09), then 8 bytes
    let mut data = vec![0x09];
    data.extend_from_slice(&[0xAA; 8]);
    let mut c = Cursor::new(&data);
    let (field, wt) = c.read_tag().unwrap().unwrap();
    assert_eq!(field, 1);
    assert_eq!(wt, WIRE_64BIT);
    c.skip_field(wt).unwrap();
    assert!(c.is_empty());
}

#[test]
fn skip_field_32bit() {
    // field 1, WIRE_32BIT (tag = (1 << 3) | 5 = 0x0D), then 4 bytes
    let mut data = vec![0x0D];
    data.extend_from_slice(&[0xBB; 4]);
    let mut c = Cursor::new(&data);
    let (field, wt) = c.read_tag().unwrap().unwrap();
    assert_eq!(field, 1);
    assert_eq!(wt, WIRE_32BIT);
    c.skip_field(wt).unwrap();
    assert!(c.is_empty());
}

#[test]
fn skip_field_len_delimited() {
    // field 1, WIRE_LEN, length 3, then "ABC"
    let data = [0x0A, 0x03, 0x41, 0x42, 0x43];
    let mut c = Cursor::new(&data);
    let (field, wt) = c.read_tag().unwrap().unwrap();
    assert_eq!(field, 1);
    assert_eq!(wt, WIRE_LEN);
    c.skip_field(wt).unwrap();
    assert!(c.is_empty());
}

#[test]
fn skip_field_unknown_wire_type() {
    let mut c = Cursor::new(&[]);
    assert!(c.skip_field(3).is_err());
    assert!(c.skip_field(4).is_err());
    assert!(c.skip_field(6).is_err());
}

// ---------------------------------------------------------------------------
// Decode: read_raw_field
// ---------------------------------------------------------------------------

#[test]
fn read_raw_field_varint() {
    // Two-byte varint (300 = 0xAC 0x02), then a trailing byte to confirm position
    let data = [0xAC, 0x02, 0xFF];
    let mut c = Cursor::new(&data);
    let raw = c.read_raw_field(WIRE_VARINT).unwrap();
    assert_eq!(raw, &[0xAC, 0x02]);
    assert_eq!(c.remaining(), 1);
}

#[test]
fn read_raw_field_64bit() {
    let bytes = 0x0102_0304_0506_0708_u64.to_le_bytes();
    let mut c = Cursor::new(&bytes);
    let raw = c.read_raw_field(WIRE_64BIT).unwrap();
    assert_eq!(raw, &bytes);
    assert!(c.is_empty());
}

#[test]
fn read_raw_field_32bit() {
    let bytes = 0x0102_0304_u32.to_le_bytes();
    let mut c = Cursor::new(&bytes);
    let raw = c.read_raw_field(WIRE_32BIT).unwrap();
    assert_eq!(raw, &bytes);
    assert!(c.is_empty());
}

#[test]
fn read_raw_field_len_delimited() {
    // Length prefix (3) + 3 payload bytes
    let data = [0x03, 0xAA, 0xBB, 0xCC];
    let mut c = Cursor::new(&data);
    let raw = c.read_raw_field(WIRE_LEN).unwrap();
    // Raw includes the length prefix varint + the payload
    assert_eq!(raw, &[0x03, 0xAA, 0xBB, 0xCC]);
    assert!(c.is_empty());
}

#[test]
fn read_raw_field_unknown_wire_type() {
    let mut c = Cursor::new(&[]);
    assert!(c.read_raw_field(3).is_err());
}

#[test]
fn read_raw_field_roundtrip() {
    // Encode a full message with two fields, read them raw, reassemble verbatim
    let mut encoded = Vec::new();
    encode_varint_field(&mut encoded, 1, 300);
    encode_bytes_field(&mut encoded, 2, b"hello");

    let mut c = Cursor::new(&encoded);
    let mut reassembled = Vec::new();

    while let Some((field_num, wire_type)) = c.read_tag().unwrap() {
        let raw_value = c.read_raw_field(wire_type).unwrap();
        encode_tag(&mut reassembled, field_num, wire_type);
        reassembled.extend_from_slice(raw_value);
    }

    assert_eq!(reassembled, encoded);
}

// ---------------------------------------------------------------------------
// Cursor: remaining
// ---------------------------------------------------------------------------

#[test]
fn cursor_remaining() {
    let data = [0x01, 0x02, 0x03];
    let mut c = Cursor::new(&data);
    assert_eq!(c.remaining(), 3);
    c.read_varint().unwrap();
    assert_eq!(c.remaining(), 2);
    c.read_varint().unwrap();
    assert_eq!(c.remaining(), 1);
    c.read_varint().unwrap();
    assert_eq!(c.remaining(), 0);
    assert!(c.is_empty());
}

// ---------------------------------------------------------------------------
// Encode: varint
// ---------------------------------------------------------------------------

#[test]
fn encode_varint_single_byte() {
    let mut buf = Vec::new();
    encode_varint(&mut buf, 0);
    assert_eq!(buf, [0x00]);

    buf.clear();
    encode_varint(&mut buf, 1);
    assert_eq!(buf, [0x01]);

    buf.clear();
    encode_varint(&mut buf, 127);
    assert_eq!(buf, [0x7f]);
}

#[test]
fn encode_varint_multi_byte() {
    let mut buf = Vec::new();
    encode_varint(&mut buf, 128);
    assert_eq!(buf, [0x80, 0x01]);

    buf.clear();
    encode_varint(&mut buf, 300);
    assert_eq!(buf, [0xac, 0x02]);

    buf.clear();
    encode_varint(&mut buf, 16384);
    assert_eq!(buf, [0x80, 0x80, 0x01]);
}

#[test]
fn encode_varint_max() {
    let mut buf = Vec::new();
    encode_varint(&mut buf, u64::MAX);
    assert_eq!(buf.len(), 10);
    assert_eq!(
        buf,
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
    );
}

// ---------------------------------------------------------------------------
// Encode: zigzag
// ---------------------------------------------------------------------------

#[test]
fn zigzag_encode_64_known_values() {
    assert_eq!(zigzag_encode_64(0), 0);
    assert_eq!(zigzag_encode_64(-1), 1);
    assert_eq!(zigzag_encode_64(1), 2);
    assert_eq!(zigzag_encode_64(-2), 3);
    assert_eq!(zigzag_encode_64(2), 4);
    assert_eq!(zigzag_encode_64(i64::MIN), u64::MAX);
    assert_eq!(zigzag_encode_64(i64::MAX), u64::MAX - 1);
}

#[test]
fn zigzag_encode_32_known_values() {
    assert_eq!(zigzag_encode_32(0), 0);
    assert_eq!(zigzag_encode_32(-1), 1);
    assert_eq!(zigzag_encode_32(1), 2);
    assert_eq!(zigzag_encode_32(-2), 3);
}

#[test]
fn zigzag_encode_decode_roundtrip() {
    for v in [
        0i64,
        1,
        -1,
        2,
        -2,
        100,
        -100,
        1_000_000,
        -1_000_000,
        i64::MAX,
        i64::MIN,
    ] {
        let encoded = zigzag_encode_64(v);
        assert_eq!(zigzag_decode_64(encoded), v, "roundtrip failed for {v}");
    }
}

// ---------------------------------------------------------------------------
// Encode: field-level
// ---------------------------------------------------------------------------

#[test]
fn int64_field_skip_zero() {
    let mut buf = Vec::new();
    encode_int64_field(&mut buf, 1, 0);
    assert!(buf.is_empty(), "should skip zero value");
}

#[test]
fn int64_field_positive() {
    let mut buf = Vec::new();
    encode_int64_field(&mut buf, 1, 5001);
    assert_eq!(buf[0], 0x08);
    let rest = &buf[1..];
    let mut val: u64 = 0;
    for (i, &b) in rest.iter().enumerate() {
        val |= u64::from(b & 0x7f) << (7 * i);
        if b < 0x80 {
            assert_eq!(val, 5001);
            break;
        }
    }
}

#[test]
fn int32_field_negative_sign_extends() {
    let mut buf = Vec::new();
    encode_int32_field(&mut buf, 1, -1);
    assert_eq!(buf.len(), 11);
}

#[test]
fn uint32_field() {
    let mut buf = Vec::new();
    encode_uint32_field(&mut buf, 5, 42);
    assert_eq!(buf, [0x28, 0x2a]);
}

#[test]
fn bool_field_false_skipped() {
    let mut buf = Vec::new();
    encode_bool_field(&mut buf, 6, false);
    assert!(buf.is_empty());
}

#[test]
fn bool_field_true() {
    let mut buf = Vec::new();
    encode_bool_field(&mut buf, 6, true);
    assert_eq!(buf, [0x30, 0x01]);
}

#[test]
fn bytes_field_skip_empty() {
    let mut buf = Vec::new();
    encode_bytes_field(&mut buf, 1, &[]);
    assert!(buf.is_empty(), "should skip empty data");
}

#[test]
fn bytes_field_always_includes_empty() {
    let mut buf = Vec::new();
    encode_bytes_field_always(&mut buf, 1, &[]);
    assert_eq!(buf, [0x0a, 0x00]);
}

#[test]
fn bytes_field_with_data() {
    let mut buf = Vec::new();
    encode_bytes_field(&mut buf, 1, b"hello");
    assert_eq!(&buf[..2], &[0x0a, 0x05]);
    assert_eq!(&buf[2..], b"hello");
}

// ---------------------------------------------------------------------------
// Encode: field-level _always variants
// ---------------------------------------------------------------------------

#[test]
fn varint_field_always_writes_zero() {
    let mut buf = Vec::new();
    encode_varint_field_always(&mut buf, 1, 0);
    assert_eq!(buf, [0x08, 0x00]);
}

#[test]
fn int64_field_always_writes_zero() {
    let mut buf = Vec::new();
    encode_int64_field_always(&mut buf, 1, 0);
    assert_eq!(buf, [0x08, 0x00]);
}

#[test]
fn int32_field_always_writes_zero() {
    let mut buf = Vec::new();
    encode_int32_field_always(&mut buf, 1, 0);
    assert_eq!(buf, [0x08, 0x00]);
}

#[test]
fn uint32_field_always_writes_zero() {
    let mut buf = Vec::new();
    encode_uint32_field_always(&mut buf, 5, 0);
    assert_eq!(buf, [0x28, 0x00]);
}

#[test]
fn bool_field_always_writes_false() {
    let mut buf = Vec::new();
    encode_bool_field_always(&mut buf, 6, false);
    assert_eq!(buf, [0x30, 0x00]);
}

#[test]
fn bool_field_always_writes_true() {
    let mut buf = Vec::new();
    encode_bool_field_always(&mut buf, 6, true);
    assert_eq!(buf, [0x30, 0x01]);
}

#[test]
fn sint64_field_always_writes_zero() {
    let mut buf = Vec::new();
    encode_sint64_field_always(&mut buf, 1, 0);
    // zigzag(0) = 0, so tag + varint(0)
    assert_eq!(buf, [0x08, 0x00]);
}

#[test]
fn sint64_field_always_writes_negative() {
    let mut buf = Vec::new();
    encode_sint64_field_always(&mut buf, 1, -1);
    // zigzag(-1) = 1, so tag + varint(1)
    assert_eq!(buf, [0x08, 0x01]);
}

// ---------------------------------------------------------------------------
// Encode: packed repeated
// ---------------------------------------------------------------------------

#[test]
fn packed_uint32_values() {
    let mut buf = Vec::new();
    let mut scratch = Vec::new();
    encode_packed_uint32(&mut buf, &mut scratch, 2, &[1, 2, 3]);
    assert_eq!(buf, [0x12, 0x03, 0x01, 0x02, 0x03]);
}

#[test]
fn packed_uint32_empty() {
    let mut buf = Vec::new();
    let mut scratch = Vec::new();
    encode_packed_uint32(&mut buf, &mut scratch, 2, &[]);
    assert!(buf.is_empty(), "should skip empty packed field");
}

#[test]
fn packed_int32_negative() {
    let mut buf = Vec::new();
    let mut scratch = Vec::new();
    encode_packed_int32(&mut buf, &mut scratch, 8, &[-1]);
    assert_eq!(buf[0], 0x42);
    assert_eq!(buf[1], 0x0a);
    assert_eq!(buf.len(), 12);
}

#[test]
fn packed_sint64_encode_decode_roundtrip() {
    let values = [0i64, 1, -1, 2, -2, 100, -100, i64::MAX, i64::MIN];
    let mut buf = Vec::new();
    let mut scratch = Vec::new();
    encode_packed_sint64(&mut buf, &mut scratch, 1, &values);

    // Decode: skip tag + length prefix, then iterate packed body
    let mut c = Cursor::new(&buf);
    let (field, wt) = c.read_tag().unwrap().unwrap();
    assert_eq!(field, 1);
    assert_eq!(wt, WIRE_LEN);
    let body = c.read_len_delimited().unwrap();
    let decoded: Vec<i64> = PackedSint64Iter::new(body).collect();
    assert_eq!(decoded, values);
}

#[test]
fn packed_sint32_encode_decode_roundtrip() {
    let values = [0i32, 1, -1, 2, -2, 100, -100, i32::MAX, i32::MIN];
    let mut buf = Vec::new();
    let mut scratch = Vec::new();
    encode_packed_sint32(&mut buf, &mut scratch, 3, &values);

    let mut c = Cursor::new(&buf);
    let (field, wt) = c.read_tag().unwrap().unwrap();
    assert_eq!(field, 3);
    assert_eq!(wt, WIRE_LEN);
    let body = c.read_len_delimited().unwrap();
    let decoded: Vec<i32> = PackedSint32Iter::new(body).collect();
    assert_eq!(decoded, values);
}

#[test]
fn packed_uint32_encode_decode_roundtrip() {
    let values = [0u32, 1, 127, 128, 300, 100_000, u32::MAX];
    let mut buf = Vec::new();
    let mut scratch = Vec::new();
    encode_packed_uint32(&mut buf, &mut scratch, 2, &values);

    let mut c = Cursor::new(&buf);
    let (field, wt) = c.read_tag().unwrap().unwrap();
    assert_eq!(field, 2);
    assert_eq!(wt, WIRE_LEN);
    let body = c.read_len_delimited().unwrap();
    let decoded: Vec<u32> = PackedUint32Iter::new(body).collect();
    assert_eq!(decoded, values);
}

#[test]
fn packed_int32_encode_decode_roundtrip() {
    let values = [0i32, 1, -1, 127, -128, 300];
    let mut buf = Vec::new();
    let mut scratch = Vec::new();
    encode_packed_int32(&mut buf, &mut scratch, 4, &values);

    let mut c = Cursor::new(&buf);
    let (field, wt) = c.read_tag().unwrap().unwrap();
    assert_eq!(field, 4);
    assert_eq!(wt, WIRE_LEN);
    let body = c.read_len_delimited().unwrap();
    let decoded: Vec<i32> = PackedInt32Iter::new(body).collect();
    assert_eq!(decoded, values);
}

#[test]
fn packed_bool_encode_decode_roundtrip() {
    let values = [true, false, true, true, false];
    let mut buf = Vec::new();
    encode_packed_bool(&mut buf, 5, &values);

    let mut c = Cursor::new(&buf);
    let (field, wt) = c.read_tag().unwrap().unwrap();
    assert_eq!(field, 5);
    assert_eq!(wt, WIRE_LEN);
    let body = c.read_len_delimited().unwrap();
    let decoded: Vec<bool> = PackedBoolIter::new(body).collect();
    assert_eq!(decoded, values);
}

// ---------------------------------------------------------------------------
// Encode→Decode roundtrips: field-level
// ---------------------------------------------------------------------------

#[test]
fn varint_field_encode_decode_roundtrip() {
    for value in [0u64, 1, 127, 128, 300, u64::MAX] {
        let mut buf = Vec::new();
        encode_varint_field_always(&mut buf, 1, value);

        let mut c = Cursor::new(&buf);
        let (field, wt) = c.read_tag().unwrap().unwrap();
        assert_eq!(field, 1);
        assert_eq!(wt, WIRE_VARINT);
        let decoded = c.read_varint().unwrap();
        assert_eq!(decoded, value, "roundtrip failed for {value}");
        assert!(c.is_empty());
    }
}

#[test]
fn int64_field_encode_decode_roundtrip() {
    for value in [0i64, 1, -1, i64::MAX, i64::MIN] {
        let mut buf = Vec::new();
        encode_int64_field_always(&mut buf, 2, value);

        let mut c = Cursor::new(&buf);
        let (field, wt) = c.read_tag().unwrap().unwrap();
        assert_eq!(field, 2);
        assert_eq!(wt, WIRE_VARINT);
        let decoded = c.read_varint_i64().unwrap();
        assert_eq!(decoded, value, "roundtrip failed for {value}");
        assert!(c.is_empty());
    }
}

#[test]
fn sint64_field_encode_decode_roundtrip() {
    for value in [0i64, 1, -1, 100, -100, i64::MAX, i64::MIN] {
        let mut buf = Vec::new();
        encode_sint64_field_always(&mut buf, 3, value);

        let mut c = Cursor::new(&buf);
        let (field, wt) = c.read_tag().unwrap().unwrap();
        assert_eq!(field, 3);
        assert_eq!(wt, WIRE_VARINT);
        let decoded = c.read_sint64().unwrap();
        assert_eq!(decoded, value, "roundtrip failed for {value}");
        assert!(c.is_empty());
    }
}

#[test]
fn bytes_field_encode_decode_roundtrip() {
    for data in [&b""[..], b"hello", b"\x00\xff\x80"] {
        let mut buf = Vec::new();
        encode_bytes_field_always(&mut buf, 7, data);

        let mut c = Cursor::new(&buf);
        let (field, wt) = c.read_tag().unwrap().unwrap();
        assert_eq!(field, 7);
        assert_eq!(wt, WIRE_LEN);
        let decoded = c.read_len_delimited().unwrap();
        assert_eq!(decoded, data);
        assert!(c.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Multi-field message roundtrip
// ---------------------------------------------------------------------------

#[test]
fn multi_field_message_roundtrip() {
    // Encode a message with several fields of different types
    let mut buf = Vec::new();
    encode_uint32_field_always(&mut buf, 1, 42);
    encode_int64_field_always(&mut buf, 2, -999);
    encode_bool_field_always(&mut buf, 3, true);
    encode_bytes_field_always(&mut buf, 4, b"test");
    encode_sint64_field_always(&mut buf, 5, -12345);

    // Decode and verify each field
    let mut c = Cursor::new(&buf);

    let (field, wt) = c.read_tag().unwrap().unwrap();
    assert_eq!((field, wt), (1, WIRE_VARINT));
    assert_eq!(c.read_varint_u32().unwrap(), 42);

    let (field, wt) = c.read_tag().unwrap().unwrap();
    assert_eq!((field, wt), (2, WIRE_VARINT));
    assert_eq!(c.read_varint_i64().unwrap(), -999);

    let (field, wt) = c.read_tag().unwrap().unwrap();
    assert_eq!((field, wt), (3, WIRE_VARINT));
    assert_eq!(c.read_varint().unwrap(), 1);

    let (field, wt) = c.read_tag().unwrap().unwrap();
    assert_eq!((field, wt), (4, WIRE_LEN));
    assert_eq!(c.read_len_delimited().unwrap(), b"test");

    let (field, wt) = c.read_tag().unwrap().unwrap();
    assert_eq!((field, wt), (5, WIRE_VARINT));
    assert_eq!(c.read_sint64().unwrap(), -12345);

    assert!(c.read_tag().unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Cursor: position
// ---------------------------------------------------------------------------

#[test]
fn cursor_position() {
    let data = [0x08, 0xAC, 0x02]; // tag + 2-byte varint
    let mut c = Cursor::new(&data);
    assert_eq!(c.position(), 0);
    let _ = c.read_tag().unwrap();
    assert_eq!(c.position(), 1);
    let _ = c.read_varint().unwrap();
    assert_eq!(c.position(), 3);
}

// ---------------------------------------------------------------------------
// Cursor: fixed-width readers
// ---------------------------------------------------------------------------

#[test]
fn read_fixed32() {
    let data = 42u32.to_le_bytes();
    let mut c = Cursor::new(&data);
    assert_eq!(c.read_fixed32().unwrap(), 42);
    assert!(c.is_empty());
}

#[test]
fn read_fixed64() {
    let data = 123456789u64.to_le_bytes();
    let mut c = Cursor::new(&data);
    assert_eq!(c.read_fixed64().unwrap(), 123456789);
    assert!(c.is_empty());
}

#[test]
fn read_fixed32_truncated() {
    let mut c = Cursor::new(&[0x01, 0x02]);
    assert!(c.read_fixed32().is_err());
}

#[test]
fn read_fixed64_truncated() {
    let mut c = Cursor::new(&[0x01, 0x02, 0x03, 0x04]);
    assert!(c.read_fixed64().is_err());
}

#[test]
#[allow(clippy::approx_constant)]
fn read_float() {
    let val: f32 = 3.14;
    let data = val.to_le_bytes();
    let mut c = Cursor::new(&data);
    let decoded = c.read_float().unwrap();
    assert!((decoded - val).abs() < f32::EPSILON);
}

#[test]
#[allow(clippy::approx_constant)]
fn read_double() {
    let val: f64 = 2.718281828;
    let data = val.to_le_bytes();
    let mut c = Cursor::new(&data);
    let decoded = c.read_double().unwrap();
    assert!((decoded - val).abs() < f64::EPSILON);
}

// ---------------------------------------------------------------------------
// Encode: sint skip-zero variants
// ---------------------------------------------------------------------------

#[test]
fn sint64_field_skip_zero() {
    let mut buf = Vec::new();
    encode_sint64_field(&mut buf, 1, 0);
    assert!(buf.is_empty());
}

#[test]
fn sint64_field_nonzero() {
    let mut buf = Vec::new();
    encode_sint64_field(&mut buf, 1, -1);
    assert_eq!(buf, [0x08, 0x01]); // zigzag(-1) = 1
}

#[test]
fn sint32_field_skip_zero() {
    let mut buf = Vec::new();
    encode_sint32_field(&mut buf, 1, 0);
    assert!(buf.is_empty());
}

#[test]
fn sint32_field_nonzero() {
    let mut buf = Vec::new();
    encode_sint32_field(&mut buf, 1, -2);
    assert_eq!(buf, [0x08, 0x03]); // zigzag(-2) = 3
}

#[test]
fn sint32_field_always_writes_zero() {
    let mut buf = Vec::new();
    encode_sint32_field_always(&mut buf, 1, 0);
    assert_eq!(buf, [0x08, 0x00]);
}

#[test]
fn sint32_field_encode_decode_roundtrip() {
    for value in [0i32, 1, -1, 100, -100, i32::MAX, i32::MIN] {
        let mut buf = Vec::new();
        encode_sint32_field_always(&mut buf, 3, value);

        let mut c = Cursor::new(&buf);
        let (field, wt) = c.read_tag().unwrap().unwrap();
        assert_eq!(field, 3);
        assert_eq!(wt, WIRE_VARINT);
        let decoded = c.read_sint32().unwrap();
        assert_eq!(decoded, value, "roundtrip failed for {value}");
        assert!(c.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Encode: fixed-width field encoders
// ---------------------------------------------------------------------------

#[test]
fn fixed32_field_skip_zero() {
    let mut buf = Vec::new();
    encode_fixed32_field(&mut buf, 1, 0);
    assert!(buf.is_empty());
}

#[test]
fn fixed32_field_encode_decode_roundtrip() {
    for value in [0u32, 1, 42, u32::MAX] {
        let mut buf = Vec::new();
        encode_fixed32_field_always(&mut buf, 1, value);

        let mut c = Cursor::new(&buf);
        let (field, wt) = c.read_tag().unwrap().unwrap();
        assert_eq!(field, 1);
        assert_eq!(wt, WIRE_32BIT);
        let decoded = c.read_fixed32().unwrap();
        assert_eq!(decoded, value, "roundtrip failed for {value}");
        assert!(c.is_empty());
    }
}

#[test]
fn fixed64_field_skip_zero() {
    let mut buf = Vec::new();
    encode_fixed64_field(&mut buf, 1, 0);
    assert!(buf.is_empty());
}

#[test]
fn fixed64_field_encode_decode_roundtrip() {
    for value in [0u64, 1, 123456789, u64::MAX] {
        let mut buf = Vec::new();
        encode_fixed64_field_always(&mut buf, 2, value);

        let mut c = Cursor::new(&buf);
        let (field, wt) = c.read_tag().unwrap().unwrap();
        assert_eq!(field, 2);
        assert_eq!(wt, WIRE_64BIT);
        let decoded = c.read_fixed64().unwrap();
        assert_eq!(decoded, value, "roundtrip failed for {value}");
        assert!(c.is_empty());
    }
}

#[test]
fn float_field_skip_zero() {
    let mut buf = Vec::new();
    encode_float_field(&mut buf, 1, 0.0);
    assert!(buf.is_empty());
}

#[test]
fn float_field_encode_decode_roundtrip() {
    #[allow(clippy::approx_constant)]
    for value in [0.0f32, 1.0, -1.0, 3.14, f32::MAX, f32::MIN] {
        let mut buf = Vec::new();
        encode_float_field_always(&mut buf, 4, value);

        let mut c = Cursor::new(&buf);
        let (field, wt) = c.read_tag().unwrap().unwrap();
        assert_eq!(field, 4);
        assert_eq!(wt, WIRE_32BIT);
        let decoded = c.read_float().unwrap();
        assert_eq!(decoded.to_bits(), value.to_bits(), "roundtrip failed for {value}");
        assert!(c.is_empty());
    }
}

#[test]
fn double_field_skip_zero() {
    let mut buf = Vec::new();
    encode_double_field(&mut buf, 1, 0.0);
    assert!(buf.is_empty());
}

#[test]
fn double_field_encode_decode_roundtrip() {
    #[allow(clippy::approx_constant)]
    for value in [0.0f64, 1.0, -1.0, 2.718281828, f64::MAX, f64::MIN] {
        let mut buf = Vec::new();
        encode_double_field_always(&mut buf, 5, value);

        let mut c = Cursor::new(&buf);
        let (field, wt) = c.read_tag().unwrap().unwrap();
        assert_eq!(field, 5);
        assert_eq!(wt, WIRE_64BIT);
        let decoded = c.read_double().unwrap();
        assert_eq!(decoded.to_bits(), value.to_bits(), "roundtrip failed for {value}");
        assert!(c.is_empty());
    }
}
