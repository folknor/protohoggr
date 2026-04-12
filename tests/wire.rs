#![allow(clippy::unwrap_used, missing_docs)]

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

#[test]
fn decode_varint_10byte_max_valid() {
    // u64::MAX = 0xFFFFFFFFFFFFFFFF encodes as 9 bytes of 0xFF + final byte 0x01
    let data = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
    let mut c = Cursor::new(&data);
    assert_eq!(c.read_varint().unwrap(), u64::MAX);
}

#[test]
fn decode_varint_10byte_overflow() {
    // Same as above but final byte is 0x02 — overflows u64
    let data = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02];
    let mut c = Cursor::new(&data);
    assert!(c.read_varint().is_err());
}

#[test]
fn decode_varint_10byte_overflow_high() {
    // Final byte 0x7F — way beyond u64
    let data = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F];
    let mut c = Cursor::new(&data);
    assert!(c.read_varint().is_err());
}

#[test]
fn decode_varint_11byte_rejected() {
    // 11 continuation bytes — too long regardless of final byte
    let data = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00];
    let mut c = Cursor::new(&data);
    assert!(c.read_varint().is_err());
}

#[test]
fn decode_varint_u32_valid() {
    let mut buf = Vec::new();
    encode_varint(&mut buf, u64::from(u32::MAX));
    let mut c = Cursor::new(&buf);
    assert_eq!(c.read_varint_u32().unwrap(), u32::MAX);
}

#[test]
fn decode_varint_u32_overflow() {
    let mut buf = Vec::new();
    encode_varint(&mut buf, u64::from(u32::MAX) + 1);
    let mut c = Cursor::new(&buf);
    assert!(c.read_varint_u32().is_err());
}

#[test]
fn decode_varint_i64_wrap() {
    // u64::MAX reinterpreted as i64 is -1
    let data = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
    let mut c = Cursor::new(&data);
    assert_eq!(c.read_varint_i64().unwrap(), -1);
}

#[test]
fn decode_read_tag_oversized_varint() {
    // A tag varint that decodes to a value > u32::MAX should error
    let mut buf = Vec::new();
    encode_varint(&mut buf, u64::from(u32::MAX) + 1);
    let mut c = Cursor::new(&buf);
    assert!(c.read_tag().is_err());
}

#[test]
fn decode_read_tag_field_zero() {
    // Tag varint where field_number = 0 is invalid per protobuf spec.
    // Wire type bits 0-2 can be anything; field bits 3+ are all zero.
    for wire_type in 0..=7u8 {
        let data = [wire_type];
        let mut c = Cursor::new(&data);
        assert!(c.read_tag().is_err(), "tag with field 0, wire_type {wire_type} should error");
    }
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
// Decode: sint32 standalone
// ---------------------------------------------------------------------------

#[test]
fn decode_sint32_standalone() {
    // zigzag: 0→0, 1→-1, 2→1, 4294967294→i32::MAX, 4294967295→i32::MIN
    for (raw, expected) in [
        (0u64, 0i32),
        (1, -1),
        (2, 1),
        (3, -2),
        (4294967294, i32::MAX),
        (4294967295, i32::MIN),
    ] {
        let mut buf = Vec::new();
        encode_varint(&mut buf, raw);
        let mut c = Cursor::new(&buf);
        assert_eq!(c.read_sint32().unwrap(), expected, "sint32 failed for raw={raw}");
    }
}

// ---------------------------------------------------------------------------
// Decode: skip_varint edge cases
// ---------------------------------------------------------------------------

#[test]
fn skip_varint_overlength() {
    // 11 continuation bytes + terminator — not a valid varint (>10 bytes).
    // skip_varint has no length check (by design it just scans for MSB=0),
    // so this documents that it skips overlength sequences without error.
    let mut data = vec![0x80; 11];
    data.push(0x00); // terminator
    let mut c = Cursor::new(&data);
    // skip_varint accepts this — it's a raw byte scanner, not a value decoder
    c.skip_varint().unwrap();
    assert!(c.is_empty());
}

// ---------------------------------------------------------------------------
// Cursor: clone
// ---------------------------------------------------------------------------

#[test]
fn cursor_clone_independent() {
    let data = [0x01, 0x02, 0x03];
    let mut c1 = Cursor::new(&data);
    c1.read_varint().unwrap(); // advance to pos 1
    let mut c2 = c1.clone();
    // Both should be at the same position
    assert_eq!(c1.position(), c2.position());
    // Advancing one shouldn't affect the other
    c2.read_varint().unwrap();
    assert_eq!(c1.position(), 1);
    assert_eq!(c2.position(), 2);
}

// ---------------------------------------------------------------------------
// WireError: Display and Error
// ---------------------------------------------------------------------------

#[test]
fn wire_error_display() {
    let err = Cursor::new(&[]).read_varint().unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("wire format error:"), "got: {msg}");
}

#[test]
fn wire_error_is_error() {
    let err = Cursor::new(&[]).read_varint().unwrap_err();
    // Verify it implements std::error::Error (source() returns None for simple errors)
    let _: &dyn std::error::Error = &err;
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

#[test]
fn packed_typed_iter_size_hint() {
    let data = [0x01, 0x02, 0x03, 0x04, 0x05];
    // All typed wrappers delegate to PackedIter::size_hint
    let (lo, hi) = PackedSint64Iter::new(&data).size_hint();
    assert_eq!((lo, hi), (0, Some(5)));
    let (lo, hi) = PackedSint32Iter::new(&data).size_hint();
    assert_eq!((lo, hi), (0, Some(5)));
    let (lo, hi) = PackedInt64Iter::new(&data).size_hint();
    assert_eq!((lo, hi), (0, Some(5)));
    let (lo, hi) = PackedInt32Iter::new(&data).size_hint();
    assert_eq!((lo, hi), (0, Some(5)));
    let (lo, hi) = PackedUint32Iter::new(&data).size_hint();
    assert_eq!((lo, hi), (0, Some(5)));
    let (lo, hi) = PackedBoolIter::new(&data).size_hint();
    assert_eq!((lo, hi), (0, Some(5)));
}

#[test]
fn packed_typed_iter_remaining_bytes() {
    let data = [0x01, 0x02, 0x03];
    assert_eq!(PackedSint64Iter::new(&data).remaining_bytes(), 3);
    assert_eq!(PackedSint32Iter::new(&data).remaining_bytes(), 3);
    assert_eq!(PackedInt64Iter::new(&data).remaining_bytes(), 3);
    assert_eq!(PackedInt32Iter::new(&data).remaining_bytes(), 3);
    assert_eq!(PackedUint32Iter::new(&data).remaining_bytes(), 3);
    assert_eq!(PackedBoolIter::new(&data).remaining_bytes(), 3);
    // empty() should have 0 remaining
    assert_eq!(PackedSint64Iter::empty().remaining_bytes(), 0);
    assert_eq!(PackedSint32Iter::empty().remaining_bytes(), 0);
    assert_eq!(PackedInt64Iter::empty().remaining_bytes(), 0);
    assert_eq!(PackedInt32Iter::empty().remaining_bytes(), 0);
    assert_eq!(PackedUint32Iter::empty().remaining_bytes(), 0);
    assert_eq!(PackedBoolIter::empty().remaining_bytes(), 0);
}

#[test]
fn packed_typed_iter_empty() {
    assert!(PackedSint64Iter::empty().is_empty());
    assert!(PackedSint32Iter::empty().is_empty());
    assert!(PackedInt64Iter::empty().is_empty());
    assert!(PackedInt32Iter::empty().is_empty());
    assert!(PackedUint32Iter::empty().is_empty());
    assert!(PackedBoolIter::empty().is_empty());
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
fn read_raw_field_truncated_varint() {
    // Continuation byte with no terminator
    let mut c = Cursor::new(&[0x80]);
    assert!(c.read_raw_field(WIRE_VARINT).is_err());
}

#[test]
fn read_raw_field_empty_varint() {
    let mut c = Cursor::new(&[]);
    assert!(c.read_raw_field(WIRE_VARINT).is_err());
}

#[test]
fn read_raw_field_truncated_64bit() {
    let mut c = Cursor::new(&[0x01, 0x02, 0x03]);
    assert!(c.read_raw_field(WIRE_64BIT).is_err());
}

#[test]
fn read_raw_field_truncated_32bit() {
    let mut c = Cursor::new(&[0x01, 0x02]);
    assert!(c.read_raw_field(WIRE_32BIT).is_err());
}

#[test]
fn read_raw_field_truncated_len_payload() {
    // Length says 5 bytes but only 2 follow
    let data = [0x05, 0xAA, 0xBB];
    let mut c = Cursor::new(&data);
    assert!(c.read_raw_field(WIRE_LEN).is_err());
}

#[test]
fn read_raw_field_truncated_len_prefix() {
    // Continuation byte in length varint with no terminator
    let mut c = Cursor::new(&[0x80]);
    assert!(c.read_raw_field(WIRE_LEN).is_err());
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
// Encode: tag
// ---------------------------------------------------------------------------

#[test]
fn encode_tag_standalone() {
    let mut buf = Vec::new();
    // field 1, WIRE_VARINT → (1 << 3) | 0 = 0x08
    encode_tag(&mut buf, 1, WIRE_VARINT);
    assert_eq!(buf, [0x08]);

    buf.clear();
    // field 1, WIRE_LEN �� (1 << 3) | 2 = 0x0A
    encode_tag(&mut buf, 1, WIRE_LEN);
    assert_eq!(buf, [0x0A]);

    buf.clear();
    // field 15, WIRE_VARINT → (15 << 3) | 0 = 120 = 0x78
    encode_tag(&mut buf, 15, WIRE_VARINT);
    assert_eq!(buf, [0x78]);

    buf.clear();
    // field 16, WIRE_VARINT → (16 << 3) | 0 = 128 → 2-byte varint
    encode_tag(&mut buf, 16, WIRE_VARINT);
    assert_eq!(buf, [0x80, 0x01]);
}

#[test]
fn encode_tag_max_field_number() {
    // Max valid field number: 2^29 - 1 = 536870911
    let mut buf = Vec::new();
    encode_tag(&mut buf, 0x1FFF_FFFF, WIRE_VARINT);
    // Decode it back
    let mut c = Cursor::new(&buf);
    let (field, wt) = c.read_tag().unwrap().unwrap();
    assert_eq!(field, 0x1FFF_FFFF);
    assert_eq!(wt, WIRE_VARINT);
}

#[test]
#[should_panic(expected = "field number out of range")]
fn encode_tag_field_zero_panics() {
    let mut buf = Vec::new();
    encode_tag(&mut buf, 0, WIRE_VARINT);
}

#[test]
#[should_panic(expected = "field number out of range")]
fn encode_tag_field_overflow_panics() {
    let mut buf = Vec::new();
    encode_tag(&mut buf, 0x2000_0000, WIRE_VARINT);
}

#[test]
#[should_panic(expected = "wire type out of range")]
fn encode_tag_wire_type_overflow_panics() {
    let mut buf = Vec::new();
    encode_tag(&mut buf, 1, 8);
}

// ---------------------------------------------------------------------------
// Encode: field-level
// ---------------------------------------------------------------------------

#[test]
fn varint_field_skip_zero() {
    let mut buf = Vec::new();
    encode_varint_field(&mut buf, 1, 0);
    assert!(buf.is_empty());
}

#[test]
fn varint_field_nonzero() {
    let mut buf = Vec::new();
    encode_varint_field(&mut buf, 1, 42);
    assert_eq!(buf, [0x08, 0x2A]);
}

#[test]
fn int32_field_positive_roundtrip() {
    let mut buf = Vec::new();
    encode_int32_field(&mut buf, 1, 42);
    let mut c = Cursor::new(&buf);
    let (field, wt) = c.read_tag().unwrap().unwrap();
    assert_eq!((field, wt), (1, WIRE_VARINT));
    // int32 on the wire is just a varint
    let decoded = c.read_varint().unwrap();
    assert_eq!(decoded, 42);
}

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

// ---------------------------------------------------------------------------
// Float/double special values: NaN, -0.0, infinity
// ---------------------------------------------------------------------------

#[test]
fn float_nan_roundtrip() {
    let mut buf = Vec::new();
    encode_float_field_always(&mut buf, 1, f32::NAN);
    let mut c = Cursor::new(&buf);
    let (_, wt) = c.read_tag().unwrap().unwrap();
    assert_eq!(wt, WIRE_32BIT);
    let decoded = c.read_float().unwrap();
    assert!(decoded.is_nan());
}

#[test]
fn float_infinity_roundtrip() {
    for value in [f32::INFINITY, f32::NEG_INFINITY] {
        let mut buf = Vec::new();
        encode_float_field_always(&mut buf, 1, value);
        let mut c = Cursor::new(&buf);
        let _ = c.read_tag().unwrap().unwrap();
        let decoded = c.read_float().unwrap();
        assert_eq!(decoded, value);
    }
}

#[test]
fn float_negative_zero_not_skipped() {
    // -0.0 has non-zero bits (sign bit set), so skip-zero encoders should encode it
    let mut buf = Vec::new();
    encode_float_field(&mut buf, 1, -0.0_f32);
    assert!(!buf.is_empty(), "-0.0 should not be skipped");
    // Verify it roundtrips correctly
    let mut c = Cursor::new(&buf);
    let _ = c.read_tag().unwrap().unwrap();
    let decoded = c.read_float().unwrap();
    assert!(decoded.is_sign_negative());
    assert_eq!(decoded, 0.0);
}

#[test]
fn double_nan_roundtrip() {
    let mut buf = Vec::new();
    encode_double_field_always(&mut buf, 1, f64::NAN);
    let mut c = Cursor::new(&buf);
    let _ = c.read_tag().unwrap().unwrap();
    let decoded = c.read_double().unwrap();
    assert!(decoded.is_nan());
}

#[test]
fn double_infinity_roundtrip() {
    for value in [f64::INFINITY, f64::NEG_INFINITY] {
        let mut buf = Vec::new();
        encode_double_field_always(&mut buf, 1, value);
        let mut c = Cursor::new(&buf);
        let _ = c.read_tag().unwrap().unwrap();
        let decoded = c.read_double().unwrap();
        assert_eq!(decoded, value);
    }
}

#[test]
fn double_negative_zero_not_skipped() {
    let mut buf = Vec::new();
    encode_double_field(&mut buf, 1, -0.0_f64);
    assert!(!buf.is_empty(), "-0.0 should not be skipped");
    let mut c = Cursor::new(&buf);
    let _ = c.read_tag().unwrap().unwrap();
    let decoded = c.read_double().unwrap();
    assert!(decoded.is_sign_negative());
    assert_eq!(decoded, 0.0);
}

// ---------------------------------------------------------------------------
// Encode: packed_bool empty
// ---------------------------------------------------------------------------

#[test]
fn packed_bool_empty() {
    let mut buf = Vec::new();
    encode_packed_bool(&mut buf, 1, &[]);
    assert!(buf.is_empty());
}

// ---------------------------------------------------------------------------
// count_packed_varints
// ---------------------------------------------------------------------------

#[test]
fn count_varints_empty() {
    assert_eq!(count_packed_varints(&[]), 0);
}

#[test]
fn count_varints_all_single_byte() {
    assert_eq!(count_packed_varints(&[0x01, 0x7F, 0x00]), 3);
}

#[test]
fn count_varints_mixed() {
    // 300 = [0xAC, 0x02] (2 bytes), 1 = [0x01] (1 byte), 150 = [0x96, 0x01] (2 bytes)
    assert_eq!(count_packed_varints(&[0xAC, 0x02, 0x01, 0x96, 0x01]), 3);
}

#[test]
fn count_varints_single() {
    assert_eq!(count_packed_varints(&[0x05]), 1);
    assert_eq!(count_packed_varints(&[0xAC, 0x02]), 1);
}

#[test]
fn count_varints_truncated_tail() {
    // Continuation byte with no terminal — not counted.
    assert_eq!(count_packed_varints(&[0x80]), 0);
    // One complete varint [0x01] followed by a truncated one [0x80].
    assert_eq!(count_packed_varints(&[0x01, 0x80]), 1);
}

#[test]
fn count_varints_17_bytes() {
    // Exercises SIMD 16-byte chunk + 1-byte scalar tail on x86-64.
    // 17 single-byte varints.
    let data: Vec<u8> = (0..17).collect();
    assert_eq!(count_packed_varints(&data), 17);
}

#[test]
fn count_varints_32_bytes() {
    // Two full SIMD iterations on x86-64.
    let data: Vec<u8> = (0..32).map(|i| i & 0x7F).collect();
    assert_eq!(count_packed_varints(&data), 32);
}

#[test]
fn count_varints_32_bytes_mixed_continuation() {
    // 32 bytes, every other byte is a continuation byte.
    let mut data = vec![0u8; 32];
    for i in 0..32 {
        data[i] = if i % 2 == 0 { 0x80 } else { 0x01 };
    }
    // 16 terminal bytes (odd indices).
    assert_eq!(count_packed_varints(&data), 16);
}

// ---------------------------------------------------------------------------
// decode_packed_sint64_cumulative
// ---------------------------------------------------------------------------

#[test]
fn cumulative_empty() {
    let mut out = Vec::new();
    decode_packed_sint64_cumulative(&[], 0, &mut out);
    assert!(out.is_empty());
}

#[test]
fn cumulative_empty_with_base() {
    let mut out = Vec::new();
    decode_packed_sint64_cumulative(&[], 42, &mut out);
    assert!(out.is_empty());
}

#[test]
fn cumulative_single_element() {
    // Zigzag encode delta=5: zigzag(5) = 10 = 0x0A
    let mut out = Vec::new();
    decode_packed_sint64_cumulative(&[0x0A], 0, &mut out);
    assert_eq!(out, vec![5]);
}

#[test]
fn cumulative_base_nonzero() {
    // delta=3, base=100 → 103
    // zigzag(3) = 6 = 0x06
    let mut out = Vec::new();
    decode_packed_sint64_cumulative(&[0x06], 100, &mut out);
    assert_eq!(out, vec![103]);
}

#[test]
fn cumulative_roundtrip() {
    // Encode known deltas, then decode and verify cumulative sums.
    let deltas: Vec<i64> = vec![10, -3, 7, -1, 20];
    let mut scratch = Vec::new();
    let mut field_buf = Vec::new();
    encode_packed_sint64(&mut field_buf, &mut scratch, 1, &deltas);

    // Strip tag + length prefix to get packed body.
    let mut c = Cursor::new(&field_buf);
    let _ = c.read_tag().unwrap();
    let body = c.read_len_delimited().unwrap();

    let mut out = Vec::new();
    decode_packed_sint64_cumulative(body, 0, &mut out);

    // Expected: cumulative sums of [10, -3, 7, -1, 20]
    assert_eq!(out, vec![10, 7, 14, 13, 33]);
}

#[test]
fn cumulative_roundtrip_with_base() {
    let deltas: Vec<i64> = vec![5, -2, 8];
    let mut scratch = Vec::new();
    let mut field_buf = Vec::new();
    encode_packed_sint64(&mut field_buf, &mut scratch, 1, &deltas);

    let mut c = Cursor::new(&field_buf);
    let _ = c.read_tag().unwrap();
    let body = c.read_len_delimited().unwrap();

    let mut out = Vec::new();
    decode_packed_sint64_cumulative(body, 1000, &mut out);
    assert_eq!(out, vec![1005, 1003, 1011]);
}

#[test]
fn cumulative_append_semantics() {
    // out already has elements — new results should be appended.
    let mut out = vec![999i64, 888];
    // delta=1 → zigzag(1) = 2 = 0x02
    decode_packed_sint64_cumulative(&[0x02], 0, &mut out);
    assert_eq!(out, vec![999, 888, 1]);
}

#[test]
fn cumulative_boundary_values() {
    // Test zigzag/varint size boundaries as single deltas, base=0.
    let boundary_values: Vec<i64> = vec![63, 64, 127, 128, 8191, 8192, 16383, 16384];
    for &val in &boundary_values {
        let mut scratch = Vec::new();
        let mut field_buf = Vec::new();
        encode_packed_sint64(&mut field_buf, &mut scratch, 1, &[val]);
        let mut c = Cursor::new(&field_buf);
        let _ = c.read_tag().unwrap();
        let body = c.read_len_delimited().unwrap();

        let mut out = Vec::new();
        decode_packed_sint64_cumulative(body, 0, &mut out);
        assert_eq!(out, vec![val], "failed for delta={val}");
    }
}

#[test]
fn cumulative_extreme_deltas() {
    // i64::MIN and i64::MAX as single deltas.
    for &val in &[i64::MIN, i64::MAX] {
        let mut scratch = Vec::new();
        let mut field_buf = Vec::new();
        encode_packed_sint64(&mut field_buf, &mut scratch, 1, &[val]);
        let mut c = Cursor::new(&field_buf);
        let _ = c.read_tag().unwrap();
        let body = c.read_len_delimited().unwrap();

        let mut out = Vec::new();
        decode_packed_sint64_cumulative(body, 0, &mut out);
        assert_eq!(out, vec![val], "failed for delta={val}");
    }
}

#[test]
fn cumulative_wrapping() {
    // Accumulation that crosses i64 range boundary.
    // base = i64::MAX, delta = 1 → wraps to i64::MIN
    // zigzag(1) = 2 = 0x02
    let mut out = Vec::new();
    decode_packed_sint64_cumulative(&[0x02], i64::MAX, &mut out);
    assert_eq!(out, vec![i64::MAX.wrapping_add(1)]);
    assert_eq!(out[0], i64::MIN);
}

#[test]
fn cumulative_stops_on_overflow_varint() {
    // A valid varint [0x01] followed by a 10-byte varint whose final byte is
    // 0x02 (overflows u64 — read_varint rejects this, PackedIter stops).
    // The batch decoder must also stop and not append the overflowing value.
    let mut data = vec![0x02]; // zigzag(2) = 1, so delta = 1
    // 9 continuation bytes (0xFF) + final byte 0x02 (overflow: 10th byte > 1)
    data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02]);
    let mut out = Vec::new();
    decode_packed_sint64_cumulative(&data, 0, &mut out);
    // Only the first valid varint should be decoded; the overflowing one stops iteration.
    assert_eq!(out, vec![1]);
}

#[test]
fn cumulative_stops_matches_packed_iter_on_overflow() {
    // Verify that the batch decoder and PackedSint64Iter produce the same
    // output when the packed body ends with an overflowing varint.
    let mut data = vec![0x04, 0x06]; // zigzag(2)=4, zigzag(3)=6 → deltas 2, 3
    // Append overflowing 10-byte varint.
    data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02]);
    data.push(0x02); // Another valid varint that should NOT be reached.

    // PackedSint64Iter behavior: collect decoded values.
    let iter_values: Vec<i64> = PackedSint64Iter::new(&data).collect();

    // Batch decoder with base=0, cumulative.
    let mut batch_out = Vec::new();
    decode_packed_sint64_cumulative(&data, 0, &mut batch_out);

    // The iter yields [2, 3] then stops at the overflow. The batch decoder
    // yields cumulative [2, 5] then stops at the same point.
    assert_eq!(iter_values, vec![2, 3]);
    assert_eq!(batch_out, vec![2, 5]);
}

// ---------------------------------------------------------------------------
// encode_varint_to_slice
// ---------------------------------------------------------------------------

#[test]
fn encode_to_slice_1byte() {
    let mut buf = [0u8; 10];
    for value in [0u64, 1, 127] {
        let n = unsafe { encode_varint_to_slice(&mut buf, value) };
        assert_eq!(n, 1, "value={value}");
        // Roundtrip.
        let mut c = Cursor::new(&buf[..n]);
        assert_eq!(c.read_varint().unwrap(), value);
    }
}

#[test]
fn encode_to_slice_2byte() {
    let mut buf = [0u8; 10];
    for value in [128u64, 300, 16383] {
        let n = unsafe { encode_varint_to_slice(&mut buf, value) };
        assert_eq!(n, 2, "value={value}");
        let mut c = Cursor::new(&buf[..n]);
        assert_eq!(c.read_varint().unwrap(), value);
    }
}

#[test]
fn encode_to_slice_3byte_boundary() {
    let mut buf = [0u8; 10];
    let n = unsafe { encode_varint_to_slice(&mut buf, 16384) };
    assert_eq!(n, 3);
    let mut c = Cursor::new(&buf[..n]);
    assert_eq!(c.read_varint().unwrap(), 16384);
}

#[test]
fn encode_to_slice_max() {
    let mut buf = [0u8; 10];
    let n = unsafe { encode_varint_to_slice(&mut buf, u64::MAX) };
    assert_eq!(n, 10);
    let mut c = Cursor::new(&buf[..n]);
    assert_eq!(c.read_varint().unwrap(), u64::MAX);
}

#[test]
fn encode_to_slice_roundtrip_sweep() {
    // Sweep through varint size boundaries.
    let values = [0u64, 1, 127, 128, 16383, 16384, 2097151, 2097152, u32::MAX as u64, u64::MAX];
    let mut buf = [0u8; 10];
    for value in values {
        let n = unsafe { encode_varint_to_slice(&mut buf, value) };
        let mut c = Cursor::new(&buf[..n]);
        assert_eq!(c.read_varint().unwrap(), value, "roundtrip failed for {value}");
        assert!(c.is_empty(), "trailing bytes for {value}");
    }
}

// ---------------------------------------------------------------------------
// Cursor::read_varint_unchecked
// ---------------------------------------------------------------------------

#[test]
fn unchecked_single_byte() {
    for value in [0u64, 1, 127] {
        let mut buf = [0u8; 10];
        let n = unsafe { encode_varint_to_slice(&mut buf, value) };
        let mut c = Cursor::new(&buf[..n]);
        let result = unsafe { c.read_varint_unchecked() };
        assert_eq!(result, value, "value={value}");
        assert!(c.is_empty());
    }
}

#[test]
fn unchecked_multi_byte() {
    for value in [128u64, 150, 300, 16383, 16384, 2097151] {
        let mut buf = [0u8; 10];
        let n = unsafe { encode_varint_to_slice(&mut buf, value) };
        let mut c = Cursor::new(&buf[..n]);
        let result = unsafe { c.read_varint_unchecked() };
        assert_eq!(result, value, "value={value}");
        assert!(c.is_empty());
    }
}

#[test]
fn unchecked_u64_max() {
    let mut buf = [0u8; 10];
    let n = unsafe { encode_varint_to_slice(&mut buf, u64::MAX) };
    let mut c = Cursor::new(&buf[..n]);
    let result = unsafe { c.read_varint_unchecked() };
    assert_eq!(result, u64::MAX);
    assert!(c.is_empty());
}

#[test]
fn unchecked_matches_checked() {
    // Verify identical results and cursor advancement for a range of valid values.
    let values = [0u64, 1, 127, 128, 300, 16383, 16384, u32::MAX as u64, u64::MAX];
    for value in values {
        let mut buf = [0u8; 10];
        let n = unsafe { encode_varint_to_slice(&mut buf, value) };

        let mut checked = Cursor::new(&buf[..n]);
        let mut unchecked = Cursor::new(&buf[..n]);

        let checked_val = checked.read_varint().unwrap();
        let unchecked_val = unsafe { unchecked.read_varint_unchecked() };

        assert_eq!(checked_val, unchecked_val, "value mismatch for {value}");
        assert_eq!(checked.position(), unchecked.position(), "position mismatch for {value}");
    }
}

#[test]
fn unchecked_sequential_reads() {
    // Multiple varints back to back, read sequentially with unchecked.
    let values = [1u64, 300, 127, 16384, 0];
    let mut encoded = Vec::new();
    for &v in &values {
        encode_varint(&mut encoded, v);
    }

    let mut c = Cursor::new(&encoded);
    for &expected in &values {
        let result = unsafe { c.read_varint_unchecked() };
        assert_eq!(result, expected);
    }
    assert!(c.is_empty());
}
