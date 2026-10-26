#![expect(clippy::unwrap_used, missing_docs)]

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
    assert_eq!(c.read_varint(), Err(WireError::TruncatedVarint));
    assert!(c.is_empty());
    // Nine continuation bytes then EOF: truncated, not an overflow, since the
    // tenth byte that would decide overflow never arrives.
    let mut c = Cursor::new(&[0x80; 9]);
    assert_eq!(c.read_varint(), Err(WireError::TruncatedVarint));
    assert!(c.is_empty());
}

#[test]
fn decode_varint_empty() {
    let mut c = Cursor::new(&[]);
    assert_eq!(c.read_varint(), Err(WireError::TruncatedVarint));
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
    // Same as above but final byte is 0x02 - overflows u64
    let data = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02];
    let mut c = Cursor::new(&data);
    assert_eq!(c.read_varint(), Err(WireError::VarintOverflow));
}

#[test]
fn decode_varint_10byte_overflow_high() {
    // Final byte 0x7F - way beyond u64
    let data = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F];
    let mut c = Cursor::new(&data);
    assert_eq!(c.read_varint(), Err(WireError::VarintOverflow));
}

/// The tenth byte decides: a valid low bit with no continuation (`0x00`,
/// `0x01`) completes a `u64`, anything else is an overflow there and then.
#[test]
fn decode_varint_10th_byte_decides() {
    for (last, expected) in [(0x00u8, Ok(0)), (0x01, Ok(1u64 << 63))] {
        let mut data = vec![0x80; 9];
        data.push(last);
        let mut c = Cursor::new(&data);
        assert_eq!(c.read_varint(), expected, "last={last:#x}");
        assert!(c.is_empty(), "last={last:#x}");
    }
}

/// A continuation byte in tenth position, even `0x81` whose payload bit is
/// valid, cannot start an eleventh byte: no `u64` varint is longer than ten.
/// The input ends right there, so reading on would report truncation; an
/// overflow proves the decoder rejects at the tenth byte without looking for
/// an eleventh.
#[test]
fn decode_varint_10th_byte_continuation_is_overflow() {
    for (fill, last) in [(0x80u8, 0x80u8), (0xFF, 0x81), (0x80, 0x81)] {
        let mut data = vec![fill; 9];
        data.push(last);
        let mut c = Cursor::new(&data);
        assert_eq!(
            c.read_varint(),
            Err(WireError::VarintOverflow),
            "fill={fill:#x} last={last:#x}"
        );
        assert!(c.is_empty(), "fill={fill:#x} last={last:#x}");
    }
}

/// A 10-byte varint whose last byte overflows `u64`, as a terminal byte
/// (`0x02`) and as a continuation byte (`0x80`), each followed by a valid
/// tag + varint field. The bad varint abandons the input: the cursor is left
/// at the end, the same state a truncated varint leaves, and the trailing
/// field is not reachable.
#[test]
fn decode_varint_overflow_abandons_input() {
    for last in [0x02u8, 0x80] {
        let mut data = vec![0xFF; 9];
        data.extend_from_slice(&[last, 0x08, 0x01]);
        let mut c = Cursor::new(&data);
        assert_eq!(
            c.read_varint(),
            Err(WireError::VarintOverflow),
            "last={last:#x}"
        );
        assert!(c.is_empty(), "last={last:#x}");
        assert_eq!(c.remaining(), 0, "last={last:#x}");
        assert_eq!(c.position(), data.len(), "last={last:#x}");
        assert!(c.read_tag().unwrap().is_none(), "last={last:#x}");
    }
}

#[test]
fn decode_varint_truncated_leaves_cursor_at_end() {
    let data = [0x08, 0x80, 0x80];
    let mut c = Cursor::new(&data);
    assert_eq!(c.read_varint().unwrap(), 8);
    assert_eq!(c.read_varint(), Err(WireError::TruncatedVarint));
    assert_eq!(c.position(), data.len());
}

/// Composed readers: a malformed varint abandons the input, a well-formed
/// varint rejected for its value is consumed and nothing more.
#[test]
fn composed_readers_malformed_vs_rejected_value() {
    let mut overflow = vec![0xFF; 9];
    overflow.extend_from_slice(&[0x02, 0x08, 0x01]);

    let mut c = Cursor::new(&overflow);
    assert_eq!(c.read_tag(), Err(WireError::VarintOverflow));
    assert!(c.is_empty());
    let mut c = Cursor::new(&overflow);
    assert_eq!(c.read_len_delimited(), Err(WireError::VarintOverflow));
    assert!(c.is_empty());
    let mut c = Cursor::new(&overflow);
    assert_eq!(c.read_varint_u32(), Err(WireError::VarintOverflow));
    assert!(c.is_empty());
    let mut c = Cursor::new(&overflow);
    assert_eq!(c.read_sint64(), Err(WireError::VarintOverflow));
    assert!(c.is_empty());

    // u32::MAX + 1 is a well-formed 5-byte varint: consumed, then rejected.
    let mut too_big = Vec::new();
    encode_varint(&mut too_big, u64::from(u32::MAX) + 1);
    let used = too_big.len();
    too_big.extend_from_slice(&[0x08, 0x01]);
    let mut c = Cursor::new(&too_big);
    assert_eq!(c.read_varint_u32(), Err(WireError::U32Overflow));
    assert_eq!(c.position(), used);
    let mut c = Cursor::new(&too_big);
    assert_eq!(c.read_tag(), Err(WireError::U32Overflow));
    assert_eq!(c.position(), used);

    // Tag with field number 0: consumed, then rejected.
    let mut c = Cursor::new(&[0x00, 0x08, 0x01]);
    assert_eq!(c.read_tag(), Err(WireError::FieldNumberZero));
    assert_eq!(c.position(), 1);
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
    assert_eq!(c.read_varint_u32(), Err(WireError::U32Overflow));
    assert!(c.is_empty());
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
    assert_eq!(c.read_tag(), Err(WireError::U32Overflow));
    assert!(c.is_empty());
}

#[test]
fn decode_read_tag_field_zero() {
    // Tag varint where field_number = 0 is invalid per protobuf spec.
    // Wire type bits 0-2 can be anything; field bits 3+ are all zero.
    for wire_type in 0..=7u8 {
        let data = [wire_type, 0x08];
        let mut c = Cursor::new(&data);
        assert_eq!(
            c.read_tag(),
            Err(WireError::FieldNumberZero),
            "tag with field 0, wire_type {wire_type}"
        );
        // The rejected tag is consumed, nothing after it.
        assert_eq!(c.position(), 1, "wire_type {wire_type}");
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
    // zigzag: 0->0, 1->-1, 2->1, 4294967294->i32::MAX, 4294967295->i32::MIN
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
        assert_eq!(
            c.read_sint32().unwrap(),
            expected,
            "sint32 failed for raw={raw}"
        );
    }
}

// ---------------------------------------------------------------------------
// Decode: skip_varint edge cases
// ---------------------------------------------------------------------------

#[test]
fn skip_varint_overlength() {
    // 11 continuation bytes + terminator - not a valid varint (>10 bytes).
    // skip_varint has no length check (by design it just scans for MSB=0),
    // so this documents that it skips overlength sequences without error.
    let mut data = vec![0x80; 11];
    data.push(0x00); // terminator
    let mut c = Cursor::new(&data);
    // skip_varint accepts this - it's a raw byte scanner, not a value decoder
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

/// Run one read on literal input that fails with `kind`. The match has no
/// wildcard, so a new kind does not compile until it gets an input here, and
/// `WireError::ALL` is generated from the enum itself, so the test below
/// walks every kind.
fn produce(kind: WireError) -> WireResult<()> {
    match kind {
        WireError::TruncatedVarint => Cursor::new(&[0x80]).read_varint().map(drop),
        WireError::VarintOverflow => Cursor::new(&[0xFF; 10]).read_varint().map(drop),
        WireError::U32Overflow => Cursor::new(&[0x80, 0x80, 0x80, 0x80, 0x10])
            .read_varint_u32()
            .map(drop),
        WireError::FieldNumberZero => Cursor::new(&[0x02]).read_tag().map(drop),
        WireError::LengthPastEnd => Cursor::new(&[0x02, 0xAA]).read_len_delimited().map(drop),
        WireError::TruncatedFixed32 => Cursor::new(&[0; 3]).read_fixed32().map(drop),
        WireError::TruncatedFixed64 => Cursor::new(&[0; 7]).read_fixed64().map(drop),
        WireError::UnknownWireType => Cursor::new(&[0; 16]).skip_field(3),
    }
}

#[test]
fn wire_error_every_kind_from_input() {
    for &kind in WireError::ALL {
        assert_eq!(produce(kind), Err(kind));
    }
}

/// The full `Display` text of every kind, as literals: deriving the expected
/// text from `as_str` would let both change wrongly together.
#[test]
fn wire_error_display() {
    for &kind in WireError::ALL {
        let expected = match kind {
            WireError::TruncatedVarint => "wire format error: truncated varint",
            WireError::VarintOverflow => "wire format error: varint overflows u64",
            WireError::U32Overflow => "wire format error: varint overflows u32",
            WireError::FieldNumberZero => "wire format error: tag has field number 0",
            WireError::LengthPastEnd => {
                "wire format error: length-delimited field extends past end"
            }
            WireError::TruncatedFixed32 => "wire format error: truncated 32-bit fixed-width value",
            WireError::TruncatedFixed64 => "wire format error: truncated 64-bit fixed-width value",
            WireError::UnknownWireType => "wire format error: unknown wire type",
        };
        assert_eq!(kind.to_string(), expected);
    }
}

/// `as_str` is what downstream error types carry, so it is pinned on its
/// own, not only through `Display`.
#[test]
fn wire_error_as_str() {
    for &kind in WireError::ALL {
        let expected = match kind {
            WireError::TruncatedVarint => "truncated varint",
            WireError::VarintOverflow => "varint overflows u64",
            WireError::U32Overflow => "varint overflows u32",
            WireError::FieldNumberZero => "tag has field number 0",
            WireError::LengthPastEnd => "length-delimited field extends past end",
            WireError::TruncatedFixed32 => "truncated 32-bit fixed-width value",
            WireError::TruncatedFixed64 => "truncated 64-bit fixed-width value",
            WireError::UnknownWireType => "unknown wire type",
        };
        assert_eq!(kind.as_str(), expected);
    }
}

/// `WireError` is a leaf: no kind wraps a lower-level cause.
#[test]
fn wire_error_has_no_source() {
    for &kind in WireError::ALL {
        let err: &dyn std::error::Error = &kind;
        assert!(err.source().is_none(), "{kind:?}");
    }
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
    // zigzag: 0->0, 1->-1, 2->1, 3->-2
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

/// Packed bodies with a malformed varint followed by valid data, and how many
/// values precede the bad varint. Overflow with a terminal 10th byte, overflow
/// with a continuation 10th byte, and a truncated tail.
fn malformed_packed_bodies() -> Vec<(Vec<u8>, usize)> {
    let mut cases = Vec::new();
    for last in [0x02u8, 0x80] {
        let mut data = vec![0x04, 0x06];
        data.extend_from_slice(&[0xFF; 9]);
        data.push(last);
        data.extend_from_slice(&[0x02, 0x04, 0x06]);
        cases.push((data, 2));
    }
    cases.push((vec![0x04, 0x80, 0x80], 1));
    cases
}

/// After the first `None`, every later `next()` is `None` too, the iterator
/// reports no bytes left, and a clone of it is just as finished.
/// The `FusedIterator` bound is the compile-time half of the check.
fn assert_fused_on_malformed<'a, I>(
    name: &str,
    new: fn(&'a [u8]) -> I,
    is_empty: fn(&I) -> bool,
    remaining_bytes: fn(&I) -> usize,
    data: &'a [u8],
    valid: usize,
) where
    I: std::iter::FusedIterator + Clone,
{
    let mut it = new(data);
    assert_eq!(
        it.by_ref().take(valid + 1).count(),
        valid,
        "{name} {data:?}"
    );
    for _ in 0..4 {
        assert!(it.next().is_none(), "{name} resumed on {data:?}");
    }
    assert!(is_empty(&it), "{name} {data:?}");
    assert_eq!(remaining_bytes(&it), 0, "{name} {data:?}");
    assert_eq!(it.size_hint(), (0, Some(0)), "{name} {data:?}");
    let mut clone = it.clone();
    assert!(clone.next().is_none(), "{name} clone {data:?}");
    assert!(is_empty(&clone), "{name} clone {data:?}");
}

macro_rules! check_fused {
    ($ty:ident, $data:expr, $valid:expr) => {
        assert_fused_on_malformed(
            stringify!($ty),
            $ty::new,
            $ty::is_empty,
            $ty::remaining_bytes,
            $data,
            $valid,
        )
    };
}

#[test]
fn packed_iters_stay_finished_after_decode_error() {
    for (data, valid) in malformed_packed_bodies() {
        check_fused!(PackedIter, &data, valid);
        check_fused!(PackedSint64Iter, &data, valid);
        check_fused!(PackedSint32Iter, &data, valid);
        check_fused!(PackedInt64Iter, &data, valid);
        check_fused!(PackedInt32Iter, &data, valid);
        check_fused!(PackedUint32Iter, &data, valid);
        check_fused!(PackedBoolIter, &data, valid);
    }
}

/// Packed bodies that decode cleanly: one-byte, mixed-width, and ten-byte
/// varints, including the two legal tenth bytes (`0x00` and `0x01`).
fn well_formed_packed_bodies() -> Vec<Vec<u8>> {
    let encode = |values: &[u64]| {
        let mut buf = Vec::new();
        for &v in values {
            encode_varint(&mut buf, v);
        }
        buf
    };
    let mut overlong_zero = vec![0x80; 9];
    overlong_zero.push(0x00);
    overlong_zero.push(0x05);
    vec![
        Vec::new(),
        encode(&[1, 2, 3, 4, 5]),
        encode(&[1; 10]),
        encode(&[1; 37]),
        encode(&[0, 127, 128, 16_383, 16_384, 1 << 35, u64::MAX, 7, 300]),
        encode(&[u64::MAX; 4]),
        encode(&[u64::MAX, 1, u64::MAX >> 1, 2, 1 << 63]),
        overlong_zero,
    ]
}

/// At every step, `size_hint` brackets the number of items still to come.
fn assert_size_hint_brackets<I: Iterator + Clone>(name: &str, mut it: I, data: &[u8]) {
    loop {
        let left = it.clone().count();
        let (lo, hi) = it.size_hint();
        assert!(lo <= left, "{name} lower {lo} > {left} on {data:?}");
        assert!(
            hi.is_some_and(|hi| left <= hi),
            "{name} upper {hi:?} < {left} on {data:?}"
        );
        if it.next().is_none() {
            break;
        }
    }
}

/// On malformed input only the upper bound is promised. The lower bound is
/// a documented deviation: it can claim more items than the iterator yields.
fn assert_size_hint_upper_holds<I: Iterator + Clone>(name: &str, mut it: I, data: &[u8]) {
    loop {
        let left = it.clone().count();
        let (_, hi) = it.size_hint();
        assert!(
            hi.is_some_and(|hi| left <= hi),
            "{name} upper {hi:?} < {left} on {data:?}"
        );
        if it.next().is_none() {
            break;
        }
    }
}

macro_rules! check_size_hint {
    ($check:ident, $data:expr) => {
        $check("PackedIter", PackedIter::new($data), $data);
        $check("PackedSint64Iter", PackedSint64Iter::new($data), $data);
        $check("PackedSint32Iter", PackedSint32Iter::new($data), $data);
        $check("PackedInt64Iter", PackedInt64Iter::new($data), $data);
        $check("PackedInt32Iter", PackedInt32Iter::new($data), $data);
        $check("PackedUint32Iter", PackedUint32Iter::new($data), $data);
        $check("PackedBoolIter", PackedBoolIter::new($data), $data);
    };
}

#[test]
fn packed_size_hint_brackets_well_formed_input() {
    for data in well_formed_packed_bodies() {
        check_size_hint!(assert_size_hint_brackets, &data);
    }
}

#[test]
fn packed_size_hint_upper_holds_on_malformed_input() {
    let mut bodies: Vec<Vec<u8>> = malformed_packed_bodies()
        .into_iter()
        .map(|(d, _)| d)
        .collect();
    bodies.push(vec![0x80; 10]);
    bodies.push(vec![0x80; 20]);
    bodies.push(vec![0x01, 0x02, 0x80]);
    for data in bodies {
        check_size_hint!(assert_size_hint_upper_holds, &data);
    }
}

/// Pins the documented deviation: the lower bound comes from the byte count
/// alone, so a malformed run that yields nothing still claims
/// `remaining / 10` items. A change here must update the "Size hint" section
/// of the `PackedIter` docs.
#[test]
fn packed_size_hint_lower_bound_overclaims_on_malformed_input() {
    for (len, claimed) in [(9, 0), (10, 1), (20, 2), (29, 2)] {
        let data = vec![0x80; len];
        let it = PackedIter::new(&data);
        assert_eq!(it.size_hint(), (claimed, Some(len)), "{len} bytes");
        assert_eq!(it.count(), 0, "{len} bytes");
        assert_eq!(
            PackedSint64Iter::new(&data).size_hint(),
            (claimed, Some(len))
        );
        assert_eq!(PackedBoolIter::new(&data).size_hint(), (claimed, Some(len)));
    }
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

/// Wire types a tag can carry, or a caller can pass, that `skip_field` and
/// `read_raw_field` reject: the group types 3 and 4, the unassigned 6 and 7,
/// and values no three-bit tag field can hold.
const UNKNOWN_WIRE_TYPES: [u32; 6] = [3, 4, 6, 7, 8, u32::MAX];

/// Sixteen zero bytes are a complete value for every accepted wire type
/// (a one-byte varint, a zero-length payload, 4 and 8 fixed bytes), so a
/// rejection on this input cannot be truncation.
const VALID_FOR_ANY_WIRE_TYPE: [u8; 16] = [0; 16];

#[test]
fn skip_field_unknown_wire_type() {
    for wire in UNKNOWN_WIRE_TYPES {
        let mut c = Cursor::new(&VALID_FOR_ANY_WIRE_TYPE);
        assert_eq!(
            c.skip_field(wire),
            Err(WireError::UnknownWireType),
            "wire={wire}"
        );
        assert_eq!(c.position(), 0, "wire={wire}");
    }
    // The same input is accepted for every known type.
    for wire in [WIRE_VARINT, WIRE_64BIT, WIRE_LEN, WIRE_32BIT] {
        Cursor::new(&VALID_FOR_ANY_WIRE_TYPE)
            .skip_field(wire)
            .unwrap();
    }
}

/// The varint skip scans for a terminal byte without decoding, so it accepts
/// varints that `read_varint` rejects as an overflow: a tenth byte above
/// `0x01`, and an overlong run of more than ten bytes. A trailing byte shows
/// it stops right after the terminal byte.
#[test]
fn skip_field_varint_accepts_overflowing_varint() {
    let mut overflow = vec![0xFF; 9];
    overflow.push(0x02);
    let mut overlong = vec![0x80; 11];
    overlong.push(0x00);
    for varint in [overflow, overlong] {
        let mut data = varint.clone();
        data.push(0x08);
        assert_eq!(
            Cursor::new(&data).read_varint(),
            Err(WireError::VarintOverflow)
        );
        let mut c = Cursor::new(&data);
        c.skip_field(WIRE_VARINT).unwrap();
        assert_eq!(c.position(), varint.len());
        let mut c = Cursor::new(&data);
        assert_eq!(c.read_raw_field(WIRE_VARINT).unwrap(), &varint[..]);
        assert_eq!(c.position(), varint.len());
    }
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
    assert_eq!(
        c.read_raw_field(WIRE_VARINT),
        Err(WireError::TruncatedVarint)
    );
    assert!(c.is_empty());
}

#[test]
fn read_raw_field_empty_varint() {
    let mut c = Cursor::new(&[]);
    assert_eq!(
        c.read_raw_field(WIRE_VARINT),
        Err(WireError::TruncatedVarint)
    );
}

#[test]
fn read_raw_field_truncated_64bit() {
    let mut c = Cursor::new(&[0x01, 0x02, 0x03]);
    assert_eq!(
        c.read_raw_field(WIRE_64BIT),
        Err(WireError::TruncatedFixed64)
    );
    assert_eq!(c.position(), 0);
}

#[test]
fn read_raw_field_truncated_32bit() {
    let mut c = Cursor::new(&[0x01, 0x02]);
    assert_eq!(
        c.read_raw_field(WIRE_32BIT),
        Err(WireError::TruncatedFixed32)
    );
    assert_eq!(c.position(), 0);
}

#[test]
fn read_raw_field_truncated_len_payload() {
    // Length says 5 bytes but only 2 follow
    let data = [0x05, 0xAA, 0xBB];
    let mut c = Cursor::new(&data);
    assert_eq!(c.read_raw_field(WIRE_LEN), Err(WireError::LengthPastEnd));
    assert_eq!(c.position(), 1);
}

/// A length prefix far past the end of the input, followed by `payload`.
fn huge_len_input(len: u64, payload: &[u8]) -> (Vec<u8>, usize) {
    let mut data = Vec::new();
    encode_varint(&mut data, len);
    let prefix_len = data.len();
    data.extend_from_slice(payload);
    (data, prefix_len)
}

/// Lengths that once overflowed `pos + len` (64-bit) or truncated under
/// `as usize` (32-bit: 2^32 + 3 read as 3, matching the 3 payload bytes).
const HUGE_LENS: [u64; 4] = [u64::MAX, u64::MAX - 1, (1 << 32) + 3, 1 << 63];

#[test]
fn read_len_delimited_huge_len_is_err() {
    for len in HUGE_LENS {
        let (data, prefix_len) = huge_len_input(len, &[0xAA, 0xBB, 0xCC]);
        let mut c = Cursor::new(&data);
        assert_eq!(
            c.read_len_delimited(),
            Err(WireError::LengthPastEnd),
            "len {len}"
        );
        // The prefix is consumed, the payload is not.
        assert_eq!(c.position(), prefix_len, "len {len}");
        assert_eq!(c.remaining(), 3, "len {len}");
    }
}

#[test]
fn skip_field_len_huge_len_is_err() {
    for len in HUGE_LENS {
        let (data, prefix_len) = huge_len_input(len, &[0xAA, 0xBB, 0xCC]);
        let mut c = Cursor::new(&data);
        assert_eq!(
            c.skip_field(WIRE_LEN),
            Err(WireError::LengthPastEnd),
            "len {len}"
        );
        assert_eq!(c.position(), prefix_len, "len {len}");
    }
}

#[test]
fn read_raw_field_len_huge_len_is_err() {
    for len in HUGE_LENS {
        let (data, prefix_len) = huge_len_input(len, &[0xAA, 0xBB, 0xCC]);
        let mut c = Cursor::new(&data);
        assert_eq!(
            c.read_raw_field(WIRE_LEN),
            Err(WireError::LengthPastEnd),
            "len {len}"
        );
        assert_eq!(c.position(), prefix_len, "len {len}");
    }
}

#[test]
fn read_len_delimited_huge_len_mid_buffer() {
    // A valid field first, so the bad prefix sits at a nonzero offset.
    let mut data = Vec::new();
    encode_bytes_field_always(&mut data, 1, b"ok");
    let first = data.len();
    encode_varint(&mut data, u64::MAX);
    let mut c = Cursor::new(&data);
    assert_eq!(c.read_tag().unwrap(), Some((1, WIRE_LEN)));
    assert_eq!(c.read_len_delimited().unwrap(), b"ok");
    assert_eq!(c.position(), first);
    assert_eq!(c.read_len_delimited(), Err(WireError::LengthPastEnd));
    assert_eq!(c.position(), data.len());
}

#[test]
fn read_len_delimited_exact_fit_and_empty_at_eof() {
    let data = [0x02, 0xAA, 0xBB, 0x00];
    let mut c = Cursor::new(&data);
    assert_eq!(c.read_len_delimited().unwrap(), &[0xAA, 0xBB]);
    // Zero-length payload whose prefix is the last byte.
    assert_eq!(c.read_len_delimited().unwrap(), &[] as &[u8]);
    assert!(c.is_empty());
    // Nonempty payload ending exactly at EOF.
    let data = [0x02, 0xAA, 0xBB];
    let mut c = Cursor::new(&data);
    assert_eq!(c.read_len_delimited().unwrap(), &[0xAA, 0xBB]);
    assert!(c.is_empty());
    // Length one past the end fails without consuming the payload.
    let data = [0x03, 0xAA, 0xBB];
    let mut c = Cursor::new(&data);
    assert_eq!(c.read_len_delimited(), Err(WireError::LengthPastEnd));
    assert_eq!(c.position(), 1);
}

#[test]
fn fixed_width_short_at_offset_leaves_cursor() {
    // Three bytes after a one-byte varint: too short for fixed32 and fixed64.
    let data = [0x01, 0xAA, 0xBB, 0xCC];
    for width in [4usize, 8] {
        let mut c = Cursor::new(&data);
        c.read_varint().unwrap();
        let (err, wire) = if width == 4 {
            (WireError::TruncatedFixed32, WIRE_32BIT)
        } else {
            (WireError::TruncatedFixed64, WIRE_64BIT)
        };
        if width == 4 {
            assert_eq!(c.read_fixed32(), Err(err));
            assert_eq!(c.position(), 1);
            assert_eq!(c.read_float(), Err(err));
        } else {
            assert_eq!(c.read_fixed64(), Err(err));
            assert_eq!(c.position(), 1);
            assert_eq!(c.read_double(), Err(err));
        }
        assert_eq!(c.position(), 1);
        assert_eq!(c.skip_field(wire), Err(err));
        assert_eq!(c.position(), 1);
        assert_eq!(c.read_raw_field(wire), Err(err));
        assert_eq!(c.position(), 1);
    }
    // Exact fit at an offset succeeds and reaches the end.
    let data = [0x01, 0x78, 0x56, 0x34, 0x12];
    let mut c = Cursor::new(&data);
    c.read_varint().unwrap();
    assert_eq!(c.read_fixed32().unwrap(), 0x1234_5678);
    assert!(c.is_empty());
}

#[test]
fn read_raw_field_truncated_len_prefix() {
    // Continuation byte in length varint with no terminator
    let mut c = Cursor::new(&[0x80]);
    assert_eq!(c.read_raw_field(WIRE_LEN), Err(WireError::TruncatedVarint));
    assert!(c.is_empty());
}

#[test]
fn read_raw_field_unknown_wire_type() {
    for wire in UNKNOWN_WIRE_TYPES {
        let mut c = Cursor::new(&VALID_FOR_ANY_WIRE_TYPE);
        assert_eq!(
            c.read_raw_field(wire),
            Err(WireError::UnknownWireType),
            "wire={wire}"
        );
        assert_eq!(c.position(), 0, "wire={wire}");
    }
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
    // Both sides of the bit-31 threshold, which is asymmetric: -2^30 still
    // fits in 31 bits, -2^30 - 1 does not.
    assert_eq!(zigzag_encode_32((1 << 30) - 1), 0x7FFF_FFFE);
    assert_eq!(zigzag_encode_32(1 << 30), 0x8000_0000);
    assert_eq!(zigzag_encode_32(-(1 << 30)), 0x7FFF_FFFF);
    assert_eq!(zigzag_encode_32(-(1 << 30) - 1), 0x8000_0001);
    assert_eq!(zigzag_encode_32(i32::MAX), 0xFFFF_FFFE);
    assert_eq!(zigzag_encode_32(i32::MIN), 0xFFFF_FFFF);
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
    // field 1, WIRE_VARINT -> (1 << 3) | 0 = 0x08
    encode_tag(&mut buf, 1, WIRE_VARINT);
    assert_eq!(buf, [0x08]);

    buf.clear();
    // field 1, WIRE_LEN = (1 << 3) | 2 = 0x0A
    encode_tag(&mut buf, 1, WIRE_LEN);
    assert_eq!(buf, [0x0A]);

    buf.clear();
    // field 15, WIRE_VARINT -> (15 << 3) | 0 = 120 = 0x78
    encode_tag(&mut buf, 15, WIRE_VARINT);
    assert_eq!(buf, [0x78]);

    buf.clear();
    // field 16, WIRE_VARINT -> (16 << 3) | 0 = 128 -> 2-byte varint
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
// Encode->Decode roundtrips: field-level
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
    assert_eq!(c.read_fixed32(), Err(WireError::TruncatedFixed32));
    assert_eq!(c.position(), 0);
}

#[test]
fn read_fixed64_truncated() {
    let mut c = Cursor::new(&[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(c.read_fixed64(), Err(WireError::TruncatedFixed64));
    assert_eq!(c.position(), 0);
}

#[test]
#[expect(clippy::approx_constant)]
fn read_float() {
    let val: f32 = 3.14;
    let data = val.to_le_bytes();
    let mut c = Cursor::new(&data);
    let decoded = c.read_float().unwrap();
    assert!((decoded - val).abs() < f32::EPSILON);
}

#[test]
#[expect(clippy::approx_constant)]
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
fn sint32_field_extremes_are_five_bytes() {
    // zigzag(i32::MIN) = 0xFFFF_FFFF: canonical 5-byte varint, not 10.
    let mut buf = Vec::new();
    encode_sint32_field(&mut buf, 1, i32::MIN);
    assert_eq!(buf, [0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);

    buf.clear();
    encode_sint32_field(&mut buf, 1, 1 << 30);
    assert_eq!(buf, [0x08, 0x80, 0x80, 0x80, 0x80, 0x08]);

    buf.clear();
    encode_sint32_field_always(&mut buf, 1, i32::MIN);
    assert_eq!(buf, [0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);
}

#[test]
fn sint32_decode_truncates_before_zigzag() {
    // Raw 2^32: truncating to 32 bits first gives 0. Zigzag-decoding the
    // 64-bit value and then casting would give i32::MIN instead.
    let raw = [0x80, 0x80, 0x80, 0x80, 0x10];
    let mut c = Cursor::new(&raw);
    assert_eq!(c.read_sint32().unwrap(), 0);
    assert!(c.is_empty());

    let values: Vec<i32> = PackedSint32Iter::new(&raw).collect();
    assert_eq!(values, [0]);
}

#[test]
fn sint32_decode_accepts_sign_extended_ten_byte_form() {
    // Versions before the zigzag_encode_32 fix wrote zigzag(i32::MIN) sign-extended
    // to 64 bits. Files on disk carry this form, so decoders must keep accepting it.
    // A following value (raw zigzag 2, which decodes to 1) proves the long varint is fully consumed.
    let legacy = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x02,
    ];
    let mut c = Cursor::new(&legacy);
    assert_eq!(c.read_sint32().unwrap(), i32::MIN);
    assert_eq!(c.read_sint32().unwrap(), 1);
    assert!(c.is_empty());

    let values: Vec<i32> = PackedSint32Iter::new(&legacy).collect();
    assert_eq!(values, [i32::MIN, 1]);
}

#[test]
fn packed_sint32_extremes_are_five_bytes() {
    let mut buf = Vec::new();
    let mut scratch = Vec::new();
    encode_packed_sint32(&mut buf, &mut scratch, 1, &[i32::MIN, i32::MAX]);
    // Tag, length 10, then two 5-byte varints.
    assert_eq!(
        buf,
        [
            0x0A, 10, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0xFE, 0xFF, 0xFF, 0xFF, 0x0F
        ]
    );
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
    #[expect(clippy::approx_constant)]
    for value in [0.0f32, 1.0, -1.0, 3.14, f32::MAX, f32::MIN] {
        let mut buf = Vec::new();
        encode_float_field_always(&mut buf, 4, value);

        let mut c = Cursor::new(&buf);
        let (field, wt) = c.read_tag().unwrap().unwrap();
        assert_eq!(field, 4);
        assert_eq!(wt, WIRE_32BIT);
        let decoded = c.read_float().unwrap();
        assert_eq!(
            decoded.to_bits(),
            value.to_bits(),
            "roundtrip failed for {value}"
        );
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
    #[expect(clippy::approx_constant)]
    for value in [0.0f64, 1.0, -1.0, 2.718281828, f64::MAX, f64::MIN] {
        let mut buf = Vec::new();
        encode_double_field_always(&mut buf, 5, value);

        let mut c = Cursor::new(&buf);
        let (field, wt) = c.read_tag().unwrap().unwrap();
        assert_eq!(field, 5);
        assert_eq!(wt, WIRE_64BIT);
        let decoded = c.read_double().unwrap();
        assert_eq!(
            decoded.to_bits(),
            value.to_bits(),
            "roundtrip failed for {value}"
        );
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
    // Continuation byte with no terminal - not counted.
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
    let data: Vec<u8> = (0..32)
        .map(|i| if i % 2 == 0 { 0x80 } else { 0x01 })
        .collect();
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
    // delta=3, base=100 -> 103
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
    // out already has elements - new results should be appended.
    let mut out = vec![999i64, 888];
    // delta=1 -> zigzag(1) = 2 = 0x02
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
    // base = i64::MAX, delta = 1 -> wraps to i64::MIN
    // zigzag(1) = 2 = 0x02
    let mut out = Vec::new();
    decode_packed_sint64_cumulative(&[0x02], i64::MAX, &mut out);
    assert_eq!(out, vec![i64::MAX.wrapping_add(1)]);
    assert_eq!(out[0], i64::MIN);
}

#[test]
fn cumulative_stops_on_overflow_varint() {
    // A valid varint [0x01] followed by a 10-byte varint whose final byte is
    // 0x02 (overflows u64 - read_varint rejects this, PackedIter stops).
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
    let mut data = vec![0x04, 0x06]; // zigzag(2)=4, zigzag(3)=6 -> deltas 2, 3
    // Append overflowing 10-byte varint.
    data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02]);
    data.push(0x02); // Another valid varint that should NOT be reached.

    // PackedSint64Iter behavior. Collecting stops at the first None, so it
    // cannot tell a stopped iterator from one that would resume; call next()
    // again afterwards to check the trailing value is really unreachable.
    let mut iter = PackedSint64Iter::new(&data);
    let iter_values: Vec<i64> = iter.by_ref().collect();
    assert!(iter.next().is_none(), "iterator resumed past the overflow");

    // Batch decoder with base=0, cumulative.
    let mut batch_out = Vec::new();
    decode_packed_sint64_cumulative(&data, 0, &mut batch_out);

    // The iter yields [2, 3] then stops at the overflow. The batch decoder
    // yields cumulative [2, 5] then stops at the same point.
    assert_eq!(iter_values, vec![2, 3]);
    assert_eq!(batch_out, vec![2, 5]);
}

// ---------------------------------------------------------------------------
// Canonical varint fixtures: hand-written bytes, independent of every encoder
// in the crate. Each value sits on one side of a 7-bit group boundary, so
// together they cover every encoded length from 1 to 10 bytes from both
// ends. The unchecked decoder tests take their input only from here: an
// encoder bug must fail a test, never turn into an out-of-contract unsafe
// call.
// ---------------------------------------------------------------------------

const CANONICAL_VARINTS: &[(u64, &[u8])] = &[
    (0, &[0x00]),
    (1, &[0x01]),
    (127, &[0x7F]),
    (128, &[0x80, 0x01]),
    (300, &[0xAC, 0x02]),
    (16_383, &[0xFF, 0x7F]),
    (16_384, &[0x80, 0x80, 0x01]),
    ((1 << 21) - 1, &[0xFF, 0xFF, 0x7F]),
    (1 << 21, &[0x80, 0x80, 0x80, 0x01]),
    ((1 << 28) - 1, &[0xFF, 0xFF, 0xFF, 0x7F]),
    (1 << 28, &[0x80, 0x80, 0x80, 0x80, 0x01]),
    (0xFFFF_FFFF, &[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]),
    ((1 << 35) - 1, &[0xFF, 0xFF, 0xFF, 0xFF, 0x7F]),
    (1 << 35, &[0x80, 0x80, 0x80, 0x80, 0x80, 0x01]),
    ((1 << 42) - 1, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]),
    (1 << 42, &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01]),
    ((1 << 49) - 1, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]),
    (1 << 49, &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01]),
    (
        (1 << 56) - 1,
        &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F],
    ),
    (
        1 << 56,
        &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01],
    ),
    (
        (1 << 63) - 1,
        &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F],
    ),
    (
        1 << 63,
        &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01],
    ),
    (
        u64::MAX,
        &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01],
    ),
];

/// A byte placed after a fixture to show where a read stopped. It is itself
/// a complete one-byte varint (5), so reading it back proves the cursor
/// landed exactly on it.
const SENTINEL: u8 = 0x05;

/// `bytes` followed by `SENTINEL`.
fn with_sentinel(bytes: &[u8]) -> Vec<u8> {
    let mut data = bytes.to_vec();
    data.push(SENTINEL);
    data
}

#[test]
fn canonical_fixtures_cover_every_length() {
    let mut lengths: Vec<usize> = CANONICAL_VARINTS.iter().map(|(_, b)| b.len()).collect();
    lengths.dedup();
    assert_eq!(lengths, (1..=10).collect::<Vec<_>>());
}

// ---------------------------------------------------------------------------
// encode_varint_to_array
// ---------------------------------------------------------------------------

#[test]
fn encode_to_array_writes_canonical_bytes() {
    for &(value, bytes) in CANONICAL_VARINTS {
        let mut buf = [0xAA; 10];
        let n = encode_varint_to_array(&mut buf, value);
        assert_eq!(&buf[..n], bytes, "value={value}");
        assert!(
            buf[n..].iter().all(|&b| b == 0xAA),
            "bytes past the returned length were written for value={value}"
        );
    }
}

#[test]
fn encode_to_array_matches_encode_varint() {
    let mut buf = [0u8; 10];
    let mut expected = Vec::new();
    for shift in 0..64 {
        for value in [1u64 << shift, (1u64 << shift) - 1, (1u64 << shift) + 1] {
            expected.clear();
            encode_varint(&mut expected, value);
            let n = encode_varint_to_array(&mut buf, value);
            assert_eq!(&buf[..n], &expected[..], "value={value}");
        }
    }
}

// ---------------------------------------------------------------------------
// Cursor::read_varint_unchecked
// ---------------------------------------------------------------------------

#[test]
fn unchecked_canonical_fixtures() {
    for &(value, bytes) in CANONICAL_VARINTS {
        // Exactly the varint: the terminal byte is the slice's last byte.
        let mut c = Cursor::new(bytes);
        // SAFETY: every fixture ends in a terminal byte.
        assert_eq!(unsafe { c.read_varint_unchecked() }, value);
        assert_eq!(c.position(), bytes.len(), "value={value}");

        // Followed by more data: the read stops after the terminal byte.
        let data = with_sentinel(bytes);
        let mut c = Cursor::new(&data);
        // SAFETY: the fixture's terminal byte precedes the sentinel.
        assert_eq!(unsafe { c.read_varint_unchecked() }, value);
        assert_eq!(c.position(), bytes.len(), "value={value}");
        // SAFETY: the sentinel is itself a terminal byte.
        assert_eq!(unsafe { c.read_varint_unchecked() }, u64::from(SENTINEL));
        assert!(c.is_empty());
    }
}

#[test]
fn unchecked_matches_checked() {
    // Same value and same cursor advance as read_varint, on canonical and
    // non-minimal encodings alike.
    let non_minimal: &[(u64, &[u8])] = &[
        (0, &[0x80, 0x00]),
        (127, &[0xFF, 0x80, 0x00]),
        (1, &[0x81, 0x80, 0x80, 0x00]),
        (
            0,
            &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00],
        ),
    ];
    for &(value, bytes) in CANONICAL_VARINTS.iter().chain(non_minimal) {
        let data = with_sentinel(bytes);
        let mut checked = Cursor::new(&data);
        let mut unchecked = Cursor::new(&data);
        assert_eq!(checked.read_varint().unwrap(), value, "bytes={bytes:02X?}");
        // SAFETY: every fixture ends in a terminal byte.
        assert_eq!(unsafe { unchecked.read_varint_unchecked() }, value);
        assert_eq!(unchecked.position(), bytes.len(), "bytes={bytes:02X?}");
        assert_eq!(checked.position(), unchecked.position());
    }
}

#[test]
fn unchecked_sequential_reads() {
    // 1, 300, 127, 16384, 0 back to back.
    let data = [0x01, 0xAC, 0x02, 0x7F, 0x80, 0x80, 0x01, 0x00];
    let mut c = Cursor::new(&data);
    for (expected, end) in [(1u64, 1), (300, 3), (127, 4), (16_384, 7), (0, 8)] {
        // SAFETY: the data ends in a terminal byte, so one follows every
        // position before the end.
        assert_eq!(unsafe { c.read_varint_unchecked() }, expected);
        assert_eq!(c.position(), end);
    }
    assert!(c.is_empty());
}

#[test]
fn unchecked_malformed_but_terminated_stops_after_terminal() {
    // Inside the safety contract (a terminal byte exists) but not valid
    // varints: an 11-byte run, an overflowing 10th byte, and a run long
    // enough to push the shift amount far past 64. The value is unspecified
    // and not asserted; the read must not panic in any profile and must
    // stop exactly after the terminal byte.
    let mut long_run = vec![0xFF; 200];
    long_run.push(0x7F);
    let cases: [&[u8]; 3] = [
        &[
            0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
        ],
        &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02],
        &long_run,
    ];
    for bytes in cases {
        let data = with_sentinel(bytes);
        let mut c = Cursor::new(&data);
        // SAFETY: each case ends in a terminal byte.
        let _ = unsafe { c.read_varint_unchecked() };
        assert_eq!(c.position(), bytes.len());
        // SAFETY: the sentinel is itself a terminal byte.
        assert_eq!(unsafe { c.read_varint_unchecked() }, u64::from(SENTINEL));
        assert!(c.is_empty());
    }
}
