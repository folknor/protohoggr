//! Zero-copy protobuf wire-format primitives.
//!
//! Provides varint encoding/decoding, zigzag encoding/decoding, a cursor-based
//! decoder, field-level encoders, and packed repeated field helpers. Pure Rust,
//! std only: no external crate dependencies of any kind, dev included.

use std::fmt;
use std::iter::FusedIterator;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Declares [`WireError`] together with [`WireError::ALL`] and
/// [`WireError::as_str`] from one list, so a new kind cannot be left out of
/// `ALL` - the list the tests walk to produce every kind from real input.
macro_rules! wire_errors {
    ($($(#[$doc:meta])* $kind:ident => $msg:literal,)+) => {
        /// An error that occurs when decoding protobuf wire format.
        ///
        /// A fieldless kind: `Copy` and comparable, so a failed read can be
        /// asserted by kind. The kind says why the read failed,
        /// not where it left the [`Cursor`]; each variant documents that end
        /// state relative to the position the failing call started from.
        //
        // `repr(u32)` is for codegen; the discriminant values are incidental.
        // Measured on a late-2026 nightly on x86-64 against the 16-byte
        // `&'static str` error this enum replaced. With the default one-byte
        // layout, the bit packing of the 8-byte `Result<u32, WireError>`
        // (shifts and a tag test) stayed on the inlined one-byte `read_tag`
        // path, and tag-dispatch loops over fixed32 and length-delimited
        // fields ran up to a fifth slower. At four bytes, `Result<u32, _>` and
        // `Result<Option<(u32, u32)>, _>` lay out as whole 32-bit words and
        // the packing folds away; tag-dispatch loops retired fewer
        // instructions than before. `repr(u64)` added instructions to them
        // instead. One cost remains: the out-of-line `read_varint_slow`
        // writes a 4-byte `Ok` tag with a zeroing idiom where the old error
        // stored an 8-byte immediate, one more retired instruction per
        // multi-byte varint, which did not show as more cycles under fat
        // LTO. Remeasure before changing the representation.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[repr(u32)]
        pub enum WireError {
            $($(#[$doc])* $kind,)+
        }

        impl WireError {
            /// Every kind, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$kind,)+];

            /// A short static description of the kind, without the
            /// `"wire format error: "` prefix that `Display` adds.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$kind => $msg,)+
                }
            }
        }
    };
}

wire_errors! {
    /// The input ended inside a varint, or where a varint was required
    /// (including an empty input). Nothing is left to read: the cursor is at
    /// the end of its data.
    ///
    /// `read_tag` reports a clean end of input as `Ok(None)` instead.
    TruncatedVarint => "truncated varint",
    /// A varint's tenth byte is above `0x01`, terminal or continuation: no
    /// `u64` varint can complete from it. The rest of the input is abandoned
    /// and the cursor is at the end of its data.
    ///
    /// Only reads that decode the value report this. `skip_varint`, and
    /// `skip_field` / `read_raw_field` for [`WIRE_VARINT`], scan for the
    /// terminal byte without decoding and accept such a varint.
    VarintOverflow => "varint overflows u64",
    /// A well-formed varint holds a value above `u32::MAX` where a `u32` is
    /// required (`read_varint_u32`, and a tag in `read_tag`). The varint is
    /// consumed, nothing after it.
    U32Overflow => "varint overflows u32",
    /// A tag has field number 0, which protobuf forbids. The tag varint is
    /// consumed, nothing after it.
    FieldNumberZero => "tag has field number 0",
    /// A length prefix is larger than the remaining input (or than `usize`).
    /// The prefix is consumed; the payload is not.
    LengthPastEnd => "length-delimited field extends past end",
    /// Fewer than 4 bytes remain for a fixed32, float or [`WIRE_32BIT`]
    /// field. The cursor has not moved.
    TruncatedFixed32 => "truncated 32-bit fixed-width value",
    /// Fewer than 8 bytes remain for a fixed64, double or [`WIRE_64BIT`]
    /// field. The cursor has not moved.
    TruncatedFixed64 => "truncated 64-bit fixed-width value",
    /// `skip_field` or `read_raw_field` was given a wire type other than
    /// [`WIRE_VARINT`], [`WIRE_64BIT`], [`WIRE_LEN`] or [`WIRE_32BIT`]. That
    /// includes the group types 3 and 4, which this crate does not support.
    /// The cursor has not moved.
    UnknownWireType => "unknown wire type",
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wire format error: {}", self.as_str())
    }
}

/// A leaf error: `source()` is `None`.
impl std::error::Error for WireError {}

// `WireError` is meant to travel anywhere an error can: boxed as
// `dyn Error + Send + Sync`, copied, and kept past the input it came from.
const _: () = {
    const fn assert_error<T: std::error::Error + Send + Sync + Copy + 'static>() {}
    assert_error::<WireError>();
};

/// A type alias for `Result<T, WireError>`.
pub type WireResult<T> = Result<T, WireError>;

/// Every decoding error is built here. `#[cold]` asks the
/// optimizer to treat the branches that call it as unlikely and lay the
/// error paths out away from the hot code; it is a hint, not a guarantee.
#[cold]
fn wire_error(kind: WireError) -> WireError {
    kind
}

// ---------------------------------------------------------------------------
// Wire-format constants
// ---------------------------------------------------------------------------

/// Protobuf wire type: variable-length integer (LEB128).
pub const WIRE_VARINT: u32 = 0;

/// Protobuf wire type: 64-bit fixed.
pub const WIRE_64BIT: u32 = 1;

/// Protobuf wire type: length-delimited (bytes, strings, submessages, packed repeated).
pub const WIRE_LEN: u32 = 2;

/// Protobuf wire type: 32-bit fixed.
pub const WIRE_32BIT: u32 = 5;

// ---------------------------------------------------------------------------
// Cursor - zero-copy reader over a byte slice
// ---------------------------------------------------------------------------

/// Zero-copy cursor for reading protobuf wire format from a byte slice.
#[derive(Clone, Debug)]
pub struct Cursor<'a> {
    data: &'a [u8],
    /// Invariant: `pos <= data.len()`. [`rest`](Cursor::rest) relies on it
    /// for soundness, so every write to `pos` must preserve it. Each one
    /// either advances past bytes it has just bounds-checked or sets `pos`
    /// to `data.len()` (abandoning the input after a malformed varint),
    /// except in `read_varint_unchecked`, whose caller contract forbids
    /// reading past the end (a violation is an out-of-bounds read, already
    /// UB, before `pos` could pass `data.len()`).
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Create a new cursor over the given byte slice.
    #[inline]
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Returns `true` if the cursor has reached the end of the data.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Returns the number of bytes remaining to be read.
    #[inline]
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Current byte offset within the underlying slice.
    #[inline]
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// The unread bytes, `data[pos..]`, without a bounds check.
    ///
    /// The unchecked slice is not about skipping a check for its own sake:
    /// it tells the optimizer `pos <= data.len()`, which it cannot derive.
    /// Without it, a late-2026 nightly on x86-64 compiled the bounded reads to
    /// two comparisons (`pos <= len` and `len - pos >= n`) where one
    /// suffices, making fixed-width skips costlier than the `pos + n` form
    /// they replaced.
    #[inline]
    fn rest(&self) -> &'a [u8] {
        // SAFETY: `pos <= data.len()` is a field invariant; see `pos`.
        unsafe { self.data.get_unchecked(self.pos..) }
    }

    /// Consume and return the next `n` bytes, or `None` (cursor unchanged)
    /// if fewer than `n` remain.
    ///
    /// Every length- and width-bounded read goes through this or
    /// [`take_array`](Self::take_array). The bound is a comparison against
    /// the remaining length, never `pos + n`: `n` can come straight off the
    /// wire (a length prefix up to `u64::MAX`), and an addition there can
    /// wrap past the check. Once the comparison passes,
    /// `pos + n <= data.len()`, so the advance cannot overflow and keeps the
    /// `pos` invariant.
    #[inline]
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let bytes = self.rest().get(..n)?;
        self.pos += n;
        Some(bytes)
    }

    /// Fixed-width form of [`take`](Self::take).
    #[inline]
    fn take_array<const N: usize>(&mut self) -> Option<&'a [u8; N]> {
        let bytes = self.rest().first_chunk::<N>()?;
        self.pos += N;
        Some(bytes)
    }

    /// Read a varint (LEB128). Fast path for single-byte values.
    ///
    /// A malformed varint - truncated by the end of the data, or a 10th byte
    /// that overflows `u64` - is an `Err` and leaves the cursor at the end of
    /// its data: the rest of the input is abandoned, never resumed from
    /// inside the bad varint. Record [`position`](Self::position) before the
    /// read if the start of the failed varint matters.
    ///
    /// This scalar implementation intentionally does NOT use SIMD. Benchmarked
    /// (criterion, 8000 packed sint64, varint-simd v0.4.1 SSSE3): scalar is
    /// 2.3× faster than SIMD batch4 decode for 1-byte varints (the dominant
    /// OSM case - dense node id/lat/lon deltas) and tied for 3-byte varints.
    /// The 1-byte fast path below is perfectly predicted by the CPU branch
    /// predictor, beating SSE shuffle + mask overhead. See `notes/SIMD.md` in
    /// pbfhogg (dd7f69a) for the full research doc (P3-20, closed).
    #[inline]
    pub fn read_varint(&mut self) -> WireResult<u64> {
        if self.pos >= self.data.len() {
            return Err(wire_error(WireError::TruncatedVarint));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        if b < 0x80 {
            return Ok(u64::from(b));
        }
        self.read_varint_slow(u64::from(b & 0x7F))
    }

    #[cold]
    fn read_varint_slow(&mut self, mut val: u64) -> WireResult<u64> {
        let mut shift: u32 = 7;
        loop {
            if self.pos >= self.data.len() {
                return Err(wire_error(WireError::TruncatedVarint));
            }
            let b = self.data[self.pos];
            self.pos += 1;
            if shift == 63 {
                // 10th byte: only the low bit is valid payload for a u64.
                if b > 1 {
                    // Abandon the rest of the input, the same end state a
                    // truncated varint reaches. Callers that swallow errors
                    // (the packed iterators) then stop for good instead of
                    // resuming mid-garbage at the next byte.
                    self.pos = self.data.len();
                    return Err(wire_error(WireError::VarintOverflow));
                }
                val |= u64::from(b) << 63;
                return Ok(val);
            }
            val |= u64::from(b & 0x7F) << shift;
            if b < 0x80 {
                return Ok(val);
            }
            // Reaches at most 63: the `shift == 63` arm above returns on
            // every path, so a varint can never run past ten bytes here.
            shift += 7;
        }
    }

    /// Read a varint (LEB128) without bounds or validity checks.
    ///
    /// The unchecked counterpart to [`read_varint`](Cursor::read_varint):
    /// no check against the end of the data, and no check of the varint's
    /// shape. It reads bytes up to and including the first one with its high
    /// bit clear (the terminal byte), leaves the cursor just past it, and
    /// returns the decoded value.
    ///
    /// On a well-formed varint the value and the new position are the ones
    /// `read_varint` gives, including for non-minimal encodings such as
    /// `[0x80, 0x00]`. A terminated but malformed varint - longer than ten
    /// bytes, or a tenth byte above `0x01` - is not an error and not UB: the
    /// read still stops after its terminal byte, and returns an unspecified
    /// value. It never panics, in any build profile.
    ///
    /// # Safety
    ///
    /// A byte with its high bit clear must exist at or after the current
    /// position, before the end of the underlying slice. In particular the
    /// cursor must not be empty. Without one, the read runs past the end of
    /// the slice (UB). A terminal byte earlier in the slice, before the
    /// current position, does not count.
    #[inline]
    pub unsafe fn read_varint_unchecked(&mut self) -> u64 {
        // SAFETY: the caller guarantees a terminal byte at or after `pos`,
        // inside `data`, so `pos` is in bounds.
        let b = unsafe { *self.data.get_unchecked(self.pos) };
        self.pos += 1;
        if b < 0x80 {
            return u64::from(b);
        }
        // SAFETY: `b` was not the terminal byte, so the caller's terminal
        // byte lies at or after the new `pos`.
        unsafe { self.read_varint_unchecked_slow(u64::from(b & 0x7F)) }
    }

    /// Continuation of [`read_varint_unchecked`](Self::read_varint_unchecked)
    /// after a first byte with its high bit set.
    ///
    /// # Safety
    ///
    /// A byte with its high bit clear must exist at or after the current
    /// position, before the end of the underlying slice.
    #[cold]
    unsafe fn read_varint_unchecked_slow(&mut self, mut val: u64) -> u64 {
        let mut shift: u32 = 7;
        loop {
            // SAFETY: every byte before the terminal one continues the loop,
            // and the terminal byte returns, so `pos` never passes it; the
            // caller guarantees it lies inside `data`.
            let b = unsafe { *self.data.get_unchecked(self.pos) };
            self.pos += 1;
            // Both wrapping ops are what keep an over-long varint inside the
            // documented contract (unspecified value, no panic): a plain
            // `<<` panics in debug once `shift` reaches 64, and a plain `+=`
            // would overflow `shift` on a run of continuation bytes longer
            // than about 600 million. With overflow checks off (release),
            // Rust defines plain `<<` and `+=` to mask and wrap exactly as
            // these do, so release semantics are the same as before; on a
            // late-2026 nightly on x86-64 the release machine code was
            // byte-identical too.
            val |= u64::from(b & 0x7F).wrapping_shl(shift);
            if b < 0x80 {
                return val;
            }
            shift = shift.wrapping_add(7);
        }
    }

    /// Read a varint and validate it fits in a `u32`.
    ///
    /// A malformed varint leaves the cursor at the end, as in
    /// [`read_varint`](Self::read_varint). A well-formed value above
    /// `u32::MAX` is an `Err` with the varint consumed.
    #[inline]
    pub fn read_varint_u32(&mut self) -> WireResult<u32> {
        let v = self.read_varint()?;
        if v > u64::from(u32::MAX) {
            return Err(wire_error(WireError::U32Overflow));
        }
        #[expect(clippy::cast_possible_truncation)]
        Ok(v as u32)
    }

    /// Read a varint and reinterpret as `i64`.
    #[inline]
    pub fn read_varint_i64(&mut self) -> WireResult<i64> {
        #[expect(clippy::cast_possible_wrap)]
        Ok(self.read_varint()? as i64)
    }

    /// Read a zigzag-encoded `sint64` value.
    #[inline]
    pub fn read_sint64(&mut self) -> WireResult<i64> {
        let v = self.read_varint()?;
        Ok(zigzag_decode_64(v))
    }

    /// Read a zigzag-encoded `sint32` value.
    ///
    /// The full varint is consumed and validated, then truncated to 32 bits
    /// without a range check before zigzag decoding, as protobuf specifies.
    /// This also accepts the sign-extended 10-byte form that earlier
    /// protohoggr versions wrote for large-magnitude values.
    #[inline]
    pub fn read_sint32(&mut self) -> WireResult<i32> {
        let v = self.read_varint()?;
        Ok(zigzag_decode_32(sint32_wire_bits(v)))
    }

    /// Read a little-endian 32-bit fixed-width value.
    #[inline]
    pub fn read_fixed32(&mut self) -> WireResult<u32> {
        match self.take_array() {
            Some(bytes) => Ok(u32::from_le_bytes(*bytes)),
            None => Err(wire_error(WireError::TruncatedFixed32)),
        }
    }

    /// Read a little-endian 64-bit fixed-width value.
    #[inline]
    pub fn read_fixed64(&mut self) -> WireResult<u64> {
        match self.take_array() {
            Some(bytes) => Ok(u64::from_le_bytes(*bytes)),
            None => Err(wire_error(WireError::TruncatedFixed64)),
        }
    }

    /// Read a little-endian `float` (32-bit IEEE 754).
    #[inline]
    pub fn read_float(&mut self) -> WireResult<f32> {
        Ok(f32::from_bits(self.read_fixed32()?))
    }

    /// Read a little-endian `double` (64-bit IEEE 754).
    #[inline]
    pub fn read_double(&mut self) -> WireResult<f64> {
        Ok(f64::from_bits(self.read_fixed64()?))
    }

    /// Read a (`field_number`, `wire_type`) tag. Returns `None` at EOF.
    ///
    /// Returns `Err` if the field number is 0 (invalid per protobuf spec).
    /// Reserved/invalid wire types (3, 4, 6, 7) are returned as-is -
    /// validation is left to the caller or to `skip_field`, which will
    /// reject unknown types. This keeps the hot path branch-free.
    ///
    /// A malformed tag varint leaves the cursor at the end, as in
    /// [`read_varint`](Self::read_varint); a well-formed tag rejected for
    /// its value (above `u32::MAX`, or field number 0) leaves it consumed.
    #[inline]
    pub fn read_tag(&mut self) -> WireResult<Option<(u32, u32)>> {
        if self.is_empty() {
            return Ok(None);
        }
        let v = self.read_varint_u32()?;
        let field = v >> 3;
        if field == 0 {
            return Err(wire_error(WireError::FieldNumberZero));
        }
        Ok(Some((field, v & 0x7)))
    }

    /// Read a length-delimited field, returning the sub-slice.
    ///
    /// A length prefix larger than the remaining input - including one that
    /// does not fit in `usize` - is an `Err`. The prefix varint has been
    /// consumed by then; the payload has not. A malformed prefix varint
    /// instead leaves the cursor at the end, as in
    /// [`read_varint`](Self::read_varint).
    #[inline]
    pub fn read_len_delimited(&mut self) -> WireResult<&'a [u8]> {
        let len = self.read_varint()?;
        // Narrow with `try_from`, never `as`: on a 32-bit target `as` would
        // turn a length of 2^32 + 3 into 3 and decoding would continue
        // desynchronized instead of failing.
        usize::try_from(len)
            .ok()
            .and_then(|len| self.take(len))
            .ok_or_else(|| wire_error(WireError::LengthPastEnd))
    }

    /// Skip a varint by scanning for the terminating byte (MSB=0)
    /// without decoding the value.
    ///
    /// Note: this intentionally has no length limit - it will skip varints
    /// longer than 10 bytes. This is a raw byte scanner for speed, not a
    /// value decoder. For trusted protobuf data (our use case), varints are
    /// always well-formed. Use `read_varint` when overflow validation matters.
    #[inline]
    pub fn skip_varint(&mut self) -> WireResult<()> {
        loop {
            if self.pos >= self.data.len() {
                return Err(wire_error(WireError::TruncatedVarint));
            }
            let b = self.data[self.pos];
            self.pos += 1;
            if b < 0x80 {
                return Ok(());
            }
        }
    }

    /// Read the raw bytes of a field's value given its wire type, without
    /// decoding. The returned slice covers exactly the value bytes (varint
    /// bytes for `WIRE_VARINT`, the length prefix + payload for `WIRE_LEN`,
    /// the 4/8 fixed bytes for `WIRE_32BIT`/`WIRE_64BIT`).
    ///
    /// This is useful for copying unknown fields verbatim without re-encoding.
    /// The tag is NOT included - the caller already has it from `read_tag()`.
    #[inline]
    pub fn read_raw_field(&mut self, wire_type: u32) -> WireResult<&'a [u8]> {
        let start = self.pos;
        self.skip_field(wire_type)?;
        Ok(&self.data[start..self.pos])
    }

    /// Skip an unknown field given its wire type.
    #[inline]
    pub fn skip_field(&mut self, wire_type: u32) -> WireResult<()> {
        match wire_type {
            WIRE_VARINT => {
                self.skip_varint()?;
            }
            WIRE_64BIT => {
                if self.take_array::<8>().is_none() {
                    return Err(wire_error(WireError::TruncatedFixed64));
                }
            }
            WIRE_LEN => {
                self.read_len_delimited()?;
            }
            WIRE_32BIT => {
                if self.take_array::<4>().is_none() {
                    return Err(wire_error(WireError::TruncatedFixed32));
                }
            }
            _ => return Err(wire_error(WireError::UnknownWireType)),
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Zigzag decode
// ---------------------------------------------------------------------------

/// Zigzag-decode a `u64` varint into a signed `i64`.
#[inline]
#[must_use]
pub fn zigzag_decode_64(v: u64) -> i64 {
    #[expect(clippy::cast_possible_wrap)]
    let signed = (v >> 1) as i64;
    #[expect(clippy::cast_possible_wrap)]
    let sign = -((v & 1) as i64);
    signed ^ sign
}

/// Zigzag-decode a 32-bit value into a signed `i32`. Inverse of
/// [`zigzag_encode_32`].
///
/// Takes `u32`, not the raw `u64` varint: narrowing a wire value is the
/// caller's job, and the order matters. Protobuf truncates a `sint32` varint
/// to 32 bits and then zigzag-decodes, which is not the same as decoding 64
/// bits and casting. [`Cursor::read_sint32`] and [`PackedSint32Iter`] do this.
#[inline]
#[must_use]
pub fn zigzag_decode_32(v32: u32) -> i32 {
    #[expect(clippy::cast_possible_wrap)]
    let signed = (v32 >> 1) as i32;
    #[expect(clippy::cast_possible_wrap)]
    let sign = -((v32 & 1) as i32);
    signed ^ sign
}

/// Narrow a raw `sint32` varint to the 32 bits that get zigzag-decoded.
///
/// Discarding the upper bits without checking them is protobuf's specified
/// behavior, not a shortcut: when a `sint64` field is read as `sint32`,
/// protobuf truncates the encoded varint to 32 bits before zigzag decoding.
/// It also keeps reading data written by earlier protohoggr versions, whose
/// `sint32` encoders sign-extended zigzag values with bit 31 set into 10-byte
/// varints.
#[inline]
#[expect(clippy::cast_possible_truncation)]
const fn sint32_wire_bits(v: u64) -> u32 {
    v as u32
}

// ---------------------------------------------------------------------------
// Packed field iterators
// ---------------------------------------------------------------------------

/// Base packed varint iterator. Yields raw `u64` values.
///
/// A malformed varint ends iteration for good: it yields `None` and so does
/// every later call (the iterator is fused). This holds for all the typed
/// wrappers too. There is no way to tell a decode error from the end of the
/// data; use [`Cursor::read_varint`] in a loop when errors matter.
///
/// # Size hint
///
/// `size_hint` returns `(remaining / 10, Some(remaining))` from the byte
/// count alone, and all the typed wrappers forward it. The upper bound always
/// holds. The lower bound holds whenever the remaining bytes decode cleanly,
/// but on malformed input this is a deliberate deviation from the `Iterator`
/// protocol: a malformed varint ends iteration early, so the iterator can
/// yield fewer items than the lower bound - up to `remaining / 10` fewer, and
/// that bound is reached by ten `0x80` bytes, which yield nothing.
///
/// The wrong hint does not by itself cause memory unsafety, and consumers
/// must never rely on `size_hint` for that. Its effect is over-reservation,
/// which adapters can amplify: `Cycle` turns any positive lower bound into
/// `usize::MAX`, so collecting a cycled malformed iterator panics with a
/// capacity overflow, and `take(n)` over that can reserve close to `n`
/// elements.
///
/// It is left this way on purpose. A correct positive lower bound needs
/// content past the cursor, since a ten-byte overflowing run can sit
/// anywhere. Every approach weighed for obtaining it - scanning in
/// `size_hint` (repeated by `Vec::extend` at each growth step, and discarded
/// by `filter` and `filter_map`), caching a scan in the iterator, validating
/// at construction, or bookkeeping in `next` - adds work on well-formed data.
/// A lower bound of 0 makes every `collect` and `extend` regrow from scratch.
/// Keeping the bound by changing malformed-input behavior would mean
/// panicking on untrusted input or fabricating values from misaligned bytes.
/// For an exact count of an untrusted body, count successful
/// [`Cursor::read_varint`] calls.
#[derive(Clone)]
pub struct PackedIter<'a> {
    cursor: Cursor<'a>,
}

impl<'a> PackedIter<'a> {
    /// Create a new packed iterator over the given byte slice.
    #[inline]
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            cursor: Cursor::new(data),
        }
    }

    /// Create an empty packed iterator.
    #[inline]
    #[must_use]
    pub fn empty() -> Self {
        Self {
            cursor: Cursor::new(&[]),
        }
    }

    /// Returns `true` if no bytes remain to be decoded - at the end of the
    /// data, and after a decode error, which abandons the rest.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cursor.is_empty()
    }

    /// Returns the number of bytes remaining to be decoded; zero at the end
    /// of the data and after a decode error.
    #[inline]
    #[must_use]
    pub fn remaining_bytes(&self) -> usize {
        self.cursor.remaining()
    }
}

impl Iterator for PackedIter<'_> {
    type Item = u64;

    #[inline]
    fn next(&mut self) -> Option<u64> {
        if self.cursor.is_empty() {
            return None;
        }
        // Intentional: errors are swallowed as None, ending iteration.
        // Packed fields are length-delimited by the outer message, so in
        // well-formed protobuf data they always contain complete varints.
        // A fallible iterator would add per-element overhead for a case
        // that cannot happen with valid wire data.
        //
        // Fusion rests on `read_varint` leaving the cursor at the end on
        // every error, so the `is_empty` check above ends every later call.
        // That keeps this hot path free of any error-state bookkeeping.
        self.cursor.read_varint().ok()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.cursor.remaining();
        // Each varint is 1-10 bytes, so a body that decodes cleanly holds at
        // least remaining / 10 and at most remaining elements. The lower
        // bound is wrong on malformed input, deliberately: see "Size hint" in
        // the type docs for why it is not computed from the content.
        (remaining / 10, Some(remaining))
    }
}

// --- Typed wrappers ---

/// Packed iterator yielding zigzag-decoded `i64` values (`sint64`).
#[derive(Clone)]
pub struct PackedSint64Iter<'a>(PackedIter<'a>);

impl<'a> PackedSint64Iter<'a> {
    /// Create a new packed `sint64` iterator over the given byte slice.
    #[inline]
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self(PackedIter::new(data))
    }

    /// Create an empty packed `sint64` iterator.
    #[inline]
    #[must_use]
    pub fn empty() -> Self {
        Self(PackedIter::empty())
    }

    /// Returns `true` if no bytes remain to be decoded - at the end of the
    /// data, and after a decode error, which abandons the rest.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of bytes remaining to be decoded; zero at the end
    /// of the data and after a decode error.
    #[inline]
    #[must_use]
    pub fn remaining_bytes(&self) -> usize {
        self.0.remaining_bytes()
    }
}

impl Iterator for PackedSint64Iter<'_> {
    type Item = i64;

    #[inline]
    fn next(&mut self) -> Option<i64> {
        self.0.next().map(zigzag_decode_64)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

/// Packed iterator yielding zigzag-decoded `i32` values (`sint32`).
///
/// Like [`Cursor::read_sint32`], truncates each varint to 32 bits without a
/// range check before zigzag decoding.
#[derive(Clone)]
pub struct PackedSint32Iter<'a>(PackedIter<'a>);

impl<'a> PackedSint32Iter<'a> {
    /// Create a new packed `sint32` iterator over the given byte slice.
    #[inline]
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self(PackedIter::new(data))
    }

    /// Create an empty packed `sint32` iterator.
    #[inline]
    #[must_use]
    pub fn empty() -> Self {
        Self(PackedIter::empty())
    }

    /// Returns `true` if no bytes remain to be decoded - at the end of the
    /// data, and after a decode error, which abandons the rest.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of bytes remaining to be decoded; zero at the end
    /// of the data and after a decode error.
    #[inline]
    #[must_use]
    pub fn remaining_bytes(&self) -> usize {
        self.0.remaining_bytes()
    }
}

impl Iterator for PackedSint32Iter<'_> {
    type Item = i32;

    #[inline]
    fn next(&mut self) -> Option<i32> {
        self.0.next().map(|v| zigzag_decode_32(sint32_wire_bits(v)))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

/// Packed iterator yielding `i64` values (`int64`).
#[derive(Clone)]
pub struct PackedInt64Iter<'a>(PackedIter<'a>);

impl<'a> PackedInt64Iter<'a> {
    /// Create a new packed `int64` iterator over the given byte slice.
    #[inline]
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self(PackedIter::new(data))
    }

    /// Create an empty packed `int64` iterator.
    #[inline]
    #[must_use]
    pub fn empty() -> Self {
        Self(PackedIter::empty())
    }

    /// Returns `true` if no bytes remain to be decoded - at the end of the
    /// data, and after a decode error, which abandons the rest.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of bytes remaining to be decoded; zero at the end
    /// of the data and after a decode error.
    #[inline]
    #[must_use]
    pub fn remaining_bytes(&self) -> usize {
        self.0.remaining_bytes()
    }
}

impl Iterator for PackedInt64Iter<'_> {
    type Item = i64;

    #[inline]
    fn next(&mut self) -> Option<i64> {
        #[expect(clippy::cast_possible_wrap)]
        self.0.next().map(|v| v as i64)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

/// Packed iterator yielding `i32` values (`int32`).
///
/// Truncates each `u64` varint to `i32` without overflow validation. That is
/// protobuf's specified conversion, not a shortcut: a wire value that doesn't
/// fit the field type reads as if cast to it in C++, and wider values do occur
/// in valid data, e.g. after an `int64` field is changed to `int32`.
#[derive(Clone)]
pub struct PackedInt32Iter<'a>(PackedIter<'a>);

impl<'a> PackedInt32Iter<'a> {
    /// Create a new packed `int32` iterator over the given byte slice.
    #[inline]
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self(PackedIter::new(data))
    }

    /// Create an empty packed `int32` iterator.
    #[inline]
    #[must_use]
    pub fn empty() -> Self {
        Self(PackedIter::empty())
    }

    /// Returns `true` if no bytes remain to be decoded - at the end of the
    /// data, and after a decode error, which abandons the rest.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of bytes remaining to be decoded; zero at the end
    /// of the data and after a decode error.
    #[inline]
    #[must_use]
    pub fn remaining_bytes(&self) -> usize {
        self.0.remaining_bytes()
    }
}

impl Iterator for PackedInt32Iter<'_> {
    type Item = i32;

    #[inline]
    fn next(&mut self) -> Option<i32> {
        #[expect(clippy::cast_possible_truncation)]
        self.0.next().map(|v| v as i32)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

/// Packed iterator yielding `u32` values (`uint32`).
///
/// Truncates each `u64` varint to `u32` without overflow validation. That is
/// protobuf's specified conversion, not a shortcut: a wire value that doesn't
/// fit the field type reads as if cast to it in C++, and wider values do occur
/// in valid data, e.g. after a `uint64` field is changed to `uint32`.
#[derive(Clone)]
pub struct PackedUint32Iter<'a>(PackedIter<'a>);

impl<'a> PackedUint32Iter<'a> {
    /// Create a new packed `uint32` iterator over the given byte slice.
    #[inline]
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self(PackedIter::new(data))
    }

    /// Create an empty packed `uint32` iterator.
    #[inline]
    #[must_use]
    pub fn empty() -> Self {
        Self(PackedIter::empty())
    }

    /// Returns `true` if no bytes remain to be decoded - at the end of the
    /// data, and after a decode error, which abandons the rest.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of bytes remaining to be decoded; zero at the end
    /// of the data and after a decode error.
    #[inline]
    #[must_use]
    pub fn remaining_bytes(&self) -> usize {
        self.0.remaining_bytes()
    }
}

impl Iterator for PackedUint32Iter<'_> {
    type Item = u32;

    #[inline]
    fn next(&mut self) -> Option<u32> {
        #[expect(clippy::cast_possible_truncation)]
        self.0.next().map(|v| v as u32)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

/// Packed iterator yielding `bool` values.
#[derive(Clone)]
pub struct PackedBoolIter<'a>(PackedIter<'a>);

impl<'a> PackedBoolIter<'a> {
    /// Create a new packed `bool` iterator over the given byte slice.
    #[inline]
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self(PackedIter::new(data))
    }

    /// Create an empty packed `bool` iterator.
    #[inline]
    #[must_use]
    pub fn empty() -> Self {
        Self(PackedIter::empty())
    }

    /// Returns `true` if no bytes remain to be decoded - at the end of the
    /// data, and after a decode error, which abandons the rest.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of bytes remaining to be decoded; zero at the end
    /// of the data and after a decode error.
    #[inline]
    #[must_use]
    pub fn remaining_bytes(&self) -> usize {
        self.0.remaining_bytes()
    }
}

impl Iterator for PackedBoolIter<'_> {
    type Item = bool;

    #[inline]
    fn next(&mut self) -> Option<bool> {
        self.0.next().map(|v| v != 0)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

// `PackedIter` returns `None` only once its cursor is at the end (exhausted,
// or abandoned by a failed `read_varint`), and the cursor never moves back.
// Each wrapper maps `PackedIter::next` through a pure function.
impl FusedIterator for PackedIter<'_> {}
impl FusedIterator for PackedSint64Iter<'_> {}
impl FusedIterator for PackedSint32Iter<'_> {}
impl FusedIterator for PackedInt64Iter<'_> {}
impl FusedIterator for PackedInt32Iter<'_> {}
impl FusedIterator for PackedUint32Iter<'_> {}
impl FusedIterator for PackedBoolIter<'_> {}

// ---------------------------------------------------------------------------
// Batch packed-field operations
// ---------------------------------------------------------------------------

/// Count the number of varints in a packed field by counting terminal bytes
/// (bytes with the high bit clear, `b & 0x80 == 0`).
///
/// This counts terminal bytes, not necessarily complete varints. A truncated
/// final varint (no terminal byte) is simply not counted. Framing does not
/// make it exact: it fixes the field's byte extent, not the validity of the
/// varints inside. An overflowing ten-byte varint (`0x80` nine times, then
/// `0x02`) counts as 1 here, while the packed iterators yield nothing for it.
/// The count equals what the iterators yield only for a body whose varints
/// are known to be well-formed, which makes it a capacity estimate for
/// untrusted data, not a length.
#[inline]
#[must_use]
pub fn count_packed_varints(data: &[u8]) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: SSE2 is baseline on x86-64 - always available.
        unsafe { count_packed_varints_sse2(data) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        count_packed_varints_scalar(data)
    }
}

/// Scalar fallback: count bytes where `b < 0x80`. The production path off
/// x86-64; on x86-64 it is built for the unit tests, which hold the SSE2 path
/// equal to it.
#[cfg(any(test, not(target_arch = "x86_64")))]
fn count_packed_varints_scalar(data: &[u8]) -> usize {
    let mut count = 0usize;
    for &b in data {
        if b < 0x80 {
            count += 1;
        }
    }
    count
}

/// SSE2 implementation: process 16 bytes at a time using `PMOVMSKB`.
///
/// The `target_feature` attribute is load-bearing even though SSE2 is
/// baseline on x86-64: without it, calling `_mm_movemask_epi8` is unsafe
/// whatever the build configuration enables. The unaligned load takes a raw
/// pointer and has no safe form, so the function stays `unsafe` either way.
/// Safe portable alternatives (word-at-a-time SWAR, a movemask idiom LLVM
/// does not lower to `PMOVMSKB`) were measured slower at some lengths.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn count_packed_varints_sse2(data: &[u8]) -> usize {
    use core::arch::x86_64::{_mm_loadu_si128, _mm_movemask_epi8};

    let mut count = 0usize;
    let len = data.len();
    let mut i = 0usize;
    let ptr = data.as_ptr();

    // Process 16-byte chunks.
    while i + 16 <= len {
        // SAFETY: we checked i + 16 <= len, so ptr.add(i) is valid for 16 bytes.
        let chunk = unsafe { _mm_loadu_si128(ptr.add(i).cast()) };
        // movemask extracts the high bit of each byte into a 16-bit mask.
        // Terminals have high bit = 0, so we invert and popcount.
        #[expect(clippy::cast_sign_loss)]
        let mask = _mm_movemask_epi8(chunk) as u32;
        count += (!mask & 0xFFFF).count_ones() as usize;
        i += 16;
    }

    // Scalar tail.
    while i < len {
        // SAFETY: i < len is checked.
        if unsafe { *ptr.add(i) } < 0x80 {
            count += 1;
        }
        i += 1;
    }

    count
}

/// Decode an entire packed `sint64` field, accumulating zigzag-decoded deltas
/// into absolute IDs starting from `base`.
///
/// Appends results to `out` without clearing it. The caller controls whether
/// to clear `out` beforehand.
///
/// Mirrors [`PackedSint64Iter`] semantics: a malformed varint (truncated or
/// overflowing) is silently swallowed and ends decoding for good; nothing
/// after it is appended. This is a batch operation for trusted
/// wire data, not a strict validator.
///
/// Accumulation uses wrapping `i64` addition - no overflow checks.
pub fn decode_packed_sint64_cumulative(data: &[u8], base: i64, out: &mut Vec<i64>) {
    let count = count_packed_varints(data);
    if count == 0 {
        return;
    }
    out.reserve(count);

    let len = data.len();
    let mut pos = 0usize;
    let mut acc = base;

    while pos < len {
        // Read first byte.
        let b = data[pos];
        pos += 1;
        if b < 0x80 {
            // Single-byte varint fast path.
            let delta = zigzag_decode_64(u64::from(b));
            acc = acc.wrapping_add(delta);
            out.push(acc);
            continue;
        }

        // Multi-byte varint.
        let mut val = u64::from(b & 0x7F);
        let mut shift: u32 = 7;
        loop {
            if pos >= len {
                // Truncated varint - stop silently (packed iterator semantics).
                return;
            }
            let b = data[pos];
            pos += 1;
            if shift == 63 {
                // 10th byte: only the low bit is valid for u64. If b > 1,
                // this is an overflow - stop silently, matching PackedIter
                // which delegates to read_varint → Err → .ok() → None.
                if b > 1 {
                    return;
                }
                val |= u64::from(b) << 63;
                break;
            }
            val |= u64::from(b & 0x7F) << shift;
            if b < 0x80 {
                break;
            }
            shift += 7;
            // Unreachable: the `shift == 63` arm above leaves the loop on
            // every path, so `shift` never passes 63 and every over-long
            // varint stops there as an overflow. The branch stays for
            // codegen, not for safety: on a late-2026 nightly on x86-64,
            // deleting it added an instruction per element to the
            // single-byte fast path above, and moving the 10th-byte arm after
            // `shift += 7` instead ran slower on 9- and 10-byte varints.
            // Remeasure before touching it.
            if shift > 63 {
                return;
            }
        }
        let delta = zigzag_decode_64(val);
        acc = acc.wrapping_add(delta);
        out.push(acc);
    }
}

// ---------------------------------------------------------------------------
// Encoding: varint / zigzag
// ---------------------------------------------------------------------------

/// Encode a `u64` as a variable-length integer (LEB128) into `buf`.
///
/// This scalar implementation intentionally does NOT use SIMD. Benchmarked
/// (criterion, 8000 packed sint64, varint-simd v0.4.1 SSE2): scalar is
/// 3.5× faster for 1-byte varints and 1.5× faster for 3-byte varints.
/// See `notes/SIMD.md` in pbfhogg (dd7f69a) (P3-20, closed).
#[inline]
#[expect(clippy::cast_possible_truncation)]
pub fn encode_varint(buf: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buf.push((value as u8) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

/// Encode a `u64` as a variable-length integer (LEB128) into the front of a
/// 10-byte array, returning the number of bytes written (1 to 10). Bytes
/// past the returned length are left as they were.
///
/// Ten bytes is the longest a `u64` varint can be, so the array type is the
/// whole precondition and no call can write out of bounds. The intended use
/// is a reused stack array copied out with `&buf[..n]`; writing straight
/// into a larger buffer means getting a `&mut [u8; 10]` from it, typically
/// with `first_chunk_mut::<10>()`, which is a length check per call unless
/// the optimizer can remove it.
///
/// Has dedicated 1-byte (`< 128`) and 2-byte (`< 16384`) fast paths, covering
/// ~95% of zigzag-encoded OSM way-ref deltas.
#[inline]
#[expect(clippy::cast_possible_truncation)]
pub fn encode_varint_to_array(buf: &mut [u8; 10], value: u64) -> usize {
    // 1-byte fast path: value < 128
    if value < 0x80 {
        buf[0] = value as u8;
        return 1;
    }
    // 2-byte fast path: value < 16384
    if value < 0x4000 {
        buf[0] = (value as u8) | 0x80;
        buf[1] = (value >> 7) as u8;
        return 2;
    }
    // General path for values >= 16384.
    let mut value = value;
    let mut i = 0usize;
    while value >= 0x80 {
        // SAFETY: each pass shifts `value` right by 7, and a u64 is below
        // 0x80 after nine shifts, so this loop writes at most indices 0..=8
        // and leaves `i <= 9`: in bounds for a 10-element array. Plain
        // indexing also compiles without a bounds check (late-2026 nightly,
        // x86-64), but LLVM then unrolls the whole loop into a nine-way
        // compare chain; this form stays a compact loop. Neither has been
        // measured against the other.
        unsafe { *buf.get_unchecked_mut(i) = (value as u8) | 0x80 };
        value >>= 7;
        i += 1;
    }
    // SAFETY: `i <= 9`, see the loop above.
    unsafe { *buf.get_unchecked_mut(i) = value as u8 };
    i + 1
}

/// Zigzag-encode a signed 64-bit integer for `sint64` fields.
///
/// Maps: 0 → 0, -1 → 1, 1 → 2, -2 → 3, 2 → 4, …
#[inline]
#[must_use]
#[expect(clippy::cast_sign_loss)]
pub fn zigzag_encode_64(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

/// Zigzag-encode a signed 32-bit integer for `sint32` fields. Inverse of
/// [`zigzag_decode_32`].
///
/// Returns `u32`; widening it for the wire with `u64::from` zero-extends and
/// gives the canonical varint of at most 5 bytes. Casting the signed
/// intermediate with `as u64` would instead sign-extend results with bit 31
/// set into a 10-byte varint.
#[inline]
#[must_use]
#[expect(clippy::cast_sign_loss)]
pub fn zigzag_encode_32(v: i32) -> u32 {
    ((v << 1) ^ (v >> 31)) as u32
}

// ---------------------------------------------------------------------------
// Field-level encoders
// ---------------------------------------------------------------------------

/// Encode a field tag (`field_number`, `wire_type`) as a varint.
///
/// # Panics
///
/// Panics if `field` is 0 or exceeds `0x1FFF_FFFF` (the protobuf maximum of
/// 2^29 − 1), or if `wire_type` exceeds 7 (only 3 bits are available).
#[inline]
pub fn encode_tag(buf: &mut Vec<u8>, field: u32, wire_type: u32) {
    assert!(
        field > 0 && field <= 0x1FFF_FFFF,
        "field number out of range"
    );
    assert!(wire_type <= 7, "wire type out of range");
    encode_varint(buf, u64::from(field << 3 | wire_type));
}

/// Encode a varint field. Skips if `value == 0`.
#[inline]
pub fn encode_varint_field(buf: &mut Vec<u8>, field: u32, value: u64) {
    if value != 0 {
        encode_tag(buf, field, WIRE_VARINT);
        encode_varint(buf, value);
    }
}

/// Encode a varint field unconditionally (even if zero).
#[inline]
pub fn encode_varint_field_always(buf: &mut Vec<u8>, field: u32, value: u64) {
    encode_tag(buf, field, WIRE_VARINT);
    encode_varint(buf, value);
}

/// Encode an `int64` field. Skips if `value == 0`.
///
/// Negative `i64` values encode as 10-byte varints (sign-extension).
#[inline]
#[expect(clippy::cast_sign_loss)]
pub fn encode_int64_field(buf: &mut Vec<u8>, field: u32, value: i64) {
    if value != 0 {
        encode_tag(buf, field, WIRE_VARINT);
        encode_varint(buf, value as u64);
    }
}

/// Encode an `int64` field unconditionally (even if zero).
#[inline]
#[expect(clippy::cast_sign_loss)]
pub fn encode_int64_field_always(buf: &mut Vec<u8>, field: u32, value: i64) {
    encode_tag(buf, field, WIRE_VARINT);
    encode_varint(buf, value as u64);
}

/// Encode an `int32` field. Skips if `value == 0`.
///
/// Negative `i32` sign-extends to `i64` before varint encoding,
/// producing 10-byte varints.
#[inline]
#[expect(clippy::cast_sign_loss)]
pub fn encode_int32_field(buf: &mut Vec<u8>, field: u32, value: i32) {
    if value != 0 {
        encode_tag(buf, field, WIRE_VARINT);
        encode_varint(buf, value as i64 as u64);
    }
}

/// Encode an `int32` field unconditionally (even if zero).
#[inline]
#[expect(clippy::cast_sign_loss)]
pub fn encode_int32_field_always(buf: &mut Vec<u8>, field: u32, value: i32) {
    encode_tag(buf, field, WIRE_VARINT);
    encode_varint(buf, value as i64 as u64);
}

/// Encode a `uint32` field. Skips if `value == 0`.
#[inline]
pub fn encode_uint32_field(buf: &mut Vec<u8>, field: u32, value: u32) {
    if value != 0 {
        encode_tag(buf, field, WIRE_VARINT);
        encode_varint(buf, u64::from(value));
    }
}

/// Encode a `uint32` field unconditionally (even if zero).
#[inline]
pub fn encode_uint32_field_always(buf: &mut Vec<u8>, field: u32, value: u32) {
    encode_tag(buf, field, WIRE_VARINT);
    encode_varint(buf, u64::from(value));
}

/// Encode a `bool` field. Skips if `value == false`.
#[inline]
pub fn encode_bool_field(buf: &mut Vec<u8>, field: u32, value: bool) {
    if value {
        encode_tag(buf, field, WIRE_VARINT);
        buf.push(1);
    }
}

/// Encode a `bool` field unconditionally (even if false).
#[inline]
pub fn encode_bool_field_always(buf: &mut Vec<u8>, field: u32, value: bool) {
    encode_tag(buf, field, WIRE_VARINT);
    buf.push(u8::from(value));
}

/// Encode a length-delimited field (bytes, submessage, packed repeated).
///
/// Skips if `data` is empty.
#[inline]
pub fn encode_bytes_field(buf: &mut Vec<u8>, field: u32, data: &[u8]) {
    if !data.is_empty() {
        encode_tag(buf, field, WIRE_LEN);
        encode_varint(buf, data.len() as u64);
        buf.extend_from_slice(data);
    }
}

/// Encode a length-delimited field unconditionally (even if empty).
#[inline]
pub fn encode_bytes_field_always(buf: &mut Vec<u8>, field: u32, data: &[u8]) {
    encode_tag(buf, field, WIRE_LEN);
    encode_varint(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

/// Encode a `sint64` field. Skips if `value == 0`.
#[inline]
pub fn encode_sint64_field(buf: &mut Vec<u8>, field: u32, value: i64) {
    if value != 0 {
        encode_tag(buf, field, WIRE_VARINT);
        encode_varint(buf, zigzag_encode_64(value));
    }
}

/// Encode a `sint64` field unconditionally (even if zero).
#[inline]
pub fn encode_sint64_field_always(buf: &mut Vec<u8>, field: u32, value: i64) {
    encode_tag(buf, field, WIRE_VARINT);
    encode_varint(buf, zigzag_encode_64(value));
}

/// Encode a `sint32` field. Skips if `value == 0`.
#[inline]
pub fn encode_sint32_field(buf: &mut Vec<u8>, field: u32, value: i32) {
    if value != 0 {
        encode_tag(buf, field, WIRE_VARINT);
        encode_varint(buf, u64::from(zigzag_encode_32(value)));
    }
}

/// Encode a `sint32` field unconditionally (even if zero).
#[inline]
pub fn encode_sint32_field_always(buf: &mut Vec<u8>, field: u32, value: i32) {
    encode_tag(buf, field, WIRE_VARINT);
    encode_varint(buf, u64::from(zigzag_encode_32(value)));
}

/// Encode a `fixed32` field. Skips if `value == 0`.
#[inline]
pub fn encode_fixed32_field(buf: &mut Vec<u8>, field: u32, value: u32) {
    if value != 0 {
        encode_tag(buf, field, WIRE_32BIT);
        buf.extend_from_slice(&value.to_le_bytes());
    }
}

/// Encode a `fixed32` field unconditionally (even if zero).
#[inline]
pub fn encode_fixed32_field_always(buf: &mut Vec<u8>, field: u32, value: u32) {
    encode_tag(buf, field, WIRE_32BIT);
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Encode a `fixed64` field. Skips if `value == 0`.
#[inline]
pub fn encode_fixed64_field(buf: &mut Vec<u8>, field: u32, value: u64) {
    if value != 0 {
        encode_tag(buf, field, WIRE_64BIT);
        buf.extend_from_slice(&value.to_le_bytes());
    }
}

/// Encode a `fixed64` field unconditionally (even if zero).
#[inline]
pub fn encode_fixed64_field_always(buf: &mut Vec<u8>, field: u32, value: u64) {
    encode_tag(buf, field, WIRE_64BIT);
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Encode a `float` field. Skips if bit pattern is zero (positive `0.0`).
///
/// Note: `-0.0` has a non-zero bit pattern and will NOT be skipped.
#[inline]
pub fn encode_float_field(buf: &mut Vec<u8>, field: u32, value: f32) {
    if value.to_bits() != 0 {
        encode_tag(buf, field, WIRE_32BIT);
        buf.extend_from_slice(&value.to_le_bytes());
    }
}

/// Encode a `float` field unconditionally (even if zero).
#[inline]
pub fn encode_float_field_always(buf: &mut Vec<u8>, field: u32, value: f32) {
    encode_tag(buf, field, WIRE_32BIT);
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Encode a `double` field. Skips if bit pattern is zero (positive `0.0`).
///
/// Note: `-0.0` has a non-zero bit pattern and will NOT be skipped.
#[inline]
pub fn encode_double_field(buf: &mut Vec<u8>, field: u32, value: f64) {
    if value.to_bits() != 0 {
        encode_tag(buf, field, WIRE_64BIT);
        buf.extend_from_slice(&value.to_le_bytes());
    }
}

/// Encode a `double` field unconditionally (even if zero).
#[inline]
pub fn encode_double_field_always(buf: &mut Vec<u8>, field: u32, value: f64) {
    encode_tag(buf, field, WIRE_64BIT);
    buf.extend_from_slice(&value.to_le_bytes());
}

// ---------------------------------------------------------------------------
// Packed repeated field helpers
// ---------------------------------------------------------------------------

/// Encode a packed repeated `uint32` field.
pub fn encode_packed_uint32(buf: &mut Vec<u8>, scratch: &mut Vec<u8>, field: u32, values: &[u32]) {
    if values.is_empty() {
        return;
    }
    scratch.clear();
    for &v in values {
        encode_varint(scratch, u64::from(v));
    }
    encode_bytes_field(buf, field, scratch);
}

/// Encode a packed repeated `int32` field.
#[expect(clippy::cast_sign_loss)]
pub fn encode_packed_int32(buf: &mut Vec<u8>, scratch: &mut Vec<u8>, field: u32, values: &[i32]) {
    if values.is_empty() {
        return;
    }
    scratch.clear();
    for &v in values {
        encode_varint(scratch, v as i64 as u64);
    }
    encode_bytes_field(buf, field, scratch);
}

/// Encode a packed repeated `sint64` field (zigzag + varint).
pub fn encode_packed_sint64(buf: &mut Vec<u8>, scratch: &mut Vec<u8>, field: u32, values: &[i64]) {
    if values.is_empty() {
        return;
    }
    scratch.clear();
    for &v in values {
        encode_varint(scratch, zigzag_encode_64(v));
    }
    encode_bytes_field(buf, field, scratch);
}

/// Encode a packed repeated `sint32` field (zigzag + varint).
pub fn encode_packed_sint32(buf: &mut Vec<u8>, scratch: &mut Vec<u8>, field: u32, values: &[i32]) {
    if values.is_empty() {
        return;
    }
    scratch.clear();
    for &v in values {
        encode_varint(scratch, u64::from(zigzag_encode_32(v)));
    }
    encode_bytes_field(buf, field, scratch);
}

/// Encode a packed repeated `bool` field.
///
/// Bools are always exactly 1 byte on the wire, so this skips the scratch
/// buffer and writes directly - length is just `values.len()`.
pub fn encode_packed_bool(buf: &mut Vec<u8>, field: u32, values: &[bool]) {
    if values.is_empty() {
        return;
    }
    encode_tag(buf, field, WIRE_LEN);
    encode_varint(buf, values.len() as u64);
    for &v in values {
        buf.push(u8::from(v));
    }
}

// ---------------------------------------------------------------------------
// Unit tests of private implementations
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{count_packed_varints, count_packed_varints_scalar};

    /// Lengths swept at every offset: covers empty, every scalar tail length
    /// on its own, and several 16-byte chunks followed by every tail length.
    const MAX_LEN: usize = 80;
    /// Offsets into the backing buffer, so the slices start at every
    /// alignment within a 16-byte chunk.
    const MAX_OFFSET: usize = 16;

    fn reference(data: &[u8]) -> usize {
        data.iter().filter(|&&b| b < 0x80).count()
    }

    /// Xorshift32 byte stream; deterministic and dependency-free.
    fn random_bytes(len: usize, mut state: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            out.push(state.to_le_bytes()[0]);
        }
        out
    }

    /// Backing buffers of `MAX_OFFSET + MAX_LEN` bytes, one per pattern.
    fn patterns() -> Vec<Vec<u8>> {
        let n = MAX_OFFSET + MAX_LEN;
        let mut out = vec![
            vec![0x00; n],
            vec![0xFF; n],
            (0..n)
                .map(|i| if i % 2 == 0 { 0x80 } else { 0x7F })
                .collect(),
            random_bytes(n, 0x1234_5678),
            random_bytes(n, 0x9E37_79B9),
        ];
        // A lone terminal, and a lone continuation byte, at every position.
        for i in 0..n {
            let mut one_terminal = vec![0xFF; n];
            one_terminal[i] = 0x7F;
            out.push(one_terminal);
            let mut one_continuation = vec![0x00; n];
            one_continuation[i] = 0x80;
            out.push(one_continuation);
        }
        out
    }

    /// Long bodies: every lane of the vector loop saturated, and random.
    fn long_bodies() -> Vec<Vec<u8>> {
        vec![
            vec![0x00; 4099],
            vec![0xFF; 4099],
            random_bytes(4099, 0xDEAD_BEEF),
        ]
    }

    /// Run `check` on every length and offset of every pattern, then on the
    /// long bodies.
    fn sweep(check: impl Fn(&[u8])) {
        for buf in patterns() {
            for offset in 0..MAX_OFFSET {
                for len in 0..=MAX_LEN {
                    check(&buf[offset..offset + len]);
                }
            }
        }
        for body in long_bodies() {
            check(&body);
            check(&body[1..]);
        }
    }

    #[test]
    fn count_varints_scalar_matches_reference() {
        sweep(|data| {
            assert_eq!(
                count_packed_varints_scalar(data),
                reference(data),
                "{data:02x?}"
            );
        });
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn count_varints_sse2_matches_scalar() {
        sweep(|data| {
            // SAFETY: SSE2 is baseline on x86-64 - always available.
            let sse2 = unsafe { super::count_packed_varints_sse2(data) };
            assert_eq!(sse2, count_packed_varints_scalar(data), "{data:02x?}");
        });
    }

    #[test]
    fn count_varints_public_matches_scalar() {
        sweep(|data| {
            assert_eq!(
                count_packed_varints(data),
                count_packed_varints_scalar(data),
                "{data:02x?}"
            );
        });
    }
}
