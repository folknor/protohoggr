//! Zero-copy protobuf wire-format primitives.
//!
//! Provides varint encoding/decoding, zigzag encoding/decoding, a cursor-based
//! decoder, field-level encoders, and packed repeated field helpers. No external
//! dependencies — pure Rust, no std beyond default.

use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// An error that occurs when decoding protobuf wire format.
#[derive(Debug)]
pub struct WireError {
    /// Static error message describing the failure.
    pub msg: &'static str,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wire format error: {}", self.msg)
    }
}

impl std::error::Error for WireError {}

/// A type alias for `Result<T, WireError>`.
pub type WireResult<T> = Result<T, WireError>;

#[cold]
fn wire_error(msg: &'static str) -> WireError {
    WireError { msg }
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
// Cursor — zero-copy reader over a byte slice
// ---------------------------------------------------------------------------

/// Zero-copy cursor for reading protobuf wire format from a byte slice.
#[derive(Clone, Debug)]
pub struct Cursor<'a> {
    data: &'a [u8],
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

    /// Read a varint (LEB128). Fast path for single-byte values.
    ///
    /// This scalar implementation intentionally does NOT use SIMD. Benchmarked
    /// (criterion, 8000 packed sint64, varint-simd v0.4.1 SSSE3): scalar is
    /// 2.3× faster than SIMD batch4 decode for 1-byte varints (the dominant
    /// OSM case — dense node id/lat/lon deltas) and tied for 3-byte varints.
    /// The 1-byte fast path below is perfectly predicted by the CPU branch
    /// predictor, beating SSE shuffle + mask overhead. See `notes/SIMD.md` in
    /// pbfhogg (dd7f69a) for the full research doc (P3-20, closed).
    #[inline]
    pub fn read_varint(&mut self) -> WireResult<u64> {
        if self.pos >= self.data.len() {
            return Err(wire_error("unexpected end of input reading varint"));
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
                return Err(wire_error("truncated varint"));
            }
            let b = self.data[self.pos];
            self.pos += 1;
            if shift == 63 {
                // 10th byte: only the low bit is valid payload for a u64.
                if b > 1 {
                    return Err(wire_error("varint overflows u64"));
                }
                val |= u64::from(b) << 63;
                return Ok(val);
            }
            val |= u64::from(b & 0x7F) << shift;
            if b < 0x80 {
                return Ok(val);
            }
            shift += 7;
            if shift > 63 {
                return Err(wire_error("varint too long"));
            }
        }
    }

    /// Read a varint (LEB128) without bounds or validity checks. Infallible.
    ///
    /// This is the **unchecked decoding** counterpart to
    /// [`read_varint`](Cursor::read_varint): both bounds checks (slice end)
    /// and value-shape checks (overflow, overlong) are removed. The caller is
    /// responsible for ensuring the data is well-formed — this is not merely
    /// "unchecked bounds."
    ///
    /// # Safety
    ///
    /// The caller must ensure that at the current position there exists a
    /// complete, well-formed varint:
    ///
    /// 1. At least one byte with MSB=0 (terminal) exists before the end of
    ///    the underlying slice.
    /// 2. The varint is at most 10 bytes and does not overflow `u64` (if a
    ///    10th byte is present, it must be `<= 1`).
    ///
    /// Violating condition 1 causes an out-of-bounds read (UB). Violating
    /// condition 2 produces an unspecified value (not UB, but meaningless).
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub unsafe fn read_varint_unchecked(&mut self) -> u64 {
        // SAFETY: caller guarantees a valid varint at pos.
        let b = unsafe { *self.data.get_unchecked(self.pos) };
        self.pos += 1;
        if b < 0x80 {
            return u64::from(b);
        }
        // SAFETY: caller guarantees completeness — slow path won't read OOB.
        unsafe { self.read_varint_unchecked_slow(u64::from(b & 0x7F)) }
    }

    #[cold]
    #[allow(clippy::cast_possible_truncation)]
    unsafe fn read_varint_unchecked_slow(&mut self, mut val: u64) -> u64 {
        let mut shift: u32 = 7;
        loop {
            // SAFETY: caller of read_varint_unchecked guarantees a terminal
            // byte exists before end of slice.
            let b = unsafe { *self.data.get_unchecked(self.pos) };
            self.pos += 1;
            val |= u64::from(b & 0x7F) << shift;
            if b < 0x80 {
                return val;
            }
            shift += 7;
        }
    }

    /// Read a varint and validate it fits in a `u32`.
    #[inline]
    pub fn read_varint_u32(&mut self) -> WireResult<u32> {
        let v = self.read_varint()?;
        if v > u64::from(u32::MAX) {
            return Err(wire_error("varint overflows u32"));
        }
        #[allow(clippy::cast_possible_truncation)]
        Ok(v as u32)
    }

    /// Read a varint and reinterpret as `i64`.
    #[inline]
    pub fn read_varint_i64(&mut self) -> WireResult<i64> {
        #[allow(clippy::cast_possible_wrap)]
        Ok(self.read_varint()? as i64)
    }

    /// Read a zigzag-encoded `sint64` value.
    #[inline]
    pub fn read_sint64(&mut self) -> WireResult<i64> {
        let v = self.read_varint()?;
        Ok(zigzag_decode_64(v))
    }

    /// Read a zigzag-encoded `sint32` value.
    #[inline]
    pub fn read_sint32(&mut self) -> WireResult<i32> {
        let v = self.read_varint()?;
        Ok(zigzag_decode_32(v))
    }

    /// Read a little-endian 32-bit fixed-width value.
    #[inline]
    pub fn read_fixed32(&mut self) -> WireResult<u32> {
        if self.pos + 4 > self.data.len() {
            return Err(wire_error("unexpected end of input reading fixed32"));
        }
        let bytes: [u8; 4] = [
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ];
        self.pos += 4;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Read a little-endian 64-bit fixed-width value.
    #[inline]
    pub fn read_fixed64(&mut self) -> WireResult<u64> {
        if self.pos + 8 > self.data.len() {
            return Err(wire_error("unexpected end of input reading fixed64"));
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(bytes))
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
    /// Reserved/invalid wire types (3, 4, 6, 7) are returned as-is —
    /// validation is left to the caller or to `skip_field`, which will
    /// reject unknown types. This keeps the hot path branch-free.
    #[inline]
    pub fn read_tag(&mut self) -> WireResult<Option<(u32, u32)>> {
        if self.is_empty() {
            return Ok(None);
        }
        let v = self.read_varint_u32()?;
        let field = v >> 3;
        if field == 0 {
            return Err(wire_error("tag has field number 0"));
        }
        Ok(Some((field, v & 0x7)))
    }

    /// Read a length-delimited field, returning the sub-slice.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub fn read_len_delimited(&mut self) -> WireResult<&'a [u8]> {
        let len = self.read_varint()? as usize;
        if self.pos + len > self.data.len() {
            return Err(wire_error("length-delimited field extends past end"));
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    /// Skip a varint by scanning for the terminating byte (MSB=0)
    /// without decoding the value.
    ///
    /// Note: this intentionally has no length limit — it will skip varints
    /// longer than 10 bytes. This is a raw byte scanner for speed, not a
    /// value decoder. For trusted protobuf data (our use case), varints are
    /// always well-formed. Use `read_varint` when overflow validation matters.
    #[inline]
    pub fn skip_varint(&mut self) -> WireResult<()> {
        loop {
            if self.pos >= self.data.len() {
                return Err(wire_error("unexpected end of input skipping varint"));
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
    /// The tag is NOT included — the caller already has it from `read_tag()`.
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
                if self.pos + 8 > self.data.len() {
                    return Err(wire_error("unexpected end of input skipping 64-bit"));
                }
                self.pos += 8;
            }
            WIRE_LEN => {
                self.read_len_delimited()?;
            }
            WIRE_32BIT => {
                if self.pos + 4 > self.data.len() {
                    return Err(wire_error("unexpected end of input skipping 32-bit"));
                }
                self.pos += 4;
            }
            _ => return Err(wire_error("unknown wire type")),
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
    #[allow(clippy::cast_possible_wrap)]
    let signed = (v >> 1) as i64;
    #[allow(clippy::cast_possible_wrap)]
    let sign = -((v & 1) as i64);
    signed ^ sign
}

/// Zigzag-decode a `u64` varint into a signed `i32` (truncates to 32 bits first).
///
/// Intentionally truncates without validation — `sint32` varints are at most
/// 5 bytes on the wire, and in valid protobuf data the upper bits are always
/// zero. Checking would add overhead on every packed element for a case that
/// doesn't occur with well-formed data.
#[inline]
#[must_use]
pub fn zigzag_decode_32(v: u64) -> i32 {
    #[allow(clippy::cast_possible_truncation)]
    let v32 = v as u32;
    #[allow(clippy::cast_possible_wrap)]
    let signed = (v32 >> 1) as i32;
    #[allow(clippy::cast_possible_wrap)]
    let sign = -((v32 & 1) as i32);
    signed ^ sign
}

// ---------------------------------------------------------------------------
// Packed field iterators
// ---------------------------------------------------------------------------

/// Base packed varint iterator. Yields raw `u64` values.
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

    /// Returns `true` if no bytes remain.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cursor.is_empty()
    }

    /// Returns the number of undecoded bytes remaining.
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
        self.cursor.read_varint().ok()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.cursor.remaining();
        // Each varint is 1-10 bytes, so:
        // min elements = remaining / 10 (all 10-byte varints)
        // max elements = remaining (all 1-byte varints)
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

    /// Returns `true` if no bytes remain.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of undecoded bytes remaining.
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

    /// Returns `true` if no bytes remain.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of undecoded bytes remaining.
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
        self.0.next().map(zigzag_decode_32)
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

    /// Returns `true` if no bytes remain.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of undecoded bytes remaining.
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
        #[allow(clippy::cast_possible_wrap)]
        self.0.next().map(|v| v as i64)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

/// Packed iterator yielding `i32` values (`int32`).
///
/// Truncates each `u64` varint to `i32` without overflow validation.
/// Valid `int32` packed fields never contain varints exceeding 32-bit
/// range, so checking would add per-element overhead for a case that
/// doesn't occur with well-formed data.
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

    /// Returns `true` if no bytes remain.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of undecoded bytes remaining.
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
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        self.0.next().map(|v| v as i32)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

/// Packed iterator yielding `u32` values (`uint32`).
///
/// Truncates each `u64` varint to `u32` without overflow validation.
/// Valid `uint32` packed fields never contain varints exceeding 32-bit
/// range, so checking would add per-element overhead for a case that
/// doesn't occur with well-formed data.
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

    /// Returns `true` if no bytes remain.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of undecoded bytes remaining.
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
        #[allow(clippy::cast_possible_truncation)]
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

    /// Returns `true` if no bytes remain.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of undecoded bytes remaining.
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

// ---------------------------------------------------------------------------
// Batch packed-field operations
// ---------------------------------------------------------------------------

/// Count the number of varints in a packed field by counting terminal bytes
/// (bytes with the high bit clear, `b & 0x80 == 0`).
///
/// This counts terminal bytes, not necessarily complete varints. A truncated
/// final varint (no terminal byte) is simply not counted. This matches the
/// intended use: counting elements in a length-delimited packed field that
/// was already validated by the enclosing message framing.
#[inline]
#[must_use]
pub fn count_packed_varints(data: &[u8]) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: SSE2 is baseline on x86-64 — always available.
        unsafe { count_packed_varints_sse2(data) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        count_packed_varints_scalar(data)
    }
}

/// Scalar fallback: count bytes where `b < 0x80`.
#[cfg(not(target_arch = "x86_64"))]
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
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn count_packed_varints_sse2(data: &[u8]) -> usize {
    #[cfg(target_arch = "x86_64")]
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
        #[allow(clippy::cast_sign_loss)]
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
/// Mirrors [`PackedSint64Iter`] semantics: decode errors (truncated tail) are
/// silently swallowed, ending iteration. This is a batch operation for trusted
/// wire data, not a strict validator.
///
/// Accumulation uses wrapping `i64` addition — no overflow checks.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
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
                // Truncated varint — stop silently (packed iterator semantics).
                return;
            }
            let b = data[pos];
            pos += 1;
            if shift == 63 {
                // 10th byte: only the low bit is valid for u64. If b > 1,
                // this is an overflow — stop silently, matching PackedIter
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
            if shift > 63 {
                // Overlong varint — stop silently.
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
#[allow(clippy::cast_possible_truncation)]
pub fn encode_varint(buf: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buf.push((value as u8) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

/// Encode a `u64` as a variable-length integer (LEB128) into a pre-allocated
/// slice, returning the number of bytes written.
///
/// Includes a branchless fast path for 1-byte (`< 128`) and 2-byte
/// (`< 16384`) values, covering ~95% of zigzag-encoded OSM way-ref deltas.
///
/// # Safety
///
/// Caller must ensure `buf.len() >= 10`.
#[inline]
#[allow(clippy::cast_possible_truncation)]
pub unsafe fn encode_varint_to_slice(buf: &mut [u8], value: u64) -> usize {
    // 1-byte fast path: value < 128
    if value < 0x80 {
        // SAFETY: caller guarantees buf.len() >= 10.
        unsafe { *buf.get_unchecked_mut(0) = value as u8 };
        return 1;
    }
    // 2-byte fast path: value < 16384
    if value < 0x4000 {
        // SAFETY: caller guarantees buf.len() >= 10.
        unsafe {
            *buf.get_unchecked_mut(0) = (value as u8) | 0x80;
            *buf.get_unchecked_mut(1) = (value >> 7) as u8;
        }
        return 2;
    }
    // General path for values >= 16384.
    let mut value = value;
    let mut i = 0usize;
    while value >= 0x80 {
        // SAFETY: caller guarantees buf.len() >= 10, and a u64 varint is at most 10 bytes.
        unsafe { *buf.get_unchecked_mut(i) = (value as u8) | 0x80 };
        value >>= 7;
        i += 1;
    }
    // SAFETY: i < 10 at this point.
    unsafe { *buf.get_unchecked_mut(i) = value as u8 };
    i + 1
}

/// Zigzag-encode a signed 64-bit integer for `sint64` fields.
///
/// Maps: 0 → 0, -1 → 1, 1 → 2, -2 → 3, 2 → 4, …
#[inline]
#[must_use]
#[allow(clippy::cast_sign_loss)]
pub fn zigzag_encode_64(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

/// Zigzag-encode a signed 32-bit integer for `sint32` fields.
#[inline]
#[must_use]
#[allow(clippy::cast_sign_loss)]
pub fn zigzag_encode_32(v: i32) -> u64 {
    ((v << 1) ^ (v >> 31)) as u64
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
    assert!(field > 0 && field <= 0x1FFF_FFFF, "field number out of range");
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
#[allow(clippy::cast_sign_loss)]
pub fn encode_int64_field(buf: &mut Vec<u8>, field: u32, value: i64) {
    if value != 0 {
        encode_tag(buf, field, WIRE_VARINT);
        encode_varint(buf, value as u64);
    }
}

/// Encode an `int64` field unconditionally (even if zero).
#[inline]
#[allow(clippy::cast_sign_loss)]
pub fn encode_int64_field_always(buf: &mut Vec<u8>, field: u32, value: i64) {
    encode_tag(buf, field, WIRE_VARINT);
    encode_varint(buf, value as u64);
}

/// Encode an `int32` field. Skips if `value == 0`.
///
/// Negative `i32` sign-extends to `i64` before varint encoding,
/// producing 10-byte varints.
#[inline]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn encode_int32_field(buf: &mut Vec<u8>, field: u32, value: i32) {
    if value != 0 {
        encode_tag(buf, field, WIRE_VARINT);
        encode_varint(buf, value as i64 as u64);
    }
}

/// Encode an `int32` field unconditionally (even if zero).
#[inline]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
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
#[allow(clippy::cast_possible_truncation)]
pub fn encode_bytes_field(buf: &mut Vec<u8>, field: u32, data: &[u8]) {
    if !data.is_empty() {
        encode_tag(buf, field, WIRE_LEN);
        encode_varint(buf, data.len() as u64);
        buf.extend_from_slice(data);
    }
}

/// Encode a length-delimited field unconditionally (even if empty).
#[inline]
#[allow(clippy::cast_possible_truncation)]
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
        encode_varint(buf, zigzag_encode_32(value));
    }
}

/// Encode a `sint32` field unconditionally (even if zero).
#[inline]
pub fn encode_sint32_field_always(buf: &mut Vec<u8>, field: u32, value: i32) {
    encode_tag(buf, field, WIRE_VARINT);
    encode_varint(buf, zigzag_encode_32(value));
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
pub fn encode_packed_uint32(
    buf: &mut Vec<u8>,
    scratch: &mut Vec<u8>,
    field: u32,
    values: &[u32],
) {
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
#[allow(clippy::cast_sign_loss)]
pub fn encode_packed_int32(
    buf: &mut Vec<u8>,
    scratch: &mut Vec<u8>,
    field: u32,
    values: &[i32],
) {
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
pub fn encode_packed_sint64(
    buf: &mut Vec<u8>,
    scratch: &mut Vec<u8>,
    field: u32,
    values: &[i64],
) {
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
pub fn encode_packed_sint32(
    buf: &mut Vec<u8>,
    scratch: &mut Vec<u8>,
    field: u32,
    values: &[i32],
) {
    if values.is_empty() {
        return;
    }
    scratch.clear();
    for &v in values {
        encode_varint(scratch, zigzag_encode_32(v));
    }
    encode_bytes_field(buf, field, scratch);
}

/// Encode a packed repeated `bool` field.
///
/// Bools are always exactly 1 byte on the wire, so this skips the scratch
/// buffer and writes directly — length is just `values.len()`.
#[allow(clippy::cast_possible_truncation)]
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
