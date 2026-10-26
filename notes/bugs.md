# Bugs

```
1. An entry is removed entirely when completely resolved. No historical record
   stays here.
2. Stable IDs never change and are never reused; removal leaves a gap.
3. An entry adjudicated against, verified incorrect, or whose outcome is that no
   action is taken owes comments at the code sites it names - and, where the
   claim touches a documented contract, the relevant `reference/` or `docs/`
   page - before the entry is removed, so the finding is not hunted again.
4. Once all findings are resolved, the file gets deleted.
5. Finding IDs are never written into the code or other documents. They are
   stable only until this document is drained; the next hunt writes new ones,
   and they are never deduplicated through git history. Carry the context
   inline instead.
```

Defects turned up by the verification hunt of 2026-10-26. Unverified: each is
what the hunters reported, and the fix pass decides. "Reported by" names the
hunter and scope (`codex/tests`, `opus/machinery` and so on).

## BUG-001 - `read_len_delimited` panics or misreads on a huge length prefix instead of returning `Err`

`Cursor::read_len_delimited` does `let len = self.read_varint()? as usize;`
then `if self.pos + len > self.data.len()`, then slices
`self.data[self.pos..self.pos + len]`.

- 64-bit, dev profile: a length varint near `u64::MAX` overflows the addition
  and panics ("attempt to add with overflow").
- 64-bit, release: the addition wraps to a small value, the bounds check
  passes, and the slice panics with an end before its start.
- 32-bit: `as usize` truncates. A length of `2^32 + 3` reads as 3, the check
  passes, a 3-byte slice is returned and decoding continues desynchronized: a
  silent wrong answer. The `cast_possible_truncation` allow on the function is
  the local exemption that hid this case (opus/tests).

`skip_field(WIRE_LEN)` and `read_raw_field(WIRE_LEN)` inherit it. It
contradicts AGENTS.md ("Use `WireResult<T>` / `WireError` for fallible
operations, not panics"), README ("rejects malformed sequences") and the
function's own error message. The hunters agree it is outside the
well-formed-data performance goal and not memory-unsafe; opus/machinery notes a
single corrupt byte in a PBF blob would abort pbfhogg or elivagar rather than
surface an error. No test feeds a length larger than the remaining input by
more than a few bytes (`read_raw_field_truncated_len_payload` uses 5 vs 2).

Proposed fix: `usize::try_from` (or compare the `u64` before narrowing) and
`len > self.remaining()`, plus a test with `encode_varint(u64::MAX)` as the
prefix. opus/machinery adds that `read_fixed32`, `read_fixed64` and the fixed
arms of `skip_field` use `self.pos + 4` / `+ 8`, which cannot overflow while
`pos <= len`, but `pos` can exceed `len` after a contract-violating
`read_varint_unchecked`; writing every bound as `n > self.remaining()` removes
the question.

Enforcement proposed: the regression test on 64-bit and (via Miri or a lane)
32-bit targets; `clippy::arithmetic_side_effects` scoped to the decoder
(opus/tests, opus/machinery); a `cargo fuzz` lane over `Cursor`
(opus/machinery); the Miri i686 lane proposed in `notes/verification.md` (the unsafe-code
entry) sees the 32-bit case once a
test feeds such a length (opus/brokkr-config).

Reported by: codex/tests, codex/machinery, opus/tests, opus/machinery,
opus/brokkr-config.

## BUG-002 - Packed iterators resume after returning `None` on a decode error

`PackedIter::next` returns `self.cursor.read_varint().ok()`. On the overflow
error the cursor has already advanced past the ten bad bytes, so the next
`next()` decodes from the following byte and can return `Some`. The iterator
is not fused and does not implement `FusedIterator`; the six typed wrappers
inherit this. The doc language ("errors are swallowed as None, ending
iteration") and `cumulative_stops_matches_packed_iter_on_overflow` (the
trailing value "should NOT be reached") both describe permanent stopping, but
the test uses `collect()`, which stops at the first `None`, so resumption is
never checked. `decode_packed_sint64_cumulative` stops for good, so the two
diverge here.

opus/tests adds that the two error kinds leave different observable state:
after a truncated tail `is_empty()` is true, after an overflow it is false.
codex/tests notes Rust permits non-fused iterators, so this is a mismatch with
the project's stopping language rather than a violation of `Iterator` itself.

Proposed fix: on error set the cursor to the end (or record termination),
implement `FusedIterator` on all seven iterator types, and expose error
detection explicitly if wanted (`fn errored(&self) -> bool` or a `try_`
iterator) rather than through `is_empty()` side effects (opus/tests).

Enforcement proposed: tests that call `next()` repeatedly after `None` for the
base iterator and every wrapper. The `FusedIterator` impl is a type-level
promise but does not enforce itself (codex/tests).

Reported by: codex/tests, codex/machinery, opus/tests.

## BUG-003 - `PackedIter::size_hint` lower bound is wrong on accepted malformed input

`size_hint` returns `(remaining / 10, Some(remaining))`; the comment says
"min elements = remaining / 10". That assumes valid varints, but the safe
constructor accepts any bytes and `next()` swallows errors. Ten `0x80` bytes
give a lower bound of 1 and yield nothing; twenty give 2. The typed wrappers
inherit it. Not unsound (no `TrustedLen`), but a broken `Iterator` contract on
exactly the inputs the type promises to tolerate.

The tests (`packed_iter_size_hint` and neighbours) lock in the arithmetic for
valid inputs, testing the formula rather than the contract (codex/tests).

Proposed fix: lower bound 0 for unvalidated data (a validated iterator type
could offer the stronger bound), or document the bound as valid-input only.

Enforcement proposed: a contract test asserting
`lower <= actual_count <= upper` over valid, truncated and overflowing inputs,
including partially consumed iterators (codex/tests, codex/machinery).

Reported by: codex/tests, codex/machinery, opus/tests, opus/machinery.
