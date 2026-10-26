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
