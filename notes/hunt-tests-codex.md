The main weaknesses are incomplete assertions, coupled encoding and decoding tests, and packed-iterator contracts that the tests do not fully exercise. I found no environment-dependent test fixtures or shared mutable test state.

Nothing was edited. `brokkr check` stopped before validation because it could not open `/home/folk/.brokkr/brokkr.lock` on the read-only filesystem. The findings below come from source inspection. An existing check log records 156 passing tests in 929 ms; that is historical evidence, not a fresh result.

1. **`int64_field_positive` can pass without checking the value.**  
   In [wire.rs:734](/home/folk/Programs/protohoggr/tests/wire.rs:734), the value assertion runs only when the handwritten decoder encounters a terminal byte. Output containing just `[0x08]`, or a short unterminated payload, passes. Trailing bytes after a correct value also pass.

   Replace the loop with an unconditional exact-byte assertion: `5001` should produce `[0x08, 0x89, 0x27]`. This also removes a second decoder maintained inside the test. **Enforcement:** the corrected test, with mutation testing verifying that tag-only, unterminated, and trailing-byte outputs fail.

2. **The negative-int32 tests assert size rather than sign extension.**  
   [wire.rs:750](/home/folk/Programs/protohoggr/tests/wire.rs:750) accepts any eleven bytes. [wire.rs:882](/home/folk/Programs/protohoggr/tests/wire.rs:882) checks the packed header and total length but leaves all ten payload bytes unchecked. Both can pass with incorrect encoded values.

   Assert complete literal wire vectors, including the nine `0xFF` bytes and terminal `0x01` for `-1`. **Enforcement:** exact-byte tests. Existing roundtrips provide additional coverage but do not repair these individual claims.

3. **Roundtrips leave matching encoder and decoder mistakes invisible.**  
   Examples include packed fields at [wire.rs:892](/home/folk/Programs/protohoggr/tests/wire.rs:892), fixed-width fields at [wire.rs:1273](/home/folk/Programs/protohoggr/tests/wire.rs:1273), and slice encoding at [wire.rs:1679](/home/folk/Programs/protohoggr/tests/wire.rs:1679). These tests are useful, but they establish agreement between implementations, not independently correct protobuf bytes.

   The changelog already records exactly this failure mode: the previous sint32 encoder produced noncanonical ten-byte values that this crate decoded successfully. The new literal sint32 regression vectors address that case well.

   Use a shared, literal conformance corpus containing values, expected bytes, and expected consumed lengths. Run encoders and decoders independently against it. Include both sides of every seven-bit width boundary; the current “boundary sweep” omits several widths. **Enforcement:** corpus tests and mutation testing. No external protobuf runtime is needed during checks.

4. **Unsafe-decoder tests obtain their safety precondition from an encoder under test.**  
   [wire.rs:1752](/home/folk/Programs/protohoggr/tests/wire.rs:1752) and neighboring tests feed `encode_varint_to_slice` output directly into `read_varint_unchecked`. An encoder regression can therefore turn a test failure into an invalid unsafe call.

   Hand the unsafe decoder independently known valid byte vectors. Separately, the slice encoder's sole safety requirement is a buffer of at least ten bytes: accepting `&mut [u8; 10]` would make that requirement structural and allow a safe public function. **Enforcement:** the signature, independent fixtures, and a Miri validation lane for unsafe implementation behavior. Ordinary successful test execution does not establish memory safety.

5. **“Ending iteration” is not permanent after a packed decoding error.**  
   [PackedIter::next](/home/folk/Programs/protohoggr/src/lib.rs:458) converts an error to `None` without recording termination. Given an overflowing ten-byte varint followed by a valid value, one call returns `None` and the next can return `Some`.

   [wire.rs:1653](/home/folk/Programs/protohoggr/tests/wire.rs:1653) says the later valid value “should NOT be reached,” but uses `collect()`, which stops at the first `None`. It never checks resumption. Rust permits non-fused iterators, so this is a mismatch with the project's stopping language, not inherently a violation of `Iterator`.

   If permanent stopping is intended, clear the remaining input or record termination, then implement `FusedIterator`. **Enforcement:** explicitly call `next()` repeatedly after failure for the base iterator and wrappers. Implementing the marker trait alone does not enforce its promise.

6. **`size_hint()` gives an invalid lower bound for accepted malformed input.**  
   [src/lib.rs:471](/home/folk/Programs/protohoggr/src/lib.rs:471) returns `remaining / 10`. Ten continuation bytes therefore advertise at least one element, while the first `next()` returns `None`. A public safe constructor accepts that slice.

   The tests at [wire.rs:276](/home/folk/Programs/protohoggr/tests/wire.rs:276) instead lock in the arithmetic for valid inputs. They test the implementation formula rather than the iterator contract.

   Return a conservative lower bound of zero unless validity is structurally guaranteed. **Enforcement:** test `lower <= actual_count <= upper` over valid, truncated, and overflowing inputs, including partially consumed iterators. This also frees implementations to improve their hints without rewriting behaviorally unnecessary assertions.

7. **Several documented conversion and error behaviors have no direct regression guard.**  
   The suite tests wider-varint truncation for sint32, but not the corresponding documented behavior of `PackedUint32Iter` and `PackedInt32Iter`. The uint32 roundtrip only supplies values that already fit. `PackedInt64Iter` is directly tested only with nonnegative values, and `PackedBoolIter` only with canonical zero and one.

   Missing direct vectors include:
   - Wider raw varints truncating to uint32 and int32.
   - Negative packed int64 values.
   - Nonzero bool values other than one, including multibyte varints.
   - Reserved wire types passing through `read_tag`.
   - Truncated packed tails and cumulative decoding stopping on truncation.

   **Enforcement:** literal input/output tables, including following sentinel values to verify complete consumption. These are checkable compatibility claims, not a request for comprehensive adversarial validation.

8. **Buffer ownership is explicit, but reuse behavior is barely tested.**  
   Packed encoders receive caller-owned scratch buffers, yet all their tests start with empty scratch. Removing `scratch.clear()` could leave these tests passing while ordinary repeated use becomes wrong. Empty-field tests also start with empty output, so an implementation that clears existing output could pass.

   Exercise consecutive encodes with dirty scratch and preexisting output. Test empty input between nonempty calls. Decide and document whether scratch contents after an empty call are meaningful; the implementation currently preserves them. **Enforcement:** reusable append/preserve-prefix tests across every encoder family. No allocator instrumentation is needed for these correctness properties.

9. **Some encoder branches are not exercised at all.**  
   Examples include zero omission for `encode_int32_field` and `encode_uint32_field`; empty packed int32/sint64/sint32 fields; and nonzero values through the default fixed32/fixed64 encoders. Testing an `_always` variant does not establish the corresponding default variant's nonzero branch.

   **Enforcement:** a table or small macro requiring default-zero, default-nonzero, always-zero, and always-nonzero cases for each applicable family. Keep expected wire bytes independent of the implementation. This avoids maintaining an informal coverage checklist separately.

10. **Zero-copy and exact floating-point preservation are incompletely demonstrated.**  
    [wire.rs:341](/home/folk/Programs/protohoggr/tests/wire.rs:341) and raw-field tests compare slice contents, but never establish that returned storage is the appropriate region of the original input. Content equality alone does not prove zero-copy behavior.

    Float readers use approximate comparison, while NaN roundtrips assert only `is_nan()`. NaN payload destruction would pass.

    **Enforcement:** pointer-and-length assertions for borrowed slices; literal IEEE bit patterns and `to_bits()` comparisons for floats, including distinct NaN payloads and signed zero. The borrowing signatures already provide useful lifetime enforcement, but do not by themselves establish slice provenance.

11. **A small test comment claims behavior it never checks.**  
    [wire.rs:215](/home/folk/Programs/protohoggr/tests/wire.rs:215) correctly provides a compile-time check that `WireError` implements `std::error::Error`. Its comment also mentions `source()` returning `None`, but never calls it.

    The trait check is meaningful and should remain. Either remove the extra claim or assert it. **Enforcement:** a direct `source().is_none()` assertion if that is an intended contract. No runtime test is needed merely to prove trait implementation.

12. **Length handling has a host-width-dependent bug outside the tested cases.**  
    [src/lib.rs:291](/home/folk/Programs/protohoggr/src/lib.rs:291) casts a decoded u64 length to `usize`, then adds it to the cursor position without checked arithmetic.

    On 32-bit hosts, a declared length of `2^32` truncates to zero and can be accepted as an empty field. On 64-bit hosts, a length of `u64::MAX` overflows the addition and panics; release wrapping still leads to an invalid slice range. Existing truncation tests only use small lengths.

    This is malformed-input behavior, so it does not undermine the stated well-formed-data optimization goal. It does expose an untested panic/wrong-answer boundary in a fallible safe API. **Enforcement:** `usize::try_from`, comparison against remaining bytes before addition, and regression tests on 32-bit and 64-bit targets.

13. **Architecture coverage silently changes with the host.**  
    [src/lib.rs:798](/home/folk/Programs/protohoggr/src/lib.rs:798) compiles either SSE2 counting or the scalar fallback. An x86-64 check never compiles the fallback; another architecture never exercises SSE2. SSE2's baseline availability on x86-64 is sound.

    Existing SIMD-length tests cover 17 and 32 bytes, but not a mixed continuation-byte tail after a vector chunk or deliberately offset subslices.

    Keep the scalar implementation available as an independently callable reference and compare both implementations over deterministic lengths, offsets, and byte patterns. **Enforcement:** differential tests plus a non-x86 execution lane. Report which backend actually ran. This addresses silent coverage loss without adding runtime architecture dependencies to the fixtures.

14. **Benchmark-only dependencies enlarge ordinary integration-test preparation.**  
    [Cargo.toml:55](/home/folk/Programs/protohoggr/Cargo.toml:55) places Criterion, HTML reporting, and varint-simd in this package's dev-dependency graph, although `wire.rs` uses none of them. Test preparation must resolve/build that graph on a cold build, and the historical check invokes clippy with `--all-targets`, including the benchmark.

    Move benchmarks into a separate workspace package with their own dependencies. Keep the standard library check independent, and give benchmark validation an explicit separate check. **Enforcement:** package dependency boundaries and a metadata rule forbidding benchmark dependencies in the library package.

    The runtime library is dependency-free today; that claim should not be confused with a dependency-free verification build. Cold-build cost was not measurable in this session.

15. **The harness repeats preparation work and serializes independent tests.**  
    The existing [check log](/home/folk/Programs/protohoggr/.brokkr/check-logs/check-001792993691821.log) records test preparation using `test --no-run`, another `--no-run` in the test phase, and then a build-tool test invocation with `--test-threads=1`.

    This is repeated preparation, not evidence of three full recompilations. The recorded run spent 364 ms in preparation and 306 ms in the test phase, including 30 ms reported for building test binaries, within 929 ms total. Those totals do not isolate the avoidable fraction.

    Prepare once, discover and record the resulting executable artifacts, then execute those exact artifacts. These tests have no apparent reason to require serial scheduling, though parallel scheduling may offer little benefit for such tiny bodies. **Enforcement:** harness tests asserting one preparation per configuration and exact artifact reuse; measure before choosing thread policy.

16. **Durable claims and text checks have visible gaps.**  
    - [README.md:27](/home/folk/Programs/protohoggr/README.md:27) says *all* encoding functions skip zero/empty/false by default. `encode_varint(0)`, slice encoding, and zigzag encoding plainly do not. Restrict the statement to applicable field encoders. **Enforcement:** behavioral tables; prose accuracy itself still needs review.
    - The README manually duplicates the public API inventory. Generate that inventory from rustdoc, or leave exhaustive enumeration to generated API documentation. **Enforcement:** generation with a stale-output check.
    - [src/lib.rs:104](/home/folk/Programs/protohoggr/src/lib.rs:104) and the encoding performance comments cite a transient `notes/SIMD.md` in another project. Bring the supporting benchmark methodology and historical measurements into `reference/performance.md`. **Enforcement:** a durable-to-transient link rule; historical performance claims require recorded evidence and controlled benchmarking, not fixed speed assertions on arbitrary hosts.
    - [wire.rs:648](/home/folk/Programs/protohoggr/tests/wire.rs:648) contains two literal U+FFFD replacement characters. The historical gremlins check passed; the inspected checker uses a selected Unicode denylist rather than an ASCII-only policy. **Enforcement:** ban U+FFFD explicitly, or enforce the intended character policy directly.

The suite otherwise has a clean isolation model: one automatically discovered integration-test file, local buffers, no sleeps, child processes, filesystem writes, environment mutation, global loggers, or hidden binary builds. There is no evidence here for introducing clock injection, fixture directories, process isolation, or a large test-framework rewrite.
