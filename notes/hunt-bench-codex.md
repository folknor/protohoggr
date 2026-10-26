The benchmark supports a much narrower conclusion than the source and changelog claim. It also has no correctness gate: incorrect output, early termination, and incomplete comparisons can all produce successful benchmark runs.

No files were changed. This was a read-only investigation of the repository, cached dependency sources, brokkr implementation, and existing check logs. I did not run a new check or collect new timings.

The findings below are unranked.

1. **Encoding compares different operations.** [benches/varint.rs:259](/home/folk/Programs/protohoggr/benches/varint.rs:259)

   The scalar case calls `encode_packed_sint64`: zigzag encoding, varint encoding into scratch, field tag and length encoding, then copying the body into the destination. The SIMD case writes only zigzag varints into a slice.

   Per iteration, scalar therefore copies an additional 8,000 or 20,800 body bytes and writes a field header. This cannot establish the relative speed of the underlying varint encoders, as claimed beside `encode_varint`.

   **Fix and enforcement:** Provide separate comparisons for raw varints and complete packed fields, with identical output contracts. Validate byte-for-byte equality outside timing. A shared adapter signature and correctness tests can enforce equal work.

2. **The SIMD encoder's bytes are never made observable.** [benches/varint.rs:273](/home/folk/Programs/protohoggr/benches/varint.rs:273)

   Scalar passes its output buffer to `black_box`; SIMD passes only `pos`. Its output bytes are neither checked nor consumed. This leaves room for the optimizer to eliminate stores while retaining length calculations. I have not established that the current compiler does so, but the benchmark does not prevent it.

   **Fix and enforcement:** Pass the written output slice through the same observation mechanism for both implementations. Centralize that in the benchmark adapter, and separately test the bytes. Exact optimizer behavior still needs generated-code inspection when interpreting unusually large differences.

3. **Decode failures silently become better throughput.** [benches/varint.rs:92](/home/folk/Programs/protohoggr/benches/varint.rs:92)

   Every SIMD safe-decode loop breaks on error. Scalar iteration also silently terminates on decoding errors. No case checks decoded values, element count, or complete byte consumption. The expected values returned by fixture construction are discarded.

   Nevertheless, throughput always advertises 8,000 elements. A regression that decodes fewer values can look faster and pass.

   **Fix and enforcement:** Run each exact benchmark adapter once against expected values before timing. Require exact count and consumption; reject errors. Derive throughput from the validated fixture. Wire these validations into the standard check as ordinary tests.

4. **The historical tail fix has no regression guard.** [CHANGELOG.md](/home/folk/Programs/protohoggr/CHANGELOG.md), [benches/varint.rs:105](/home/folk/Programs/protohoggr/benches/varint.rs:105)

   The changelog says all strategies now decode the same values. The current loops appear to cover the present valid fixtures, but nothing asserts that claim. There are three separately maintained batch/tail loops, using padded slices for tails. Padding can mask an accidentally incomplete final varint.

   **Fix and enforcement:** Share batch/tail adapters between validation and timing. Test lengths around batch boundaries, including nonmultiples of two and four, and verify that padding never becomes logical input. Keep intentional padding behind a fixture type carrying the logical length.

5. **The advertised large dataset is mislabeled.** [benches/varint.rs:67](/home/folk/Programs/protohoggr/benches/varint.rs:67)

   Its comment says “3-5 byte varints”; its benchmark ID says `large_3B`. Actual zigzag widths are:

   | Width | Values per iteration |
   |---|---:|
   | 2 bytes | 3,200 |
   | 3 bytes | 4,800 |
   | 4 or 5 bytes | 0 |

   The body is 20,800 bytes. Thus a claim about performance “for 3-byte varints” is not what this case measures.

   **Fix and enforcement:** Generate exact-width cases and assert their widths. For mixed workloads, derive labels and histograms from fixture metadata instead of maintaining descriptions separately.

6. **The fixtures do not establish the OSM distribution claims.** [benches/varint.rs:62](/home/folk/Programs/protohoggr/benches/varint.rs:62), [src/lib.rs:953](/home/folk/Programs/protohoggr/src/lib.rs:953)

   Two ten-value patterns repeat 800 times. They provide predictable, repeatedly reused inputs, not evidence that these patterns represent dense-node coordinates or way references.

   The source and changelog also claim that values below 16,384 cover approximately 95% of zigzag-encoded OSM way-reference deltas. There is no supporting corpus or measurement here. Only 40% of the benchmark's purported way-reference fixture falls below that threshold. That does not disprove the real-world percentage; it establishes that this fixture cannot support it.

   **Fix and enforcement:** Retain synthetic cases with explicit distributions, and add a versioned representative corpus or reproducible corpus summary with provenance. Counts and histograms are mechanically checkable. Representativeness requires a documented sampling argument and human review.

7. **Performance conclusions overreach their evidence.** [src/lib.rs:94](/home/folk/Programs/protohoggr/src/lib.rs:94), [src/lib.rs:936](/home/folk/Programs/protohoggr/src/lib.rs:936), [CHANGELOG.md](/home/folk/Programs/protohoggr/CHANGELOG.md)

   Durable claims include:

   - Scalar decode is 2.3 times faster for one-byte values and tied for three-byte values.
   - Scalar encode is 3.5 and 1.5 times faster.
   - The changelog summarizes decode wins of 2-6 times.
   - The branch predictor “perfectly” predicts the single-byte fast path.

   No retained results in this repository identify the hardware, compiler, flags, confidence intervals, or exact benchmark revision supporting those numbers. The encoding comparison is unequal, and the three-byte case is mixed-width. The decoder benchmark measures iterator traversal plus zigzag decoding, rather than an isolated `read_varint` call.

   Both source comments defer to `notes/SIMD.md` in another project. That makes transient external material the explanation for a durable implementation decision.

   **Fix and enforcement:** Put qualified measurements and methodology in `reference/performance.md`, with immutable result references. Require numeric claims to reference result records mechanically. Performance thresholds can run on a designated host; universal speed ratios and perfect prediction cannot be guaranteed by a portable build.

8. **“Branchless” is not established by the implementation or benchmark.** [src/lib.rs:953](/home/folk/Programs/protohoggr/src/lib.rs:953), [CHANGELOG.md](/home/folk/Programs/protohoggr/CHANGELOG.md)

   `encode_varint_to_slice` contains explicit conditional branches for the one- and two-byte paths. Whether a compiler lowers them without branches depends on the target and compiler. This benchmark does not exercise that function at all. It also omits performance measurements for `read_varint_unchecked`, `count_packed_varints`, and cumulative packed decoding.

   **Fix and enforcement:** Describe the source-level behavior as specialized fast paths, and benchmark the production entry points whose performance motivates their existence. Machine-code claims need target-specific disassembly checks. Correctness tests alone do not establish a performance payoff.

9. **A portable library's ordinary check depends on ambient SSSE3 configuration.** [Cargo.toml:62](/home/folk/Programs/protohoggr/Cargo.toml:62), [benches/varint.rs:118](/home/folk/Programs/protohoggr/benches/varint.rs:118)

   Cached `varint-simd` 0.4.1 exposes batch decoding only under compile-time `target_feature = "ssse3"`. The benchmark calls those functions unconditionally. Baseline x86-64 does not imply SSSE3; without enabling it, the benchmark fails to compile. The dependency also uses x86 SIMD types without a portable architecture fallback.

   This machine's user Cargo configuration supplies `-Ctarget-cpu=native`, explaining why the dependency can work here. Existing check logs show brokkr uses `clippy --all-targets`, so this assumption affects the normal check, not just benchmark execution.

   **Fix and enforcement:** Isolate the comparison dependency in a dedicated benchmark package, leaving portable library checks independent. Give the SIMD runner explicit build requirements and runtime feature detection. Enforce this with a baseline x86-64 check and a non-x86 target check. Unsupported comparisons should report their status explicitly.

10. **Benchmark-only dependencies burden ordinary verification.** [Cargo.toml:62](/home/folk/Programs/protohoggr/Cargo.toml:62)

    The library has no production dependencies, but its two dev-dependencies produce a lockfile containing 77 other packages, including target-specific packages. Criterion enables default Rayon and Plotters features plus explicit HTML reports. Those dependencies belong to the package's test/check graph even though ordinary correctness tests do not use them.

    Existing warm check logs report 150 ms for the entire clippy phase and 929 ms overall; they do not isolate benchmark overhead. A cold-build cost cannot honestly be inferred from those logs.

    **Fix and enforcement:** Move the benchmark into a separate package and select it explicitly. Disable report and parallel-analysis features unless needed. A dependency rule can keep the correctness-test package free of benchmarking dependencies.

11. **The benchmark disables safeguards across the whole file.** [benches/varint.rs:22](/home/folk/Programs/protohoggr/benches/varint.rs:22)

    It globally allows all three denied integer-cast lints and `unwrap_used`, although there are no unwrap calls. The current `N as u64` conversions do not justify that blanket exemption. Future fixture narrowing can silently inherit the allowances, precisely where SIMD target widths matter.

    **Fix and enforcement:** Use checked conversions and local, justified exceptions. A syntax rule can reject crate-wide allowances for these lints. Fixture construction should also check zigzag values against the selected SIMD target range.

12. **The documented invocation bypasses existing result ownership and provenance.** [benches/varint.rs:3](/home/folk/Programs/protohoggr/benches/varint.rs:3)

    The file tells readers to invoke raw Cargo. That bypasses brokkr's baseline naming, environment stamps, locking, and explicit result location. Criterion otherwise chooses an output directory from ambient configuration, normally under the Cargo target directory, and chooses Gnuplot or Plotters according to installed tools.

    The existing brokkr runner already supplies the appropriate ownership boundary: `.brokkr/bench/criterion`, owned by brokkr rather than Cargo. There is no repository-specific scratch write to another tool's directory in this benchmark.

    **Fix and enforcement:** Document `brokkr bench varint` and require the managed runner for published measurements. A text rule can prohibit raw Cargo run instructions. Set the report backend explicitly when reproducible report generation matters.

13. **A mistyped benchmark filter can save a successful empty baseline.**

    Following the invocation into brokkr exposed a fail-open path outside this repository. Criterion filters individual benchmark IDs without failing when none match. Brokkr forwards the filter and writes a baseline stamp after a successful process exit, without confirming that any measurements were produced.

    Renaming an ID or mistyping a filter can therefore report a saved baseline despite doing no measurement.

    **Fix and enforcement:** Brokkr should enumerate selected IDs, require a nonempty selection, and confirm results exist for that selection before publishing the baseline. Test a deliberately unmatched filter.

14. **The comparison environment gate treats missing fields as compatible.**

    Brokkr's stamp comparison checks only fields present on both sides. A missing CPU, compiler, flags variable, or configuration digest is not a mismatch. Consequently, an unset-to-set flags change or an added configuration file can escape the compatibility gate.

    This directly affects comparisons used to substantiate this crate's performance claims.

    **Fix and enforcement:** Record explicit absence and capture failure, version the stamp schema, and require complete compatible provenance by default. Tests should cover fields appearing, disappearing, and failing to load. Legacy incomplete records can require the existing explicit lenient mode.

15. **Measurement cost and correctness verification are currently separate only by omission.** [benches/varint.rs:289](/home/folk/Programs/protohoggr/benches/varint.rs:289)

    There are 11 benchmark cases. Criterion's defaults allocate three seconds of warmup and five seconds of measurement per case: approximately **88 seconds**, before compilation, statistical analysis, and reporting. That is legitimate sampling time, but none of it validates correctness.

    Existing `brokkr check` logs show compilation through all-target clippy, followed by tests selected with `--tests`; the benchmark is not executed.

    **Fix and enforcement:** Build ordinary correctness tests around the same adapters and fixtures, then keep timing as an explicit measurement command. Declare short exploratory and publication configurations. A check should verify the expected benchmark inventory so removed or renamed cases cannot silently shrink coverage.

I found no benchmark-owned environment mutation, sleeps, leaked processes, nested builds, or shared mutable fixture state. The structural opportunity is to separate portable correctness verification from the architecture-specific comparison package, while making both execute the same validated adapters.
