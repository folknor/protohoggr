The main problems are repeated orchestration, host-dependent verification, and claims broader than what the checks establish. I found the following, without ranking them.

I changed nothing. This was a read-only inspection; I did not run `brokkr check`, which writes build artifacts and state. Timings below come from retained logs. I also inspected the sibling brokkr source checkout; its behavior agrees with those logs, but I did not establish that it exactly matches the installed executable.

Existing enforcement does work: the logs show gremlins rejecting 61 characters and Clippy rejecting six diagnostics. Brokkr's `--cap-lints=warn` is not itself a bypass: its diagnostic gate rejects surviving warnings. Accounting also records expected tests and observed executions. Those are useful protections, with the limits below.

1. **The runner adds polling latency to tiny tests.**  
   Brokkr's [`wait_child`](/home/folk/Programs/brokkr/src/test_runner/run.rs:378) polls process completion using a 250 ms interval. Its watchdog also sleeps and is joined during shutdown without an immediate wakeup. Retained successful test phases consistently take 306-307 ms, including one reporting only 30 ms to build the binaries. That is consistent with polling dominating execution, although the logs do not isolate the exact contribution.

   Replace completion polling with child-exit notification and a wakeable watchdog. Preserve deadlines using timed waits. Mechanically enforce the lifecycle with runner tests that demonstrate completion wakes the waiter; use timing measurements as supporting evidence rather than brittle elapsed-time assertions.

2. **Preparation re-enters Cargo unnecessarily.**  
   The [latest retained log](/home/folk/Programs/protohoggr/.brokkr/check-logs/check-001792993691821.log:19) contains:

   - `cargo test --no-run ... --tests` during preparation.
   - The same command again during the test phase.
   - `cargo test ... --tests` to execute.

   This is three Cargo invocations, not evidence of three full compilations. Nevertheless, each repeats startup, graph and freshness work. Preparation took 364 ms; another recent run took 415 ms.

   Build once, retain the artifact inventory and launch environment, then execute those artifacts directly. Brokkr already implements direct execution for other lanes. Enforce this with an orchestration test that counts build invocations and verifies that execution uses the inventoried executable.

3. **Benchmark dependencies are entangled with ordinary verification.**  
   [`Cargo.toml`](/home/folk/Programs/protohoggr/Cargo.toml:55) puts Criterion with HTML reports and `varint-simd` in this package's dev dependencies. Ordinary library tests therefore resolve and build benchmark-only dependencies; Clippy additionally checks the benchmark through `--all-targets`. The tracked lockfile contains 78 packages including protohoggr.

   Put comparison benchmarks in a separate benchmark package with its own dependency graph. Normal verification can then remain small, while benchmark verification explicitly checks that package. Enforce the separation through manifest/dependency checks. Cold-build savings were not measured.

4. **The minimum Rust version is declared but unverified.**  
   [`rust-version = "1.85"`](/home/folk/Programs/protohoggr/Cargo.toml:7) is not tested by the observed check. AGENTS says nightly, and brokkr uses unstable libtest JSON discovery. There is no repository toolchain pin.

   The current Criterion 0.8.2 manifest declares Rust 1.86, so the complete development check cannot run on the advertised library minimum. That does not establish that the library itself fails on 1.85.

   Separate the promises: verify the library on its minimum compiler, and verify development machinery on a specified nightly. Enforce both through compiler-specific checks. Record compiler and brokkr identities in the result so a pass identifies its verifier.

5. **The prose shortcut assumes a previous successful build without proving one.**  
   Brokkr's [`scope` implementation](/home/folk/Programs/brokkr/src/scope.rs:39) skips Rust phases when the only uncommitted changes are Markdown. Its justification says the last full run already checked the same code, but classification consults Git dirt, not a successful verification record.

   Checking out an unchecked commit and modifying README can therefore skip compilation and tests. Markdown incorporated into compilation is also deliberately treated as prose.

   Base reuse on a successful result keyed to source inputs, toolchain, dependencies and build shape. Otherwise report a prose-only result without implying full verification. Enforce with a scenario test involving an unchecked commit and Markdown-only dirt. This is a machinery issue independent of how this project's brokkr config is configured.

6. **The documented check requires more host infrastructure than the library does.**  
   Gremlins enumerates files using `git ls-files`; outside a Git repository it refuses rather than scanning a source archive. The serial harness machinery uses Linux `/proc`, Unix sockets, peer credentials and pidfds. Its socket directory requires writable `$HOME`, and sufficiently long home paths can exceed Unix socket path limits.

   Thus a portable Rust library's standard verifier depends on a Linux development environment. Missing Git repository metadata produces a refusal; missing home storage produces an explicit error; kernel or socket restrictions can prevent harness setup.

   Separate portable crate verification from optional Linux process supervision. Hand the runner explicit state paths and capabilities, detect requirements before building, and test supported and refused capability combinations. Tests establish library correctness; capability probes establish whether supervision can run.

7. **A global build lock couples unrelated projects.**  
   Brokkr's lock lives under `$HOME/.brokkr`, and the inspected tooling describes it as global. A check of this small crate can wait behind work in another checkout even when their build outputs are independent.

   Lock resources by their actual ownership: shared target directories, compiler leases and specific mutable state. Keep genuinely global operations globally locked. Enforce with concurrency tests showing independent roots can proceed and shared outputs cannot. Queueing cost is workload-dependent and absent from the retained phase timings.

8. **Repository state has no declared Git hygiene, and cleanup failures disappear.**  
   [`.gitignore`](/home/folk/Programs/protohoggr/.gitignore:1) does not exclude `.brokkr/`; it currently appears as untracked state. One retained run's plan is 5,592 bytes and its journal 95,745 bytes. The whole directory is about 804 KiB.

   The directory is appropriately owned by brokkr, rather than borrowed from another tool. Declare that ownership and ignore `/.brokkr/` explicitly. Keep its logs, accounting and scratch there, with per-run subdirectories.

   Both log and accounting retention discard removal errors. Failed cleanup can silently defeat the intended ten-run bounds. Report pruning failures and test retention under failed deletion. A repository hygiene check can enforce the ignore entry. Also, `Cargo.lock` is currently tracked despite its ignore entry; that entry misleadingly describes a policy the repository no longer follows.

9. **Gremlins silently excludes files based on spelling.**  
   The scanner accepts a fixed extension list. Extensionless files such as `LICENSE`, and files renamed to an unrecognized extension, receive no scan. Ignored untracked inputs are absent from its Git inventory as well.

   The existing Rust and Markdown files are covered; the general no-gremlins claim is broader than that coverage. Classify owned text inputs explicitly, and report unclassified files instead of silently treating them as exempt. Enforce inventory coverage and test renames from recognized to unrecognized extensions. Actual binary and generated-output exemptions should remain explicit.

10. **Unsafe contracts remain prose where types could enforce part of them.**  
    [`encode_varint_to_slice`](/home/folk/Programs/protohoggr/src/lib.rs:950) requires ten writable bytes through an unsafe precondition. Accepting `&mut [u8; 10]`, or a checked conversion to a capacity-bearing wrapper, can make that requirement structural and permit a safe public operation.

    Similarly, “validated regions” for unchecked reading have no representation: ordinary `Cursor` exposes the unsafe operation directly. A validated packed-region type could carry the proof when callers repeatedly decode already-checked data.

    `missing_safety_doc` establishes that documentation exists, not that callers meet it or implementations preserve it. Types can enforce capacity and proof ownership; property tests and Miri can check implementation behavior for valid inputs. Arbitrary external unsafe callers cannot be mechanically certified by this crate.

11. **One unchecked-reader statement overpromises behavior outside its contract.**  
    [`read_varint_unchecked`](/home/folk/Programs/protohoggr/src/lib.rs:159) says violating the length/overflow condition produces an unspecified value. An overlong terminated sequence can instead reach a shift of 70 and panic with overflow checks enabled.

    Remove the behavioral promise for invalid unsafe inputs, or deliberately implement and document one. Do not add tests that violate an unsafe precondition just to preserve this sentence. The documented valid-input contract is testable; a general claim about all contract violations is not a useful guarantee.

12. **Several durable claims are false, ambiguous or unsupported today.**

    - [README's blanket skip-zero statement](/home/folk/Programs/protohoggr/README.md:27), repeated in AGENTS, includes primitive encoders. `encode_varint(0)` writes a byte, and the slice encoder does too. State the policy specifically for field encoders. Existing behavior tests can enforce it.
    - README, CHANGELOG and the slice encoder's docs call its fast path “branchless.” The implementation contains value-dependent `if` branches. Compiler output could differ, but no assembly check establishes the claim. Remove it, or restrict it to specified compiler/target output and enforce that output.
    - “No external dependencies” is true for the library's normal dependency graph, not development verification. Clarify that distinction and enforce the normal/build dependency graph mechanically.
    - The unchecked performance ratios and approximately 95% workload claim lack a durable local measurement record identifying CPU, compiler, flags and corpus. Treat them as historical measurements, not timeless properties. Benchmark records can establish observations; universal speed ratios cannot be enforced.

13. **Durable source comments already violate the documented evidence policy.**  
    [`read_varint`'s explanation](/home/folk/Programs/protohoggr/src/lib.rs:96) and the encoder comments cite `notes/SIMD.md` in another project. AGENTS explicitly prohibits durable material citing transient notes.

    Move the required evidence and rationale into a durable performance record, and make source comments understandable without the note. A text rule can enforce the forbidden citation direction. Hardware-dependent conclusions still require reviewed measurements rather than a text check.

14. **Human-maintained API inventories can drift without detection.**  
    README enumerates iterators, encoders and batch operations, while Rust already generates an API inventory. Its usage block is also ordinary Markdown, not a compiled example in the observed check.

    Link to generated API documentation and retain conceptual descriptions rather than duplicate exhaustive lists. Compile the usage example from a single source. Inventory comparison and example compilation are mechanical; deciding whether the conceptual explanation remains useful requires review.

15. **The clean-room enforcement claim is not established by this check.**  
    [`LLM.md`](/home/folk/Programs/protohoggr/LLM.md:28) makes an absolute claim about what development agents never see and says tooling enforces it. The repository's check does not audit agent access or session provenance; `.review.toml` containing an audit identifier does not establish that isolation.

    State the actual boundary and retain auditable provenance where available. Access restrictions and required attestations can be mechanically enforced. Historical agent exposure and model training data cannot be proved by this build. I found insufficient evidence to call the historical claim false.

Two additional code findings surfaced while checking the comments:

16. **`PackedIter::size_hint` has an invalid lower bound for accepted input.**  
    [`remaining / 10`](/home/folk/Programs/protohoggr/src/lib.rs:474) assumes valid varints, but the safe constructor accepts arbitrary bytes and `next()` swallows errors. Ten `0x80` bytes produce a lower bound of one and then yield zero elements. Typed iterators inherit the problem. An overflow followed by valid bytes also permits another `next()` to yield after the previous call returned `None`, so “ending iteration” does not describe permanent exhaustion.

    Use a zero lower bound for unvalidated data, and explicitly choose whether errors permanently exhaust the iterator. A validated iterator can offer stronger guarantees. Enforce both through iterator-contract tests over malformed byte slices.

17. **Length decoding can panic instead of returning `WireResult::Err`.**  
    [`read_len_delimited`](/home/folk/Programs/protohoggr/src/lib.rs:292) casts a `u64` length to `usize` and adds it to the position unchecked. A maximum-length prefix overflows the addition on 64-bit hosts; on 32-bit hosts, wider lengths truncate first.

    This is outside the trusted-data performance goal, but contradicts the broad AGENTS guidance to use fallible results instead of panics. Checked conversion plus comparison against remaining length avoids the issue structurally. Boundary tests can enforce it.

The SSE2 safety justification itself holds for the selected x86-64 branch, and its load bounds are locally established. I found no crate build script, nested-build test, orphan integration test file, or test-owned write into another tool's ignored directory. The scalar fallback is excluded from x86-64 compilation, so a host-only green result provides no verification of that implementation.
