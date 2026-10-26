# Todo

## Run benchmarking through brokkr, not custom machinery

Performance comparisons today go through machinery built in this repository
rather than through brokkr's own benchmarking:

- `bench/examples/ab.rs`, a same-binary A/B tool run with `brokkr run ab`, which
  links the working tree against `protohoggr_base` and `protohoggr_ctl`:
  renamed git dependencies on this repository in `bench/Cargo.toml`, pinned to
  `8a450a0`, the pushed commit from before 0.5.0. Every comparison made with it
  now measures against pre-0.5.0 code.
- `bench/ensemble.sh`, a shell script that loops `brokkr run` over nine
  code-alignment settings and does its own approximate parsing of cargo config to
  keep host rustflags.
- `reference/performance.md`, which documents that method as the way to measure.

Replace it with brokkr's own facilities: criterion benches in `bench/` measured
with `brokkr bench`, baselines stored and compared by brokkr, so no baseline is
pinned by hand in a manifest. `brokkr man bench` covers the workflow:
`brokkr bench NAME --commit REF` measures any commit, unpushed included, in a
brokkr-managed worktree with its own target dir; `--compare A B` diffs two saved
baselines without resampling; the environment gate refuses comparisons across
toolchains, CPUs, rustflags or cargo configs; criterion knobs such as
`--measurement-time` go after `--`. brokkr#36 (pushed-only baselines) was a
limit of the custom git-dependency design, not of `brokkr bench`, and can be
closed once the custom pieces go.

The one thing `brokkr bench` does not do is control for code layout: each side
is its own build, so each lands at different addresses. That is brokkr#40:
instruction-count (iai-callgrind) baselines as the day-to-day regression check,
a layout ensemble for criterion benches, and an optional pinned alignment. Wait
for it rather than rebuild any of it here.

Then remove the custom pieces (`bench/examples/ab.rs`, `bench/ensemble.sh`, the
`protohoggr_base` and `protohoggr_ctl` dependencies and their `swap` and `aa`
features) and rewrite `reference/performance.md` around the brokkr workflow,
keeping what the custom runs established: identical code can move 10% to
several times over from code layout alone, so a single wall-clock A/B run is not
evidence.
