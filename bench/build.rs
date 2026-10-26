//! Declares `--cfg ab_ensemble`, which `bench/ensemble.sh` adds to every
//! flagged build so `examples/ab.rs` can report that the flags reached it.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(ab_ensemble)");
}
