#!/bin/sh
# Layout ensemble for examples/ab.rs: the AB, BA (--features swap) and AA
# (--features aa) legs under each of several code-alignment configurations,
# every build and run through brokkr. See reference/performance.md.
#
# Usage: bench/ensemble.sh <target-triple> [ab FILTER]
#   e.g. bench/ensemble.sh x86_64-unknown-linux-gnu msg_question
#
# Alignment flags reach rustc through CARGO_TARGET_<TRIPLE>_RUSTFLAGS, which
# cargo joins with the [target.<triple>] / [target.'cfg(..)'] rustflags of
# its config files. That preserves the host's own flags only when those come
# from target tables, so this script refuses every setup where the variable
# would mask or miss them: RUSTFLAGS or CARGO_ENCODED_RUSTFLAGS set (even
# empty), CARGO_BUILD_RUSTFLAGS or CARGO_BUILD_TARGET set, or a cargo config
# file with build.rustflags, build.target or an include. An existing
# CARGO_TARGET_<TRIPLE>_RUSTFLAGS is appended to, not replaced.
#
# Each flagged leg also gets --cfg ab_ensemble. ab prints whether that cfg
# reached it and its enabled target features; a plain build runs first, and
# every flagged leg must report ab_ensemble=true and the plain build's
# feature list, or the script stops. That proves the flags were injected and
# target-cpu survived; it cannot see a masked flag that changes neither.
#
# AB_EXTRA_RUSTFLAGS, if set, is added to every flagged leg - e.g.
# -Zmerge-functions=disabled for the diagnostic ensemble that keeps AA's two
# copies apart. Report such a run separately from the default one.
set -eu

die() {
    echo "ensemble: $*" >&2
    exit 1
}

[ $# -ge 1 ] || die "usage: bench/ensemble.sh <target-triple> [ab FILTER]"
triple=$1
filter=${2:-}

[ -z "${RUSTFLAGS+set}" ] || die "RUSTFLAGS is set; it would mask the target rustflags"
[ -z "${CARGO_ENCODED_RUSTFLAGS+set}" ] || die "CARGO_ENCODED_RUSTFLAGS is set; it would mask the target rustflags"
[ -z "${CARGO_BUILD_RUSTFLAGS+set}" ] || die "CARGO_BUILD_RUSTFLAGS is set; a target flag would mask it"
[ -z "${CARGO_BUILD_TARGET+set}" ] || die "CARGO_BUILD_TARGET is set; the flags would go to another triple"

# Refuse a cargo config this script cannot reason about: build.rustflags
# (masked by any target flag), build.target, or an include it does not follow.
#
# This is a line-based approximation of TOML, deliberately conservative: a
# table header is reduced to its name with quotes, spaces and anything after
# the closing bracket removed; a key is everything before its "=" with quotes
# and spaces removed. Any top-level key starting with "build" (dotted keys and
# inline tables alike) is refused, not interpreted. TOML it does not model -
# multi-line strings holding header-like lines, for one - is outside it, which
# is why brokkr#37 asks brokkr to do the appending itself.
check_config() {
    file=$1
    [ -f "$file" ] || return 0
    section=
    while IFS= read -r line || [ -n "$line" ]; do
        line=$(printf '%s' "$line" | sed 's/^[[:space:]]*//')
        case $line in
            '#'*|'') continue ;;
            '['*)
                section=$(printf '%s' "$line" | sed 's/\].*//; s/^\[*//; s/[[:space:]"'\'']//g')
                case $section in
                    build) ;;
                    build*) die "$file has table [$section]; not supported" ;;
                esac
                continue ;;
            *=*) ;;
            *) continue ;;
        esac
        key=$(printf '%s' "$line" | sed 's/=.*//; s/[[:space:]"'\'']//g')
        case $section:$key in
            *:include) die "$file uses include; not supported" ;;
            build:rustflags|build:target) die "$file sets build.$key; not supported" ;;
            :build*) die "$file sets $key at top level; not supported" ;;
        esac
    done < "$file"
}

home=${CARGO_HOME:-$HOME/.cargo}
check_config "$home/config"
check_config "$home/config.toml"
dir=$(pwd)
while :; do
    check_config "$dir/.cargo/config"
    check_config "$dir/.cargo/config.toml"
    [ "$dir" != / ] || break
    dir=$(dirname "$dir")
done

var=CARGO_TARGET_$(printf '%s' "$triple" | tr 'a-z.-' 'A-Z__')_RUSTFLAGS
existing=$(printenv "$var" || true)

# The features= field of ab's build: line in the output $1.
features_of() {
    printf '%s\n' "$1" | grep '^build:' | tr ' ' '\n' | grep '^features=' || true
}

# The plain build: no injected flags, no measurement, just its build: line.
plain=$(brokkr run ab -- info) || die "plain build failed"
plain_features=$(features_of "$plain")
[ -n "$plain_features" ] || die "no build: line from the plain build"
echo "plain $(printf '%s\n' "$plain" | grep '^build:')"

i=0
while IFS= read -r cfg; do
    i=$((i + 1))
    flags="--cfg ab_ensemble $cfg ${AB_EXTRA_RUSTFLAGS:-}"
    [ -z "$existing" ] || flags="$existing $flags"
    export "$var=$flags"
    for leg in ab ba aa; do
        case $leg in
            ab) set -- ;;
            ba) set -- --features swap ;;
            aa) set -- --features aa ;;
        esac
        out=$(brokkr run ab "$@" -- time "$filter") || die "cfg$i $leg: brokkr run failed"
        case $(printf '%s\n' "$out" | grep '^build:') in
            *ab_ensemble=true*) ;;
            *) die "cfg$i $leg: the flags did not reach the build" ;;
        esac
        got=$(features_of "$out")
        [ "$got" = "$plain_features" ] || die "cfg$i $leg: target features changed ($got, plain $plain_features): host flags were masked"
        printf '%s\n' "$out" | while IFS= read -r line; do
            echo "cfg$i [$cfg] $leg $line"
        done
    done
done <<EOF

-C llvm-args=-align-all-functions=6
-C llvm-args=-align-all-functions=7
-C llvm-args=-align-loops=64
-C llvm-args=-align-loops=32
-C llvm-args=-align-all-nofallthru-blocks=5
-C llvm-args=-align-all-functions=6 -C llvm-args=-align-all-nofallthru-blocks=6
-C llvm-args=-align-all-functions=5 -C llvm-args=-align-loops=32
-C llvm-args=-align-all-functions=8 -C llvm-args=-align-loops=64
EOF
