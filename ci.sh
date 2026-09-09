#!/usr/bin/env sh
# CI gate: formatting, lints (warnings are errors), tests.
set -eu

# fmt is scoped to this repo's own crates, NOT `--all`. `cargo fmt --all` means
# "format all packages AND their local path-based dependencies", and
# gp-goblin-sender path-depends on ../goblin, so `--all` hands rustfmt the whole
# Goblin wallet and node tree as well: 110 crate roots instead of 11, judging
# another repo's formatting from this gate. Naming the five members keeps it to
# this repo. (The workspace still has to RESOLVE, so ../goblin must be present
# either way; that is what the workflows check for before calling this script.)
cargo fmt -p gp-core -p gp-wallet -p gp-nostr -p gp-server -p gp-goblin-sender -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
