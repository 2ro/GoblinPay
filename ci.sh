#!/usr/bin/env sh
# CI gate: formatting, lints (warnings are errors), tests.
set -eu

cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
