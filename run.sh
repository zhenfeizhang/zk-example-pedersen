#!/bin/sh

cargo clippy
cargo run --example groth16 --release
cargo run --example marlin --release

