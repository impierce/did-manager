# https://blog.rng0.io/how-to-do-code-coverage-in-rust

# Run tests
CARGO_INCREMENTAL=0 RUSTFLAGS='-Cinstrument-coverage' LLVM_PROFILE_FILE='cargo-test-%p-%m.profraw' cargo test --workspace --no-fail-fast

# Create HTML report
echo "Creating HTML report ..."
grcov . --binary-path ./target/debug/deps/ -s . -t html --branch --ignore-not-existing --ignore '../*' --ignore "/*" -o target/coverage/html

# Clean up
find . -name "*.profraw" -type f -delete

echo "Done."
