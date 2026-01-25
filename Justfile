# Format, lint, and type-check
check:
	cargo fmt --check
	cargo clippy --workspace --all-targets
	cargo check --workspace --all-targets

# Auto-format code
fmt:
	cargo fmt

# Run unit tests (uses nextest if available)
unit:
	@if cargo nextest --version >/dev/null 2>&1; then \
		cargo nextest run --workspace; \
	else \
		cargo test --workspace; \
	fi

# Run integration tests (requires root or appropriate permissions)
integration:
	cargo run -p integration-tests

# Run all tests
test-all: unit integration

# Build release binaries
build:
	cargo build --release -p cstor-rs

# Build debug binaries
build-debug:
	cargo build -p cstor-rs

# Generate docs
doc:
	cargo doc --workspace --no-deps

# Open docs in browser
doc-open:
	cargo doc --workspace --no-deps --open

# Clean build artifacts
clean:
	cargo clean

# Full CI check (format, lint, test)
ci: check unit
