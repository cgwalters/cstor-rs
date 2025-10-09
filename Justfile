check:
	cargo check --workspace --all-targets

unit: check
	cargo t
