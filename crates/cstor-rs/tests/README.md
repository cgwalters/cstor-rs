# Integration Tests

This directory contains integration tests for cstor-rs, including tests that compare our tar reassembly with skopeo's output.

## Test Overview

### `test_binary_builds`

Basic test that verifies the `cstor-rs` binary compiles successfully.

```bash
cargo test --test integration_test test_binary_builds
```

### `test_compare_with_skopeo`

**This is the main integration test** that verifies bit-for-bit identical tar streams between skopeo and cstor-rs.

The test:
1. Ensures busybox image exists in containers-storage (pulls if needed)
2. Copies the image using `skopeo copy containers-storage:busybox oci:/tmp/skopeo-oci`
3. Copies the same image using `cstor-rs copy-to-oci <id> /tmp/overlay-oci`
4. Computes SHA256 hashes of all layer tarballs from both copies
5. Compares hashes to verify bit-for-bit identical output

**Requirements:**
- `skopeo` installed and in PATH
- `podman` installed and in PATH
- busybox image in containers-storage (auto-pulled if not present)

**Run the test:**

```bash
# Run the full comparison test
cargo test --test integration_test test_compare_with_skopeo -- --ignored --nocapture

# Or run all integration tests
cargo test --test integration_test -- --ignored --nocapture
```

Note: Tests use `--ignored` because they require external dependencies (podman, skopeo, containers-storage with images) that aren't available in a typical CI environment. They're intended for local development verification.

### `test_layer_export`

Tests exporting a single layer as a tar stream and verifies the output is valid.

```bash
cargo test --test integration_test test_layer_export -- --ignored --nocapture
```

### `test_reflink_to_dir`

Tests the `reflink-to-dir` command which extracts a container image to a directory using reflinks (or fallback copy).

The test:
1. Ensures busybox image exists in containers-storage
2. Extracts the image using `cstor-rs reflink-to-dir --force-copy`
3. Verifies expected directories exist (bin/, etc/, lib/)
4. Compares file list with `podman export` of a container
5. Asserts >90% file coverage (some edge cases may differ)

```bash
cargo test --test integration_test test_reflink_to_dir -- --ignored --nocapture
```

## Prerequisites

Install required tools:

```bash
# Fedora/RHEL
sudo dnf install skopeo podman

# Ubuntu/Debian
sudo apt install skopeo podman

# Arch
sudo pacman -S skopeo podman
```

Ensure busybox is available:

```bash
podman pull busybox
```

**Rootless vs Root**: Tests work in rootless mode (the default with podman). The `cstor-rs` binary automatically re-executes via `podman unshare` when needed for file access permissions.

## Expected Output

When the test passes, you should see:

```
Testing with image: busybox (sha256:...)

Copying with skopeo...
Copying with cstor-rs...

Comparing outputs...
  skopeo: 1 blobs
  cstor-rs: 1 blobs

✓ Success! All blobs match bit-for-bit
```

## Current Status

The test framework demonstrates:
- ✅ CLI binary with full functionality
- ✅ Tar reassembly from TarHeader + OwnedFd
- ✅ OCI directory layout creation
- ✅ Automated comparison with skopeo
- ✅ Full tar-split format parsing
- ✅ Reflink-based image extraction

## Manual Testing

You can also test the binary manually:

```bash
# Build the binary
cargo build --bin cstor-rs

# List images
./target/debug/cstor-rs list-images --verbose

# Get busybox image ID
BUSYBOX_ID=$(podman images -q --no-trunc busybox | sed 's/sha256://')

# Inspect the image
./target/debug/cstor-rs inspect-image $BUSYBOX_ID --layers

# Export to OCI directory
./target/debug/cstor-rs copy-to-oci $BUSYBOX_ID /tmp/test-oci

# Compare with skopeo
skopeo copy containers-storage:busybox oci:/tmp/skopeo-oci

# Check the outputs
ls -la /tmp/test-oci/blobs/sha256/
ls -la /tmp/skopeo-oci/blobs/sha256/

# Compare blob checksums
sha256sum /tmp/test-oci/blobs/sha256/* > /tmp/overlay-sums.txt
sha256sum /tmp/skopeo-oci/blobs/sha256/* > /tmp/skopeo-sums.txt
diff /tmp/overlay-sums.txt /tmp/skopeo-sums.txt
```

## Troubleshooting

### "No such image"

Make sure the image exists:
```bash
podman pull busybox
podman images busybox
```

### "Failed to open layer"

The layer ID extraction from the manifest might need adjustment. Check:
```bash
./target/debug/cstor-rs list-layers $IMAGE_ID
```

### "skopeo command not found"

Install skopeo:
```bash
sudo dnf install skopeo  # or apt/pacman
```

## Implementation Notes

The integration test validates that our zero-copy fd-based approach produces identical output to skopeo's traditional tar serialization. This is crucial for:

1. **Correctness**: Ensuring our tar reassembly is byte-for-byte correct
2. **Compatibility**: Verifying we can replace tar-based workflows
3. **Performance**: Demonstrating that fd-passing achieves the same result more efficiently

The test uses SHA256 hashes rather than byte-by-byte comparison for efficiency, but the result is equivalent.
