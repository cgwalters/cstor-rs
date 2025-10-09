# cstor-rs

Read-only Rust library for accessing containers-storage (overlay driver) content efficiently.

NOTE: This codebase was 80% directly written via Anthropic's Sonnet and Opus models.

## Overview

This library provides direct read access to container images stored in containers-storage without requiring tar serialization (see [containers/storage#144](https://github.com/containers/storage/issues/144)). It uses tar-split metadata to reconstruct tar archives bit-for-bit, providing file descriptors for regular file content instead of copying data, enabling zero-copy operations.

The core innovation is using tar-split metadata to reconstruct tar archives without walking filesystem directories, streaming tar headers from metadata while passing file descriptors directly for regular files.

## Features

**Core Capabilities:**
- **Zero-copy layer access**: File descriptors instead of data serialization
- **tar-split integration**: Bit-for-bit identical TAR reconstruction from metadata
- **Capability-based security**: All file operations use cap-std for path traversal protection
- **Read-only by design**: No modifications to containers-storage
- **OCI compatibility**: Full oci-spec and ocidir integration for standard image formats
- **TOC generation**: eStargz-compatible Table of Contents for layer indexing
- **Reflink extraction**: Efficient copy-on-write extraction on btrfs/XFS filesystems
- **Direct file access**: Layer::open_file_std() API for reading individual files

**Implementation Highlights:**
- Rust implementation of tar-split format parser
- Layer chain resolution with overlay semantics (handling parent layers)
- Whiteout and opaque whiteout handling
- SQLite database access for storage metadata
- Link identifier resolution through symlink directory
- CRC64 verification for file integrity
- Automatic rootless mode support via podman unshare re-exec

**Storage Format Support:**
- SQLite database (`$root/db.sql`) for layer and image metadata
- Overlay filesystem layout (`$root/overlay/<layer-id>/diff/`)
- tar-split metadata files (`$root/overlay-layers/<layer-id>.tar-split.gz`)
- Image manifests and configuration (`$root/overlay-images/<image-id>/`)
- Link symlinks (`$root/overlay/l/`)

## Command-Line Tools

### cstor-rs

Main CLI tool exposing all library functionality. Automatically handles rootless mode by re-executing via `podman unshare` when needed for file access.

```bash
# List all images in storage
cstor-rs list-images --verbose

# Show image details
cstor-rs inspect-image <image-id> --layers

# List layers for an image
cstor-rs list-layers <image-id>

# Inspect layer details
cstor-rs inspect-layer <layer-id> --chain

# Export a layer as tar stream (uses tar-split for reconstruction)
cstor-rs export-layer <layer-id> -o layer.tar

# Copy image to OCI directory layout
cstor-rs copy-to-oci <image-id> /path/to/oci-dir

# Extract image to directory using reflinks (zero-copy on btrfs/XFS)
cstor-rs reflink-to-dir <image-id> /path/to/output-dir [--force-copy]

# Generate Table of Contents (TOC) as JSON
cstor-rs toc <image-id> --pretty

# Resolve a link ID to layer ID
cstor-rs resolve-link <link-id>
```

The CLI automatically re-executes via `podman unshare` when running as non-root for commands that need file access (export-layer, copy-to-oci, reflink-to-dir), ensuring correct UID/GID mappings.

### tar-diff

Debugging tool for comparing tar archives byte-by-byte. Useful for verifying that tar-split reconstruction produces identical output.

```bash
# Compare two tar archives
tar-diff original.tar reconstructed.tar
```

The tool reports missing entries, extra entries, and metadata/content differences between the archives.

## Usage Examples

### List Images

```rust,no_run
use cstor_rs::Storage;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Storage::discover()?;
    let images = storage.list_images()?;
    for image in images {
        println!("Image ID: {}", image.id());
    }
    Ok(())
}
```

### Export Layer Using tar-split

```rust,no_run
use cstor_rs::{Storage, Layer, TarSplitFdStream, TarSplitItem};
use std::io::{Write, Read};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Storage::discover()?;
    let layer = Layer::open(&storage, "layer-id")?;
    let mut stream = TarSplitFdStream::new(&storage, &layer)?;

    let mut output = std::fs::File::create("layer.tar")?;
    while let Some(item) = stream.next()? {
        match item {
            TarSplitItem::Segment(bytes) => {
                output.write_all(&bytes)?;
            }
            TarSplitItem::FileContent(fd, size) => {
                let mut file = std::fs::File::from(fd);
                let mut remaining = size;
                let mut buffer = [0u8; 8192];

                while remaining > 0 {
                    let to_read = (remaining as usize).min(buffer.len());
                    let n = file.read(&mut buffer[..to_read])?;
                    output.write_all(&buffer[..n])?;
                    remaining -= n as u64;
                }
            }
        }
    }
    Ok(())
}
```

### Read File from Layer

```rust,no_run
use cstor_rs::{Storage, Layer};
use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Storage::discover()?;
    let layer = Layer::open(&storage, "layer-id")?;

    // Open a file directly from the layer
    let mut file = layer.open_file_std("etc/hostname")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    println!("Hostname: {}", contents);
    Ok(())
}
```

### Generate TOC for a Layer

```rust,no_run
use cstor_rs::{Storage, Layer, toc::Toc};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Storage::discover()?;
    let layer = Layer::open(&storage, "layer-id")?;
    let toc = Toc::from_layer(&storage, &layer)?;

    for entry in &toc.entries {
        println!("{}: {:?} ({} bytes)",
            entry.name, entry.entry_type, entry.size.unwrap_or(0));
    }
    Ok(())
}
```

## Prerequisites

- **Rust**: Edition 2024 (nightly or recent stable with edition support)
- **Runtime**: podman installed (for rootless mode re-exec via `podman unshare`)
- **Storage**: Existing containers-storage with overlay driver (created by podman/buildah)

## Building

```bash
# Build library and all binaries
cargo build --release

# Build specific binary
cargo build --release --bin cstor-rs
```

## Documentation

The library includes comprehensive module-level documentation:

```bash
cargo doc --open
```

Key modules:
- `storage`: Storage discovery and root directory access
- `image`: Image manifest and configuration parsing
- `layer`: Layer hierarchy, chain resolution, and file access
- `tar_split`: tar-split format parsing and TarSplitFdStream
- `tar_writer`: TAR header writing utilities
- `toc`: Table of Contents generation (eStargz-compatible)
- `config`: storage.conf parsing
- `error`: Error types and handling

## Testing

### Unit Tests

```bash
cargo test
```

### Integration Tests

The project includes comprehensive integration tests that verify tar reassembly produces bit-for-bit identical archives:

```bash
# Ensure test image exists
podman pull busybox

# Run integration tests (requires podman)
cargo test --test integration_test -- --ignored --nocapture
```

The integration tests verify:
- Tar-split reconstruction produces bit-for-bit identical tar archives
- Layer chain resolution handles overlay semantics correctly
- File descriptor passing works for regular files
- Whiteout files are processed correctly
- Reflink extraction works on supported filesystems

## Contributing

See [docs/TODO.md](docs/TODO.md) for outstanding issues and planned enhancements. Contributions are welcome for:
- Performance improvements (buffer sizes, concurrent access)
- Additional platform support
- Error handling and edge cases
- Documentation and examples

## Architecture

The library uses capability-based file operations throughout:
- Storage holds a Dir handle to the storage root
- All file access is relative to Dir handles
- No absolute paths constructed during operations
- SQLite database accessed via fd-relative path

This eliminates path traversal vulnerabilities while maintaining clean, idiomatic Rust code.
