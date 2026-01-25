# Layer Splitting with Reflinks: Design Document

## Overview

This document describes how to implement layer splitting in cstor-rs with reflink support. The goal is to take an existing layer (or merged image) and split it into multiple new layers while using reflinks to avoid copying file content.

## Motivation

Traditional container image building creates layers based on Dockerfile instructions, which often results in poor layer caching. A single package update may invalidate a large layer. Content-based layer splitting (as implemented by [chunkah](https://github.com/jlebon/chunkah)) groups related files together, maximizing layer reuse across image updates.

**The reflink advantage**: When the source and destination are on the same filesystem with reflink support (btrfs, XFS with reflink=1), we can create new layers in O(metadata) time instead of O(data) time. Files are never copied - the kernel shares the underlying blocks.

## Use Case: Layer Splitting PoC

**Input**: An existing layer in containers-storage (e.g., a single-layer image)

**Output**: Multiple new layers in containers-storage, where files are reflinked from the source

**Example**: Split busybox into two layers:
1. `bin/busybox` (the main binary)  
2. Everything else (symlinks, config files)

This demonstrates the core capability without needing a full component detection system.

## Architecture

### Phase 1: LayerBuilder API (This PoC)

```rust
/// Builder for creating a new layer in containers-storage
pub struct LayerBuilder {
    /// Temporary directory for layer content
    staging_dir: Dir,
    /// Parent layer ID (if any)
    parent: Option<String>,
    /// Files added to this layer (for tar-split generation)
    entries: Vec<TocEntry>,
}

impl LayerBuilder {
    /// Create a new layer builder
    pub fn new(storage: &Storage, parent: Option<&str>) -> Result<Self>;
    
    /// Add a file by reflinking from a source fd
    pub fn add_file_reflink(&mut self, path: &Path, src_fd: BorrowedFd, 
                            metadata: &TocEntry) -> Result<()>;
    
    /// Add a file by copying content
    pub fn add_file_copy(&mut self, path: &Path, content: &[u8],
                         metadata: &TocEntry) -> Result<()>;
    
    /// Add a directory
    pub fn add_directory(&mut self, path: &Path, mode: u32, 
                         uid: u32, gid: u32) -> Result<()>;
    
    /// Add a symlink
    pub fn add_symlink(&mut self, path: &Path, target: &str) -> Result<()>;
    
    /// Add a hardlink
    pub fn add_hardlink(&mut self, path: &Path, target: &Path) -> Result<()>;
    
    /// Commit the layer to storage, returning the layer ID
    pub fn commit(self, storage: &mut Storage) -> Result<String>;
}
```

### Phase 2: Storage Write Methods

```rust
impl Storage {
    /// Begin creating a new layer
    pub fn create_layer(&self, parent: Option<&str>) -> Result<LayerBuilder>;
    
    /// Commit a built layer (called by LayerBuilder::commit)
    fn commit_layer(&mut self, builder: LayerBuilder) -> Result<Layer>;
    
    /// Generate a unique layer ID
    fn generate_layer_id() -> String;
}
```

## Implementation Details

### 1. Staging Directory

New layers are built in a staging directory before being committed:

```
<storage-root>/overlay-layers/.staging/<random-id>/
    diff/           # Layer content (files, directories)
    tar-split.json  # Generated tar-split metadata (temp, gzipped on commit)
```

On commit:
1. Generate layer ID (random 64 hex chars or content-addressed)
2. Rename `staging/<random>/diff/` → `overlay/<layer-id>/diff/`
3. Generate link ID, create symlink in `overlay/l/`
4. Gzip tar-split and move to `overlay-layers/<layer-id>.tar-split.gz`
5. Update `overlay-layers/layers.json`
6. Update SQLite database

### 2. Reflink File Addition

```rust
fn add_file_reflink(&mut self, path: &Path, src_fd: BorrowedFd, 
                    metadata: &TocEntry) -> Result<()> {
    // Create parent directories
    self.ensure_parent_dirs(path)?;
    
    // Create destination file
    let dest = self.staging_dir.create(path)?;
    
    // Try reflink first
    match ioctl_ficlone(&dest, src_fd) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => {
            // Fall back to copy
            let mut src = File::from(src_fd.try_clone_to_owned()?);
            std::io::copy(&mut src, &mut dest.into_std())?;
        }
        Err(e) => return Err(e.into()),
    }
    
    // Set permissions and ownership
    rustix::fs::fchmod(&dest, Mode::from_raw_mode(metadata.mode))?;
    rustix::fs::fchown(&dest, Some(Uid::from_raw(metadata.uid)), 
                       Some(Gid::from_raw(metadata.gid)))?;
    
    // Track for tar-split generation
    self.entries.push(metadata.clone());
    
    Ok(())
}
```

### 3. Tar-Split Generation

When committing, we need to generate tar-split metadata so the layer can be exported as a valid tar:

```rust
fn generate_tar_split(&self) -> Result<Vec<u8>> {
    let mut entries = Vec::new();
    let mut position = 0;
    
    for entry in &self.entries {
        // Generate tar header bytes
        let header_bytes = serialize_tar_header(entry)?;
        
        // Add segment entry for header
        entries.push(TarSplitEntry {
            entry_type: TarSplitType::Segment,
            payload: base64::encode(&header_bytes),
            position,
        });
        position += 1;
        
        // Add file entry with CRC64
        if entry.entry_type == TocEntryType::Reg && entry.size.unwrap_or(0) > 0 {
            let file = self.staging_dir.open(&entry.name)?;
            let crc = compute_crc64(&file)?;
            
            entries.push(TarSplitEntry {
                entry_type: TarSplitType::File,
                name: entry.name.to_string_lossy().to_string(),
                size: entry.size.unwrap_or(0) as i64,
                payload: base64::encode(&crc.to_be_bytes()),
                position,
            });
            position += 1;
            
            // Add padding segment if needed
            let padding = compute_tar_padding(entry.size.unwrap_or(0));
            if padding > 0 {
                entries.push(TarSplitEntry {
                    entry_type: TarSplitType::Segment,
                    payload: base64::encode(&vec![0u8; padding as usize]),
                    position,
                });
                position += 1;
            }
        }
    }
    
    // Add footer (two 512-byte zero blocks)
    entries.push(TarSplitEntry {
        entry_type: TarSplitType::Segment,
        payload: base64::encode(&[0u8; 1024]),
        position,
    });
    
    // Serialize as NDJSON and gzip
    let mut output = Vec::new();
    for entry in entries {
        serde_json::to_writer(&mut output, &entry)?;
        output.push(b'\n');
    }
    
    let mut compressed = Vec::new();
    let mut encoder = flate2::write::GzEncoder::new(&mut compressed, 
                                                     flate2::Compression::fast());
    encoder.write_all(&output)?;
    encoder.finish()?;
    
    Ok(compressed)
}
```

### 4. layers.json Update

The `overlay-layers/layers.json` file contains an array of layer metadata:

```json
[
  {
    "id": "abc123...",
    "parent": "def456...",
    "created": "2026-01-24T12:00:00Z",
    "compressed-diff-digest": "sha256:...",
    "diff-digest": "sha256:...",
    "compressed-size": 12345,
    "diff-size": 23456
  }
]
```

We need to append the new layer and atomically replace the file.

### 5. Locking

containers-storage uses file-based locks for coordination. For the PoC, we can:

1. **Option A (Simple)**: Acquire exclusive lock on `overlay-layers/layers.lock` during commit
2. **Option B (Deferred)**: Document that concurrent access with podman/buildah is unsafe

For production use, we'd need full lockfile protocol compatibility.

## Layer Splitting Algorithm

For the PoC, a simple predicate-based split:

```rust
/// Split a layer into two based on a predicate
pub fn split_layer<F>(
    storage: &mut Storage,
    source_layer: &Layer,
    predicate: F,
) -> Result<(String, String)>  // Returns (matching_layer_id, remaining_layer_id)
where
    F: Fn(&TocEntry) -> bool,
{
    let toc = Toc::from_layer(storage, source_layer)?;
    
    let mut matching = storage.create_layer(None)?;
    let mut remaining = storage.create_layer(None)?;
    
    for entry in &toc.entries {
        let src_fd = source_layer.open_file(&entry.name)?;
        
        if predicate(entry) {
            matching.add_file_reflink(&entry.name, src_fd.as_fd(), entry)?;
        } else {
            remaining.add_file_reflink(&entry.name, src_fd.as_fd(), entry)?;
        }
    }
    
    let matching_id = matching.commit(storage)?;
    let remaining_id = remaining.commit(storage)?;
    
    Ok((matching_id, remaining_id))
}
```

## Integration Test

```rust
#[test]
#[ignore]
fn test_split_layer_with_reflinks() -> Result<()> {
    let sh = shell()?;
    ensure_test_image()?;
    
    let image_id = get_image_id(&sh, TEST_IMAGE)?;
    
    // Split busybox: bin/busybox goes to layer1, everything else to layer2
    let output = cmd!(sh, 
        "cargo run --bin cstor-rs -- layer split {image_id} \
         --predicate 'name == bin/busybox' \
         --output-format json"
    ).read()?;
    
    let result: serde_json::Value = serde_json::from_str(&output)?;
    let layer1_id = result["matching_layer"].as_str().unwrap();
    let layer2_id = result["remaining_layer"].as_str().unwrap();
    
    // Verify layer1 contains only bin/busybox
    let toc1 = cmd!(sh, "cargo run --bin cstor-rs -- image toc {layer1_id}").read()?;
    let toc1: serde_json::Value = serde_json::from_str(&toc1)?;
    assert!(toc1["entries"].as_array().unwrap().iter()
        .all(|e| e["name"].as_str().unwrap().starts_with("bin/busybox") 
             || e["type"].as_str() == Some("dir")));
    
    // Verify layer2 contains the rest
    let toc2 = cmd!(sh, "cargo run --bin cstor-rs -- image toc {layer2_id}").read()?;
    let toc2: serde_json::Value = serde_json::from_str(&toc2)?;
    assert!(toc2["entries"].as_array().unwrap().iter()
        .all(|e| e["name"].as_str().unwrap() != "bin/busybox"));
    
    // Verify both layers can be exported as valid tar
    let temp_dir = TempDir::new()?;
    cmd!(sh, "cargo run --bin cstor-rs -- layer export {layer1_id} -o {temp_dir}/layer1.tar").run()?;
    cmd!(sh, "cargo run --bin cstor-rs -- layer export {layer2_id} -o {temp_dir}/layer2.tar").run()?;
    
    // Verify tars are valid
    cmd!(sh, "tar -tf {temp_dir}/layer1.tar").run()?;
    cmd!(sh, "tar -tf {temp_dir}/layer2.tar").run()?;
    
    // Verify reflinks were used (files should share blocks)
    // This is filesystem-dependent; skip if not on btrfs/xfs
    
    println!("✓ Layer split test passed");
    println!("  - Created layer1: {} (bin/busybox)", layer1_id);
    println!("  - Created layer2: {} (everything else)", layer2_id);
    
    Ok(())
}
```

## Files to Create/Modify

1. **New**: `src/layer_builder.rs` - LayerBuilder struct and implementation
2. **New**: `src/tar_split_writer.rs` - Tar-split generation from filesystem
3. **Modify**: `src/storage.rs` - Add create_layer(), commit_layer() methods
4. **Modify**: `src/lib.rs` - Export new types
5. **Modify**: `src/bin/cli/main.rs` - Add `layer split` command
6. **New**: `tests/integration_test.rs` - Add split layer test

## Future Extensions

1. **Component detection**: Integrate chunkah-style component repos (xattr, rpmdb)
2. **Image creation**: Build complete multi-layer images from split layers
3. **Locking**: Full containers-storage lock protocol for concurrent access
4. **Composefs integration**: Output to composefs object store with reflinks

## References

- [chunkah](https://github.com/jlebon/chunkah) - Content-based layer splitting
- [containers-storage](https://github.com/containers/storage) - Go implementation
- [tar-split](https://github.com/vbatts/tar-split) - Tar metadata format
- [FICLONE](https://man7.org/linux/man-pages/man2/ioctl_ficlonerange.2.html) - Reflink ioctl
