# cstor-rs TODO and Enhancement Tracking

This document tracks completed work, current status, and planned enhancements for the cstor-rs library.

## Quick Summary

**Current Status**: READ-ONLY IMPLEMENTATION COMPLETE
- All core read-only features implemented and verified
- Bit-for-bit identical tar reconstruction confirmed
- Integration tests passing
- CLI tools fully functional
- Production-ready for read-only use cases

**Major Future Work**: WRITE SUPPORT (Complex, requires significant research)
- Creating and modifying layers/images in containers-storage
- Requires understanding of locking, atomicity, crash safety
- Must integrate safely with existing container runtimes
- See "Major Future Work: Write Support" section below

**Minor Enhancements**: See "Enhancement Ideas" section
- Code quality, testing, documentation improvements
- Performance optimizations
- User experience enhancements

---

## Project Status

The cstor-rs library provides **read-only** access to containers-storage (overlay driver) without tar serialization. The core implementation is **COMPLETE** and **VERIFIED** with bit-for-bit identical tar reconstruction.

See [containers/storage#144](https://github.com/containers/storage/issues/144) for background on the zero-copy file descriptor approach.

## Implementation Approach: cap-std for fd-relative Operations

This implementation uses **cap-std** for all file access, providing fd-relative operations instead of traditional path-based access. This approach offers significant security and correctness benefits:

**Security benefits:**
- **No path traversal vulnerabilities**: All file access is confined to Dir handles, making it impossible to escape the storage directory hierarchy
- **TOCTOU-free**: File descriptor-based operations eliminate time-of-check-time-of-use race conditions inherent in path-based operations
- **Capability-based security**: Dir handles act as unforgeable capabilities, limiting access scope at the API level
- **Defense in depth**: Even if paths are manipulated, they can only reference files within the Dir handle's scope

**Design principles:**
- Storage struct holds `cap_std::fs::Dir` instead of `PathBuf`
- Layer and Image structs contain Dir handles for their respective directories
- All file operations (open, read, metadata, etc.) are relative to Dir handles
- No absolute paths are stored or constructed during normal operation
- Paths in configuration are only used to open initial Dir handles via `Dir::open_ambient_dir()`

**API implications:**
- Functions return File/Dir handles rather than paths
- Path resolution happens through Dir::open() and similar methods
- Symlink reading is fd-relative via Dir::read_link()
- File iteration uses Dir::entries() for bounded access

This approach aligns with modern security practices and eliminates entire classes of vulnerabilities while maintaining clean, idiomatic Rust code.

## Storage Layout Reference

The overlay driver uses the following directory structure under the storage root (typically `~/.local/share/containers/storage`):

- `db.sql` - SQLite database containing metadata
- `overlay/` - Layer directories with actual filesystem content
  - `<layer-id>/diff/` - Layer filesystem content
  - `<layer-id>/link` - Short identifier (26 chars)
  - `<layer-id>/lower` - Colon-separated list of parent layer references
  - `l/` - Symlink directory mapping short IDs to diff directories
- `overlay-layers/` - tar-split metadata
  - `<layer-id>.tar-split.gz` - Compressed tar-split data for reconstructing tar headers
- `overlay-images/` - Image metadata
  - `<image-id>/manifest` - Image manifest
  - `<image-id>/=<base64-encoded-key>` - Additional metadata files (base64-encoded keys)

All file access uses fd-relative operations through cap-std for security.

## Original Implementation Plan (Collapsed - Historical Reference)

All implementation phases have been completed. The following provides a brief summary:

**Phase 1: Core Infrastructure (✅ COMPLETE)**
- Storage discovery and validation
- SQLite database access via fd-relative path
- Configuration parsing (storage.conf)
- Error handling with `thiserror`

**Phase 2: Layer Reading (✅ COMPLETE)**
- Layer metadata reading (link, lower files)
- Link resolution via symlink directory
- Layer chain traversal
- Whiteout handling

**Phase 3: Image Reading (✅ COMPLETE)**
- Image manifest parsing (OCI format)
- Layer ID extraction from image config
- Image-to-layer mapping

**Phase 4: Tar-Split Integration (✅ COMPLETE)**
- tar-split binary format parser
- Bit-for-bit identical TAR reconstruction
- File descriptor passing for zero-copy access
- CRC64 verification

**Phase 5: Testing (✅ COMPLETE)**
- Integration tests with skopeo comparison
- Verification of bit-for-bit identical output
- Deep layer chain testing

**Phase 6: CLI & Advanced Features (✅ COMPLETE)**
- CLI tool with 8 commands
- TOC generation (eStargz-compatible)
- Reflink extraction (zero-copy on btrfs/XFS)
- Automatic rootless mode support

For detailed implementation notes, see git history and module documentation.

---

## Detailed Phase Documentation (Archived)

The following sections contain the original detailed implementation plan. Retained for historical reference and to document design decisions.

<details>
<summary>Click to expand Phase 1: Core Infrastructure</summary>

### 1.1 Storage Root Discovery

Implementation in `src/storage.rs`:

```rust
use cap_std::fs::Dir;
use rusqlite::Connection;

pub struct Storage {
    root_dir: Dir,  // cap-std directory handle for fd-relative operations
    db: Connection,  // rusqlite connection
}

impl Storage {
    /// Open storage at the given root path
    /// Opens a directory handle for fd-relative operations
    pub fn open<P: AsRef<Path>>(root: P) -> Result<Self, StorageError>;

    /// Discover storage root from default locations
    /// Searches standard paths and opens the first valid storage
    pub fn discover() -> Result<Self, StorageError>;
}
```

Default search paths:
1. `$CONTAINERS_STORAGE_ROOT` environment variable
2. For rootless: `$XDG_DATA_HOME/containers/storage` or `~/.local/share/containers/storage`
3. For root: `/var/lib/containers/storage`

Validation requirements:
- Path must exist and be a directory
- Open directory handle with `Dir::open_ambient_dir()`
- `db.sql` must exist and be a valid SQLite database (opened via fd-relative path)
- `overlay/`, `overlay-layers/`, `overlay-images/` directories must exist (checked via Dir::exists())

Security benefits of cap-std:
- All file access is relative to Dir handle, preventing path traversal attacks
- No TOCTOU race conditions from string-based paths
- Capability-based security model limits access scope

### 1.2 SQLite Database Access

Dependencies to add to `Cargo.toml`:
```toml
rusqlite = { version = "0.32", features = ["bundled"] }
cap-std = "3.0"
cap-std-ext = "3.0"  # For additional utilities
```

Database access via fd-relative path:
```rust
impl Storage {
    fn open_database(root_dir: &Dir) -> Result<Connection> {
        // Open db.sql relative to root directory handle
        let db_file = root_dir.open("db.sql")?;
        let fd = db_file.as_raw_fd();

        // Open SQLite connection from file descriptor
        // This ensures we're accessing the exact file we opened
        Connection::open(format!("/proc/self/fd/{}", fd))
    }
}
```

Schema understanding (not all tables are relevant for read-only access):
- The Go implementation stores layer and image metadata, but the overlay driver primarily uses filesystem-based metadata
- Database is mainly used by higher-level storage APIs, not directly by overlay driver
- For this library, focus on filesystem-based metadata reading via Dir handles

### 1.3 Configuration Parsing

The overlay driver supports additional image stores and layer stores. Create `src/config.rs`:

```rust
use cap_std::fs::Dir;

pub struct StorageConfig {
    pub driver: String,  // Should be "overlay"
    pub root: PathBuf,  // Used only for discovery; actual access via Dir
    pub run_root: PathBuf,
    pub image_stores: Vec<PathBuf>,
    pub layer_stores: Vec<AdditionalLayerStore>,
}

pub struct AdditionalLayerStore {
    pub path: PathBuf,  // Path for opening Dir handle
    pub with_reference: bool,  // base64-encoded reference in path
}

impl StorageConfig {
    /// Open directory handles for configured stores
    pub fn open_stores(&self) -> Result<Vec<Dir>> {
        self.image_stores
            .iter()
            .map(|path| Dir::open_ambient_dir(path))
            .collect()
    }
}
```

Configuration locations:
- `/etc/containers/storage.conf`
- `$HOME/.config/containers/storage.conf`
- Parse TOML format
- Paths in config are converted to Dir handles for actual access

### 1.4 Error Handling

Create `src/error.rs` with structured error types:

```rust
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("storage root not found at {0}")]
    RootNotFound(PathBuf),

    #[error("invalid storage: {0}")]
    InvalidStorage(String),

    #[error("layer not found: {0}")]
    LayerNotFound(String),

    #[error("image not found: {0}")]
    ImageNotFound(String),

    #[error("failed to read link file: {0}")]
    LinkReadError(String),

    #[error("tar-split error: {0}")]
    TarSplitError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, StorageError>;
```

Dependencies:
```toml
thiserror = "2.0"
anyhow = "1.0"  // For internal error context
```

Note: cap-std errors will be wrapped in the Io variant automatically via From trait.

## Phase 2: Layer Reading

### 2.1 Layer Metadata

Create `src/layer.rs`:

```rust
use cap_std::fs::Dir;

pub struct Layer {
    id: String,              // Full layer ID (64-char hex digest)
    layer_dir: Dir,          // Directory handle for layer (overlay/<layer-id>/)
    diff_dir: Dir,           // Directory handle for diff/ subdirectory
    link_id: String,         // Short link identifier from link file
    parent_links: Vec<String>, // Parent layer link IDs from lower file
}

impl Layer {
    /// Open a layer by ID using fd-relative operations
    pub fn open(storage: &Storage, id: &str) -> Result<Self> {
        // Open overlay directory from storage root
        let overlay_dir = storage.root_dir.open_dir("overlay")?;

        // Open layer directory relative to overlay
        let layer_dir = overlay_dir.open_dir(id)?;

        // Open diff directory for content access
        let diff_dir = layer_dir.open_dir("diff")?;

        // Read metadata files using fd-relative operations
        let link_id = Self::read_link(&layer_dir)?;
        let parent_links = Self::read_lower(&layer_dir)?;

        Ok(Self { id: id.to_string(), layer_dir, diff_dir, link_id, parent_links })
    }

    /// Read the link file (26-char identifier) via Dir handle
    fn read_link(layer_dir: &Dir) -> Result<String>;

    /// Read the lower file (colon-separated parent links) via Dir handle
    fn read_lower(layer_dir: &Dir) -> Result<Vec<String>>;

    /// Get parent layer IDs (resolved from link IDs)
    pub fn parents(&self, storage: &Storage) -> Result<Vec<String>>;
}
```

Implementation details:
- Link file: Plain text, 26 characters, no newline at end (but may have trailing newline in practice)
- Lower file: Format is `l/<link-id>:l/<link-id>:...`, ordered from uppermost to lowermost parent
- Maximum 500 layers (overlay.go:88 `maxDepth = 500`)
- All file access uses Dir::open(), Dir::read_to_string(), etc. for fd-relative operations
- No absolute paths stored; only Dir handles provide access capability

### 2.2 Link Resolution

The `l/` directory contains symlinks mapping short IDs to layer diff directories:

```rust
use cap_std::fs::Dir;

impl Storage {
    /// Resolve a link ID to a layer ID using fd-relative symlink reading
    /// Returns the layer ID that the link points to
    pub fn resolve_link(&self, link_id: &str) -> Result<String> {
        // Open overlay directory from storage root
        let overlay_dir = self.root_dir.open_dir("overlay")?;

        // Open link directory
        let link_dir = overlay_dir.open_dir("l")?;

        // Read symlink target using fd-relative operation
        let target = link_dir.read_link(link_id)?;

        // Target format: ../<layer-id>/diff
        // Extract <layer-id> from the path
        Self::extract_layer_id_from_link(&target)
    }

    /// Extract layer ID from symlink target path
    fn extract_layer_id_from_link(target: &Path) -> Result<String>;
}
```

Algorithm:
1. Open overlay directory via Dir handle
2. Open `l/` subdirectory via Dir handle
3. Read symlink at `<link-id>` using `Dir::read_link()` (fd-relative)
4. Target format: `../<layer-id>/diff`
5. Extract `<layer-id>` from the path

Edge cases:
- Link file may contain trailing newline (trim whitespace)
- Symlink may be broken (layer removed) - return error
- Additional image stores may have their own link directories (each with its own Dir handle)

Security: Using Dir::read_link() prevents symlink attacks; the symlink is resolved relative to the link directory handle.

### 2.3 Lower Layer Chain Resolution

Build the complete chain of parent layers:

```rust
impl Layer {
    /// Get the complete chain of layers from this layer to the base
    /// Returns layers in order: [self, parent, grandparent, ..., base]
    pub fn layer_chain(&self, storage: &Storage) -> Result<Vec<Layer>>;
}
```

This is critical for overlayfs semantics:
- Each layer builds on its parents
- To read a file, search from top layer down to base
- A whiteout file (`.wh.<filename>`) in a layer hides files in lower layers
- An opaque directory (`.wh..wh..opq`) hides the entire directory in lower layers

### 2.4 Diff Directory Access

Provide efficient access to layer content using fd-relative operations:

```rust
use cap_std::fs::{Dir, File, Metadata};

impl Layer {
    /// Open a file in the layer's diff directory using fd-relative operations
    /// All access is relative to the diff_dir Dir handle
    pub fn open_file<P: AsRef<Path>>(&self, path: P) -> Result<File> {
        self.diff_dir.open(path.as_ref())
            .map_err(Into::into)
    }

    /// Get metadata for a file in the layer's diff directory
    pub fn metadata<P: AsRef<Path>>(&self, path: P) -> Result<Metadata> {
        self.diff_dir.metadata(path.as_ref())
            .map_err(Into::into)
    }

    /// Read directory entries using Dir handle
    pub fn read_dir<P: AsRef<Path>>(&self, path: P) -> Result<cap_std::fs::ReadDir> {
        self.diff_dir.read_dir(path.as_ref())
            .map_err(Into::into)
    }

    /// Resolve a path through the layer chain (respecting whiteouts)
    /// Returns Layer with diff_dir positioned at the file
    /// No paths are returned; only capability handles
    pub fn resolve_file(
        &self,
        storage: &Storage,
        path: &str
    ) -> Result<Option<(Layer, String)>>;
}
```

Whiteout handling:
- `.wh.<filename>` - File deletion marker (hide file in lower layers)
- `.wh..wh..opq` - Opaque directory marker (hide entire directory in lower layers)
- See kernel documentation: https://docs.kernel.org/filesystems/overlayfs.html

Security benefits:
- All file access confined to diff_dir Dir handle
- No path traversal outside layer directory possible
- Whiteout files checked via fd-relative operations

## Phase 3: Image Reading

### 3.1 Image Metadata

Create `src/image.rs`:

```rust
use cap_std::fs::Dir;

pub struct Image {
    id: String,
    image_dir: Dir,  // Directory handle for overlay-images/<image-id>/
}

impl Image {
    /// Open an image by ID using fd-relative operations
    pub fn open(storage: &Storage, id: &str) -> Result<Self> {
        // Open overlay-images directory from storage root
        let images_dir = storage.root_dir.open_dir("overlay-images")?;

        // Open specific image directory
        let image_dir = images_dir.open_dir(id)?;

        Ok(Self { id: id.to_string(), image_dir })
    }

    /// Read the manifest via Dir handle
    pub fn manifest(&self) -> Result<Manifest> {
        let manifest_data = self.image_dir.read_to_string("manifest")?;
        serde_json::from_str(&manifest_data)
            .map_err(|e| StorageError::InvalidStorage(format!("Invalid manifest: {}", e)))
    }

    /// Get the layer IDs for this image
    pub fn layers(&self) -> Result<Vec<String>>;

    /// Read additional metadata using fd-relative operations
    /// Key is base64-encoded for filename
    pub fn read_metadata(&self, key: &str) -> Result<Vec<u8>> {
        let filename = format!("={}", key);
        let mut file = self.image_dir.open(&filename)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    }
}
```

Image directory structure:
- `manifest` - OCI image manifest JSON (read via Dir::read_to_string())
- `=<base64-encoded-key>` - Additional metadata (config, etc.) (opened via Dir::open())
- Keys are base64-encoded without padding
- All access is fd-relative to image_dir Dir handle

### 3.2 Manifest Parsing

Dependencies:
```toml
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Manifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,

    #[serde(rename = "mediaType")]
    pub media_type: String,

    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Descriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,

    pub digest: String,
    pub size: i64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<std::collections::HashMap<String, String>>,
}
```

### 3.3 Image to Layer Mapping

```rust
use cap_std::fs::Dir;

impl Storage {
    /// List all images in storage using fd-relative directory iteration
    pub fn list_images(&self) -> Result<Vec<Image>> {
        let images_dir = self.root_dir.open_dir("overlay-images")?;

        let mut images = Vec::new();
        for entry in images_dir.entries()? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let id = entry.file_name().to_string_lossy().to_string();
                images.push(Image::open(self, &id)?);
            }
        }
        Ok(images)
    }

    /// Get an image by ID
    pub fn get_image(&self, id: &str) -> Result<Image> {
        Image::open(self, id)
    }

    /// Get layers for an image (in order from base to top)
    pub fn get_image_layers(&self, image: &Image) -> Result<Vec<Layer>>;
}
```

Algorithm:
1. Open overlay-images directory via Dir handle
2. Iterate entries using Dir::entries() (fd-relative)
3. Read manifest from image_dir via Dir::read_to_string("manifest")
4. Extract layer digests from manifest
5. Layer ID is typically the digest without the "sha256:" prefix
6. Open each layer using `Layer::open()` which opens its own Dir handles
7. Return layers in correct order (base first)

## Phase 4: Tar-Split Integration

### 4.1 Tar-Split File Reading

Create `src/tar_split.rs`:

```rust
use cap_std::fs::{Dir, File};
use std::io::Read;

pub struct TarSplitReader {
    layer: Layer,
    reader: Box<dyn Read>,  // Gzip decompression reader over fd-relative file
}

impl TarSplitReader {
    /// Open tar-split metadata for a layer using fd-relative operations
    pub fn open(storage: &Storage, layer: &Layer) -> Result<Self> {
        // Open overlay-layers directory via Dir handle
        let layers_dir = storage.root_dir.open_dir("overlay-layers")?;

        // Open tar-split file relative to layers directory
        let filename = format!("{}.tar-split.gz", layer.id);
        let file = layers_dir.open(&filename)?;

        // Wrap in gzip decompressor
        let reader = Box::new(flate2::read::GzDecoder::new(file));

        Ok(Self { layer: layer.clone(), reader })
    }

    /// Read next tar-split entry
    fn read_entry(&mut self) -> Result<Option<TarSplitEntry>>;
}

pub enum TarSplitEntry {
    /// Tar header metadata
    Header(TarHeader),

    /// Reference to file data in overlay
    FileChunk {
        offset: u64,
        size: u64,
    },

    /// Embedded small data
    Data(Vec<u8>),
}
```

Tar-split file location: `overlay-layers/<layer-id>.tar-split.gz`

The tar-split format stores:
- Original tar headers (with timestamps, permissions, etc.)
- File content references (to reconstruct from overlay diff/)
- Small embedded data (symlink targets, etc.)

File access:
- Opened via Dir::open() for fd-relative access
- No absolute paths used
- File handle passed to gzip decoder

See tar-split submodule for format details.

### 4.2 Tar-Split Submodule Integration

The tar-split format implementation is in a submodule. Integration points:

```rust
// In tar-split submodule (to be implemented)
pub struct TarSplitDecoder {
    // Internal decoder state
}

impl TarSplitDecoder {
    pub fn new<R: Read>(reader: R) -> Self;
    pub fn next_entry(&mut self) -> Result<Option<Entry>>;
}

pub struct Entry {
    pub header: TarHeader,
    pub payload: Payload,
}

pub enum Payload {
    /// No data (directory, etc.)
    None,

    /// Data embedded in tar-split
    Embedded(Vec<u8>),

    /// Reference to file in overlay (offset, size)
    FileReference { offset: u64, size: u64 },
}
```

### 4.3 TarSplitFdStream Implementation

This is the core API that provides file descriptors instead of data copies:

```rust
use cap_std::fs::File;
use std::os::unix::io::OwnedFd;

pub struct TarSplitFdStream {
    decoder: TarSplitDecoder,
    layer: Layer,  // Contains diff_dir Dir handle
    current_file: Option<File>,
}

impl TarSplitFdStream {
    /// Create a new stream for a layer
    pub fn new(storage: &Storage, layer_id: &str) -> Result<Self>;

    /// Get the next tar entry
    /// Returns (header, optional file descriptor)
    /// - For regular files: Returns an OwnedFd open to the file in diff/
    /// - For symlinks, directories, etc.: Returns None
    /// - File descriptor is positioned at the correct offset if needed
    pub fn next(&mut self) -> Result<Option<(TarHeader, Option<OwnedFd>)>> {
        // Decode next tar-split entry
        let entry = self.decoder.next_entry()?;

        match entry.payload {
            Payload::None => {
                // Directory, symlink, etc. - no fd needed
                Ok(Some((entry.header, None)))
            }
            Payload::FileReference { offset, size } => {
                // Regular file - open via fd-relative operation
                let file_path = entry.header.name.trim_start_matches("./");

                // Open file using Layer's diff_dir Dir handle
                let mut file = self.layer.diff_dir.open(file_path)?;

                if offset > 0 {
                    file.seek(std::io::SeekFrom::Start(offset))?;
                }

                // Convert cap_std::fs::File to OwnedFd
                let fd = file.into_std().into();

                Ok(Some((entry.header, Some(fd))))
            }
            Payload::Embedded(data) => {
                // Small embedded data - handle appropriately
                Ok(Some((entry.header, None)))
            }
        }
    }
}

pub struct TarHeader {
    pub name: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime: i64,
    pub typeflag: u8,
    pub linkname: String,
    pub uname: String,
    pub gname: String,
    // ... other tar header fields
}
```

Implementation strategy:
1. Decode next tar-split entry
2. If it's a directory or symlink, return header with None fd
3. If it's a regular file:
   - Extract file path from tar header
   - Open the file using layer.diff_dir.open() (fd-relative)
   - cap-std automatically applies O_RDONLY | O_CLOEXEC
   - If offset is non-zero, seek to offset
   - Convert cap_std::fs::File to OwnedFd via into_std()
   - Return header with fd

Key considerations:
- File descriptors are owned by caller (no need to close in iterator)
- Files are opened read-only via cap-std (enforced by Dir handle)
- O_CLOEXEC is automatically set by cap-std
- Seeking is done if tar-split specifies offset (for large files split across tar entries)
- All file access is fd-relative to diff_dir Dir handle

Security benefits:
- Files can only be opened within the layer's diff directory
- No path traversal possible outside the Dir handle's scope
- cap-std enforces secure defaults (O_CLOEXEC, etc.)

### 4.4 File Path Resolution

```rust
use cap_std::fs::File;

impl TarSplitFdStream {
    /// Resolve a tar path to a file in the layer
    /// Handles whiteouts and layer chain traversal
    /// Returns File opened via fd-relative operations
    fn resolve_file(&self, tar_path: &str) -> Result<File> {
        // Normalize tar path (remove leading ./)
        let path = tar_path.trim_start_matches("./");

        // Try to open file in current layer's diff_dir
        // All access is fd-relative to the Dir handle
        match self.layer.diff_dir.open(path) {
            Ok(file) => Ok(file),
            Err(_) => {
                // File not in this layer, check parents
                // Each parent layer has its own diff_dir Dir handle
                self.resolve_in_parent_layers(path)
            }
        }
    }

    /// Check for whiteouts using fd-relative operations
    fn check_whiteout(&self, dir: &Dir, filename: &str) -> Result<bool> {
        let whiteout_name = format!(".wh.{}", filename);
        Ok(dir.try_exists(&whiteout_name)?)
    }
}
```

Algorithm:
1. Normalize tar path (remove leading `./)
2. Try to open file in current layer using diff_dir.open() (fd-relative)
3. If not found, search parent layer chain (each with its own Dir handle)
4. Check for whiteouts in each layer using Dir::try_exists()
5. Return File handle opened via fd-relative operation

Edge cases:
- Hardlinks: Multiple tar entries point to same inode (need to track inodes)
- Sparse files: May need special handling
- Large files: May be referenced multiple times with different offsets
- Whiteout detection: Uses Dir::try_exists() for fd-relative checking

Security: All path resolution confined to Dir handles; no absolute path construction.

## Phase 5: Testing

### 5.1 Unit Tests

Create `src/storage.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_discovery() {
        // Test default storage location discovery
    }

    #[test]
    fn test_storage_validation() {
        // Test validation of storage structure
    }
}
```

Create `src/layer.rs`:
```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_link_resolution() {
        // Test link ID to layer ID resolution
    }

    #[test]
    fn test_lower_parsing() {
        // Test parsing lower file format
    }

    #[test]
    fn test_layer_chain() {
        // Test building complete layer chain
    }

    #[test]
    fn test_whiteout_handling() {
        // Test whiteout and opaque directory handling
    }
}
```

### 5.2 Integration Tests

Create `tests/integration_test.rs`:

```rust
use cstor_rs::{Storage, TarSplitFdStream};

#[test]
#[ignore]  // Requires test data
fn test_read_real_storage() {
    let storage = Storage::discover()
        .expect("Failed to discover storage");

    let images = storage.list_images()
        .expect("Failed to list images");

    assert!(!images.is_empty(), "No images in storage");
}

#[test]
#[ignore]
fn test_read_layer_with_tar_split() {
    let storage = Storage::discover().unwrap();
    let images = storage.list_images().unwrap();
    let image = &images[0];

    let layers = storage.get_image_layers(image).unwrap();
    let layer = &layers[0];

    let mut stream = TarSplitFdStream::new(&storage, &layer.id).unwrap();

    let mut count = 0;
    while let Some((header, fd)) = stream.next().unwrap() {
        count += 1;

        if let Some(fd) = fd {
            // Verify we can read from the fd
            use std::os::unix::io::AsRawFd;
            use std::io::Read;

            let mut file = unsafe {
                std::fs::File::from_raw_fd(fd.as_raw_fd())
            };
            let mut buf = vec![0u8; 1024];
            file.read(&mut buf).unwrap();

            std::mem::forget(file);  // Don't close fd twice
        }
    }

    assert!(count > 0, "No entries in tar-split stream");
}
```

Test data requirements:
- Integration tests use `~/.local/share/containers/storage`
- Need at least one image with layers
- Tests should be marked `#[ignore]` by default
- Provide instructions for setting up test environment:
  ```bash
  podman pull alpine:latest
  cargo test -- --ignored
  ```

### 5.3 Performance Tests

Create `benches/benchmark.rs`:

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cstor_rs::{Storage, TarSplitFdStream};

fn bench_layer_read(c: &mut Criterion) {
    let storage = Storage::discover().unwrap();
    let images = storage.list_images().unwrap();
    let layers = storage.get_image_layers(&images[0]).unwrap();

    c.bench_function("read_layer_tar_split", |b| {
        b.iter(|| {
            let mut stream = TarSplitFdStream::new(
                black_box(&storage),
                black_box(&layers[0].id)
            ).unwrap();

            while let Some((header, fd)) = stream.next().unwrap() {
                black_box(header);
                black_box(fd);
            }
        })
    });
}

criterion_group!(benches, bench_layer_read);
criterion_main!(benches);
```

Add to `Cargo.toml`:
```toml
[dev-dependencies]
criterion = "0.5"

[[bench]]
name = "benchmark"
harness = false
```

Performance goals:
- Reading tar-split metadata should be < 1ms per entry
- File descriptor creation should be < 10μs per file
- Total stream iteration for a layer should be competitive with `tar -tzf`

### 5.4 Test Coverage

Use cargo-llvm-cov for coverage:
```bash
cargo install cargo-llvm-cov
cargo llvm-cov --html
```

Target coverage goals:
- Core APIs (Storage, Layer, Image): 90%+
- Error handling paths: 80%+
- Edge cases (whiteouts, chains): 85%+
- Overall: 85%+

## Phase 6: Future Enhancements

### 6.1 Composefs Support

Composefs is a newer overlay mechanism that uses EROFS. See `storage/drivers/overlay/composefs.go`.

```rust
pub struct ComposefsLayer {
    // EROFS-based layer representation
}

impl Layer {
    /// Check if layer uses composefs
    pub fn is_composefs(&self) -> bool;

    /// Get composefs metadata
    pub fn composefs_metadata(&self) -> Result<Option<ComposefsMetadata>>;
}
```

Implementation deferred because:
- Less common than traditional overlay
- Requires EROFS support
- Not needed for MVP

### 6.2 zstd:chunked Metadata

Some layers use zstd:chunked compression with seekable access.

```rust
pub struct ChunkedLayer {
    toc: TableOfContents,  // From toc artifact
}

impl Layer {
    /// Get chunked zstd metadata if available
    pub fn chunked_metadata(&self) -> Result<Option<ChunkedMetadata>>;
}
```

Location of metadata:
- `.toc` file in layer directory
- `.fs-verity-digests` for integrity verification

Benefits:
- Faster layer extraction
- Seekable decompression
- Better for large layers

Implementation complexity:
- Requires zstd streaming support
- TOC parsing
- Integration with tar-split

Priority: Post-MVP

### 6.3 Concurrent Access

Current design is single-threaded. For concurrent access:

```rust
use cap_std::fs::Dir;

pub struct Storage {
    // Add Arc<Mutex<>> or RwLock for shared state
    root_dir: Dir,  // Dir handles are Send but not Clone
    db: Arc<Mutex<Connection>>,
}

impl Storage {
    /// Thread-safe image listing
    pub fn list_images_sync(&self) -> Result<Vec<Image>>;
}
```

Considerations:
- SQLite connection is not thread-safe by default
- File descriptor limits for concurrent streams
- Layer cache to avoid repeated link resolution
- Dir handles are Send but not Clone; may need to reopen directories per thread
- cap-std Dir::try_clone() can be used for sharing Dir handles

Implementation approach:
1. Add `Send + Sync` bounds where possible
2. Wrap shared state in `Arc<RwLock<>>`
3. Use connection pool for SQLite
4. Use Dir::try_clone() to share directory handles across threads
5. Add caching layer for frequently accessed data

Priority: Based on use case requirements

### 6.4 Caching and Optimization

Add caching for frequently accessed data:

```rust
use cap_std::fs::Dir;

pub struct CachedStorage {
    storage: Storage,
    layer_cache: LruCache<String, Layer>,  // Note: Layer contains Dir handles
    link_cache: LruCache<String, String>,
}

impl CachedStorage {
    /// Resolve link with caching
    pub fn resolve_link_cached(&mut self, link_id: &str) -> Result<String>;
}
```

Dependencies:
```toml
lru = "0.12"
```

Cache strategies:
- Layer metadata (hot cache) - includes Dir handles
- Link resolution (warm cache)
- Image manifests (cold cache)

Cache invalidation:
- Read-only library, so no invalidation needed
- Only concern is if storage changes externally

Note on caching Dir handles:
- Dir handles hold file descriptors
- Be mindful of file descriptor limits when caching
- Consider using Dir::try_clone() for cache entries if needed

### 6.5 Additional Layer Stores

The overlay driver supports additional layer stores (readonly base layers):

```rust
use cap_std::fs::Dir;

impl Storage {
    additional_stores: Vec<Dir>,  // Additional store Dir handles

    /// Search for layer in additional stores using fd-relative operations
    fn find_layer_in_stores(&self, layer_id: &str) -> Result<Option<Layer>> {
        for store_dir in &self.additional_stores {
            // Try to open layer directory in this store
            if let Ok(layer_dir) = store_dir.open_dir(format!("overlay/{}", layer_id)) {
                return Layer::from_dir(layer_id, layer_dir);
            }
        }
        Ok(None)
    }
}
```

Additional layer store paths:
- Configured in `storage.conf`
- Each store opened as a separate Dir handle via Dir::open_ambient_dir()
- May have `withReference` flag for base64-encoded paths
- Typical use: system-wide shared base images

Implementation:
- Open Dir handle for each additional store at startup
- Search stores sequentially using fd-relative operations
- No absolute paths in search logic

Priority: Based on user demand

### 6.6 Deduplication Support

The Go implementation has deduplication support. See `storage/internal/dedup/`.

```rust
pub struct DedupedLayer {
    // Track deduplicated content
}
```

This is complex and likely not needed for read-only access.

Priority: Low

</details>

---

## Completed Implementation

### Core Functionality (Read-Only Access)

All planned read-only features have been successfully implemented and verified:

**Storage & Layer Management**
- Storage discovery and initialization with cap-std (fd-relative operations)
- SQLite database access via fd-relative path
- Layer reading with link resolution and parent chain traversal
- Image manifest parsing and layer ID extraction from config
- On-demand parent layer lookup (avoids pre-loading deep chains)
- Whiteout and opaque whiteout handling

**Tar-Split Integration**
- Full tar-split binary format parser (NDJSON with gzip compression)
- Bit-for-bit identical TAR reconstruction verified with skopeo
- File data opening via layer chain search
- CRC64-ISO checksum verification
- Zero-copy file descriptor passing
- Proper handling of tar padding and segment alignment

**Table of Contents (TOC)**
- TOC generation inspired by eStargz format
- Serializable representation of layer contents
- Support for all tar entry types (files, dirs, symlinks, hardlinks, devices)
- GNU long name/linkname extension support
- Per-layer and full-image TOC generation

**CLI Tools**
- `cstor-rs` binary with 8 commands:
  - `list-images` - List all images in storage
  - `inspect-image` - Show image details
  - `list-layers` - List layers for an image
  - `inspect-layer` - Show layer details
  - `export-layer` - Export layer as tar stream
  - `copy-to-oci` - Copy image to OCI directory
  - `reflink-to-dir` - Extract image using reflinks (zero-copy on btrfs/XFS)
  - `toc` - Output Table of Contents as JSON
  - `resolve-link` - Resolve link ID to layer ID
- Automatic rootless mode support via `podman unshare` re-exec
- Reflink extraction using FICLONE ioctl
- `tar-diff` diagnostic tool for tar comparison

**Testing**
- Integration tests comparing with skopeo output
- Bit-for-bit identical tar reconstruction verified
- Deep layer chain support (50+ layers tested)
- All tests passing

### Verification Results

**Tar-Split Reassembly: BIT-FOR-BIT IDENTICAL**
- File sizes match exactly
- SHA256 hashes match perfectly
- Integration tests pass: tar streams match skopeo output exactly

**Performance Characteristics**
- Layer export: Fast, millisecond-level for typical layers
- Deep layer chains: Handles 50+ layers via on-demand traversal
- Zero-copy: File descriptors passed directly, no unnecessary data copying
- Reflink extraction: Instant copy on supported filesystems

## Major Future Work: Write Support

### WRITE SUPPORT FOR CONTAINERS-STORAGE

**Priority**: HIGH (but complex, requires significant research)

The current implementation is **read-only**. Adding write support would enable:
- Creating new layers and images in containers-storage
- Modifying existing images
- Committing container changes back to storage
- Full read-write storage management

This is a significant undertaking that requires:

**1. Thorough Understanding of containers-storage Locking**
- Study how containers/storage implements locking (`storage/pkg/lockfile/`)
- Understand lock file locations and semantics
- Research advisory vs mandatory locking behavior
- Handle lock conflicts and timeouts
- Support both process-level and system-level locking
- Coordinate with existing container runtimes (podman, buildah, etc.)

**2. Understanding Storage Format for Writes**
- Layer creation workflow (create diff directory, link file, lower file)
- Image creation (manifest writing, metadata encoding)
- Database updates (SQLite schema, transactional updates)
- tar-split generation from filesystem content
- Atomic directory creation and symlink management
- Short link ID generation algorithm
- Layer ordering and parent chain construction

**3. Atomic Operations and Crash Safety**
- Ensure operations are atomic (all-or-nothing)
- Handle partial writes and cleanup on failure
- Implement proper rollback mechanisms
- Prevent corruption of existing layers/images
- Handle concurrent access safely
- Use filesystem transactions where possible
- Proper fsync/fdatasync usage for durability

**4. Integration with Existing Container Runtimes**
- Ensure compatibility with podman/buildah/cri-o
- Respect existing locking conventions
- Follow same metadata format exactly
- Handle version compatibility
- Test interaction with running containers
- Avoid race conditions with runtime operations

**5. Additional Complexity**
- User namespace handling for rootless writes
- Quota and storage limit enforcement
- Garbage collection coordination
- Deduplication support
- Handling of additional layer stores (read-only bases)
- Storage driver options (e.g., overlay2 vs overlay)

**Resources for Implementation**
- Go reference: `github.com/containers/storage/drivers/overlay/overlay.go`
- Storage locking: `github.com/containers/storage/pkg/lockfile/`
- Database schema: Study existing db.sql structure
- Image format: OCI image spec
- Layer format: containers/storage specific overlay layout

**Recommended Approach**
1. Start with read-only operations that prepare for writes (lock acquisition/release)
2. Implement layer creation in isolation (without full integration)
3. Add comprehensive tests with storage validation
4. Study podman/buildah source code for edge cases
5. Consider contributing to containers/storage Go library first for validation
6. Implement database writes with full transaction support
7. Add comprehensive integration tests with real container runtimes

**Warning**: This is a complex feature that could corrupt storage if implemented incorrectly. Extensive testing and validation against the Go implementation is critical.

## Outstanding Issues and Future Work

This section tracks current issues, enhancements, and planned improvements for the read-only implementation.

### Current Issues (Read-Only Implementation)

#### Platform Selection for Multi-Arch Images
**Priority**: MEDIUM

The CLI currently may not properly handle multi-arch images. Consider adding platform selection support to specify target architecture when copying images.

#### CRC Verification Performance
**Priority**: LOW

CRC64 verification reads files twice (once to verify, once to return fresh fd). Consider adding flag to disable verification for performance-critical use cases.

### Enhancement Ideas

The following enhancements could improve the library but are not critical:

#### Code Quality Improvements
- Add TAR header magic byte validation for robustness
- Add circular reference detection in layer chain resolution
- Improve error context messages (include layer IDs, file paths)
- Add comprehensive error handling tests
- Refactor long functions for better readability

#### Security Hardening
- Consider explicit O_NOFOLLOW for file opens (cap-std already provides protection)
- Add fuzzing for tar-split parser (handles untrusted input)

#### Performance Optimizations
- Increase buffer sizes (64KB-128KB) for better throughput
- Add benchmarks to track performance regressions
- Consider concurrent access support with thread-safe wrappers

#### User Experience
- Add progress callbacks for long operations
- Support name:tag resolution (currently requires image IDs)
- Add compression options (zstd, different compression levels)

#### Documentation
- Create `docs/architecture.md` - system design and security model
- Create `docs/comparison.md` - comparison with skopeo/buildah
- Document tar-split format quirks discovered during implementation

#### Testing
- Add property-based tests for path normalization and header parsing
- Add tests for missing tar-split files, corrupted metadata, CRC mismatches
- Test deep layer chain limits and circular references

#### Advanced Features
- Additional image stores support (read-only additional stores from storage.conf)
- Composefs support (EROFS-based layers)
- zstd:chunked metadata support

## Design Decisions and Notes

The following design decisions were made during implementation:

1. **Hardlink handling**: Currently handled by tar-split metadata. Multiple tar entries reference the same file content correctly.

2. **Sparse file support**: Not explicitly handled. Sparse files are treated as regular files. tar-split metadata preserves the original tar representation.

3. **Extended attributes**: Not currently extracted. Overlay stores xattrs but they're not exposed in the current API. Could be added via `xattr` crate if needed.

4. **SELinux labels**: Stored as xattrs (`security.selinux`). Not currently extracted. Would require privileged access in some cases.

5. **ID-mapped mounts**: Not explicitly supported. The rootless mode auto-detection handles basic user namespace cases via `podman unshare`.

6. **Concurrent access**: Read-only operations are safe. Multiple `TarSplitFdStream` instances can be active. Be mindful of file descriptor limits.

## References

- Go implementation: `storage/drivers/overlay/overlay.go`
- Overlay filesystem: https://docs.kernel.org/filesystems/overlayfs.html
- OCI Image Spec: https://github.com/opencontainers/image-spec
- tar-split format: (submodule documentation)
- containers-storage: https://github.com/containers/storage
