//! Tar-split integration for reading container layers without full tar serialization.
//!
//! This module provides the `TarSplitFdStream` which reads tar-split metadata files
//! and returns file descriptors for the actual file content, enabling zero-copy
//! access to layer data.
//!
//! # Overview
//!
//! The tar-split format stores tar header metadata separately from file content,
//! allowing reconstruction of tar archives without duplicating the actual file data.
//! This implementation uses that metadata to provide file descriptors directly to
//! the files in the overlay diff directory.
//!
//! # Architecture
//!
//! The tar-split format is NDJSON (newline-delimited JSON), gzip-compressed:
//! - Type 1 (FileType): File/directory references with name, optional size, optional CRC64
//! - Type 2 (SegmentType): Raw TAR header bytes and padding (base64-encoded)
//! - CRC64-ISO algorithm for checksums
//!
//! # Implementation Details
//!
//! This implementation achieves bit-for-bit identical TAR reconstruction by:
//! - Returning raw Segment bytes directly without parsing/regenerating TAR headers
//! - Not adding padding to file content (padding is already in subsequent Segment entries)
//! - Supporting on-demand parent layer traversal for file lookups (avoids pre-loading deep chains)
//! - Providing CRC64-ISO checksum verification for file integrity
//! - Handling trailing segments (TAR footer and padding) as regular items at end-of-stream
//!
//! # Performance Characteristics
//!
//! - Zero-copy file access via OwnedFd (no data copying)
//! - On-demand layer chain traversal (maximum depth: 500 layers)
//! - CRC64 verification requires reading file twice (performance consideration)
//! - Efficient for deep layer chains as parent layers are only opened when needed

use std::io::{BufRead, BufReader};
use std::os::unix::io::OwnedFd;

use base64::prelude::*;
use cap_std::fs::{Dir, File};
use crc::{CRC_64_GO_ISO, Crc};
use flate2::read::GzDecoder;
use serde::Deserialize;

use crate::error::{Result, StorageError};
use crate::layer::Layer;
use crate::storage::Storage;

/// CRC64-ISO implementation for verifying file checksums.
const CRC64_ISO: Crc<u64> = Crc::<u64>::new(&CRC_64_GO_ISO);

/// Item returned from tar-split stream iteration.
///
/// tar-split stores complete TAR headers as raw bytes in Segment entries,
/// which must be written directly without modification to preserve byte-identical output.
#[derive(Debug)]
pub enum TarSplitItem {
    /// Raw segment bytes (TAR header + padding) to write directly.
    /// These bytes come from the tar-split metadata and must be written as-is.
    Segment(Vec<u8>),

    /// File content to write.
    /// Contains: (file_descriptor, size_for_padding_calculation)
    FileContent(OwnedFd, u64),
}

/// Raw tar-split entry from NDJSON format before validation.
///
/// The tar-split format uses integer discriminants:
/// - Type 1: FileType entries with metadata (name, size, CRC64)
/// - Type 2: SegmentType entries with raw TAR bytes (base64-encoded)
#[derive(Debug, Deserialize)]
struct TarSplitEntryRaw {
    /// Entry type discriminant: 1 for File, 2 for Segment.
    #[serde(rename = "type")]
    type_id: u8,
    /// File name from TAR header (type 1 only).
    #[serde(default)]
    name: Option<String>,
    /// File size in bytes (type 1 only).
    #[serde(default)]
    size: Option<u64>,
    /// CRC64-ISO checksum, base64-encoded (type 1 only).
    #[serde(default)]
    crc64: Option<String>,
    /// Base64-encoded TAR header bytes or padding (type 2 only).
    #[serde(default)]
    payload: Option<String>,
}

/// Tar-split entry from NDJSON format.
///
/// The tar-split format has two main types:
/// - Type 1: FileType entries with metadata (name, size, CRC64)
/// - Type 2: SegmentType entries with raw TAR bytes (base64-encoded)
#[derive(Debug)]
enum TarSplitEntry {
    /// File type entry: references a file/directory with metadata.
    File {
        /// File name from TAR header.
        name: Option<String>,
        /// File size in bytes.
        size: Option<u64>,
        /// CRC64-ISO checksum (base64-encoded).
        crc64: Option<String>,
    },
    /// Segment type entry: raw TAR header bytes and padding.
    Segment {
        /// Base64-encoded TAR header bytes (512 bytes) or padding.
        payload: Option<String>,
    },
}

impl TarSplitEntry {
    /// Parse a tar-split entry from raw format with validation.
    fn from_raw(raw: TarSplitEntryRaw) -> Result<Self> {
        match raw.type_id {
            1 => Ok(TarSplitEntry::File {
                name: raw.name,
                size: raw.size,
                crc64: raw.crc64,
            }),
            2 => Ok(TarSplitEntry::Segment {
                payload: raw.payload,
            }),
            _ => Err(StorageError::TarSplitError(format!(
                "Invalid tar-split entry type: {}",
                raw.type_id
            ))),
        }
    }
}

/// Tar header information extracted from tar-split metadata.
///
/// This structure contains the essential tar header fields needed to reconstruct
/// a tar entry or understand the file metadata.
#[derive(Debug, Clone)]
pub struct TarHeader {
    /// File path in the tar archive (e.g., "./etc/hosts")
    pub name: String,

    /// File mode (permissions and type information)
    pub mode: u32,

    /// User ID of the file owner
    pub uid: u32,

    /// Group ID of the file owner
    pub gid: u32,

    /// File size in bytes
    pub size: u64,

    /// Modification time (Unix timestamp)
    pub mtime: i64,

    /// Tar entry type flag:
    /// - b'0' or b'\0': Regular file
    /// - b'1': Hard link
    /// - b'2': Symbolic link
    /// - b'3': Character device
    /// - b'4': Block device
    /// - b'5': Directory
    /// - b'6': FIFO
    pub typeflag: u8,

    /// Link target for symbolic links and hard links
    pub linkname: String,

    /// User name of the file owner
    pub uname: String,

    /// Group name of the file owner
    pub gname: String,

    /// Major device number (for device files)
    pub devmajor: u32,

    /// Minor device number (for device files)
    pub devminor: u32,
}

impl TarHeader {
    /// Parse a TarHeader from a 512-byte TAR header block.
    ///
    /// The TAR header format (ustar):
    /// - 0-99: name
    /// - 100-107: mode (octal)
    /// - 108-115: uid (octal)
    /// - 116-123: gid (octal)
    /// - 124-135: size (octal)
    /// - 136-147: mtime (octal)
    /// - 148-155: checksum (octal)
    /// - 156: typeflag
    /// - 157-256: linkname
    /// - 257-262: magic ("ustar\0")
    /// - 263-264: version ("00")
    /// - 265-296: uname
    /// - 297-328: gname
    /// - 329-336: devmajor (octal)
    /// - 337-344: devminor (octal)
    /// - 345-500: prefix
    pub fn from_bytes(header: &[u8]) -> Result<Self> {
        if header.len() < 512 {
            return Err(StorageError::TarSplitError(format!(
                "TAR header too short: {} bytes",
                header.len()
            )));
        }

        // Verify checksum first to ensure this is a valid tar header
        // The checksum is computed by treating the checksum field (148-155) as spaces
        let stored_checksum = {
            let checksum_bytes = &header[148..156];
            let null_pos = checksum_bytes
                .iter()
                .position(|&b| b == 0 || b == b' ')
                .unwrap_or(checksum_bytes.len());
            let s = std::str::from_utf8(&checksum_bytes[..null_pos])
                .map_err(|_| StorageError::TarSplitError("Invalid checksum field".to_string()))?
                .trim();
            if s.is_empty() {
                return Err(StorageError::TarSplitError(
                    "Empty checksum field".to_string(),
                ));
            }
            u32::from_str_radix(s, 8).map_err(|e| {
                StorageError::TarSplitError(format!("Invalid checksum '{}': {}", s, e))
            })?
        };

        let computed_checksum: u32 = header[..148]
            .iter()
            .chain(std::iter::repeat(&b' ').take(8)) // checksum field treated as spaces
            .chain(header[156..512].iter())
            .map(|&b| b as u32)
            .sum();

        if stored_checksum != computed_checksum {
            return Err(StorageError::TarSplitError(format!(
                "Checksum mismatch: stored {} != computed {}",
                stored_checksum, computed_checksum
            )));
        }

        // Extract null-terminated string from byte range
        let extract_string = |start: usize, end: usize| -> String {
            let bytes = &header[start..end];
            let null_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            String::from_utf8_lossy(&bytes[..null_pos]).to_string()
        };

        // Parse octal field from byte range
        let parse_octal = |start: usize, end: usize| -> Result<u64> {
            let s = extract_string(start, end);
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return Ok(0);
            }
            u64::from_str_radix(trimmed, 8).map_err(|e| {
                StorageError::TarSplitError(format!("Failed to parse octal '{}': {}", trimmed, e))
            })
        };

        let name = extract_string(0, 100);
        let mode = parse_octal(100, 108)? as u32;
        let uid = parse_octal(108, 116)? as u32;
        let gid = parse_octal(116, 124)? as u32;
        let size = parse_octal(124, 136)?;
        let mtime = parse_octal(136, 148)? as i64;
        let typeflag = header[156];
        let linkname = extract_string(157, 257);
        let uname = extract_string(265, 297);
        let gname = extract_string(297, 329);
        let devmajor = parse_octal(329, 337)? as u32;
        let devminor = parse_octal(337, 345)? as u32;

        Ok(TarHeader {
            name,
            mode,
            uid,
            gid,
            size,
            mtime,
            typeflag,
            linkname,
            uname,
            gname,
            devmajor,
            devminor,
        })
    }

    /// Check if this header represents a regular file.
    pub fn is_regular_file(&self) -> bool {
        self.typeflag == b'0' || self.typeflag == b'\0'
    }

    /// Check if this header represents a directory.
    pub fn is_directory(&self) -> bool {
        self.typeflag == b'5'
    }

    /// Check if this header represents a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.typeflag == b'2'
    }

    /// Check if this header represents a hard link.
    pub fn is_hardlink(&self) -> bool {
        self.typeflag == b'1'
    }

    /// Check if this is a GNU long name entry (typeflag 'L').
    /// The file content contains the full name for the next entry.
    pub fn is_gnu_long_name(&self) -> bool {
        self.typeflag == b'L'
    }

    /// Check if this is a GNU long linkname entry (typeflag 'K').
    /// The file content contains the full linkname for the next entry.
    pub fn is_gnu_long_linkname(&self) -> bool {
        self.typeflag == b'K'
    }

    /// Normalize the path by stripping leading "./"
    pub fn normalized_name(&self) -> &str {
        self.name.strip_prefix("./").unwrap_or(&self.name)
    }
}

/// Stream that reads tar-split metadata and provides file descriptors for file content.
///
/// This is the main API for Phase 4, providing zero-copy access to layer content
/// by returning file descriptors instead of copying data.
///
/// # Architecture
///
/// The stream:
/// 1. Opens the `.tar-split.gz` file via cap-std Dir handle (fd-relative)
/// 2. Decompresses the gzip stream with flate2
/// 3. Parses tar-split entries (stub implementation for MVP)
/// 4. For regular files: opens them via `layer.diff_dir` and returns OwnedFd
/// 5. For directories/symlinks: returns header with None fd
///
/// # Example
///
/// ```no_run
/// use cstor_rs::{Storage, Layer, TarSplitFdStream, TarSplitItem};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let storage = Storage::discover()?;
/// let layer = Layer::open(&storage, "layer-id")?;
/// let mut stream = TarSplitFdStream::new(&storage, &layer)?;
///
/// while let Some(item) = stream.next()? {
///     match item {
///         TarSplitItem::Segment(bytes) => {
///             println!("Segment: {} bytes", bytes.len());
///         }
///         TarSplitItem::FileContent(fd, size) => {
///             use std::os::unix::io::AsRawFd;
///             println!("File: {} bytes, fd={}", size, fd.as_raw_fd());
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct TarSplitFdStream {
    /// The current layer for file lookups.
    layer: Layer,

    /// Storage root directory for accessing parent layers on-demand.
    storage_root: Dir,

    /// Gzip decompressor reading from the tar-split file.
    reader: BufReader<GzDecoder<File>>,

    /// Entry counter for debugging and error messages.
    entry_count: usize,

    /// Buffer for the current Segment payload that will be returned as next item.
    /// We buffer Segments to return them properly in the iteration order.
    current_segment_payload: Option<Vec<u8>>,

    /// Buffer for trailing Segment payloads (footer and padding blocks).
    /// These are accumulated after all File entries have been processed.
    trailing_segments: Vec<Vec<u8>>,
}

impl TarSplitFdStream {
    /// Create a new tar-split stream for a layer.
    ///
    /// Opens the `.tar-split.gz` file for the layer using fd-relative operations
    /// and initializes the decompression stream.
    ///
    /// # Arguments
    ///
    /// * `storage` - Storage handle for accessing the overlay-layers directory
    /// * `layer` - Layer to read tar-split metadata for
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The tar-split file doesn't exist
    /// - The file cannot be opened
    /// - Gzip decompression initialization fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::{Storage, Layer, TarSplitFdStream};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let storage = Storage::discover()?;
    /// let layer = Layer::open(&storage, "abc123...")?;
    /// let stream = TarSplitFdStream::new(&storage, &layer)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(storage: &Storage, layer: &Layer) -> Result<Self> {
        // Open overlay-layers directory via Dir handle
        let layers_dir = storage.root_dir().open_dir("overlay-layers").map_err(|e| {
            StorageError::TarSplitError(format!("Failed to open overlay-layers directory: {}", e))
        })?;

        // Open tar-split file relative to layers directory
        let filename = format!("{}.tar-split.gz", layer.id);
        let file = layers_dir.open(&filename).map_err(|e| {
            StorageError::TarSplitError(format!(
                "Failed to open tar-split file {}: {}",
                filename, e
            ))
        })?;

        // Wrap in gzip decompressor
        let gz_decoder = GzDecoder::new(file);
        let reader = BufReader::new(gz_decoder);

        // Open the layer for on-demand file lookups
        let layer = Layer::open(storage, &layer.id)?;

        // Clone storage root dir for on-demand parent layer access
        let storage_root = storage.root_dir().try_clone()?;

        Ok(Self {
            layer,
            storage_root,
            reader,
            entry_count: 0,
            current_segment_payload: None,
            trailing_segments: Vec::new(),
        })
    }

    /// Open a file in the layer chain, trying current layer first then parents.
    ///
    /// This traverses the layer chain on-demand, avoiding the need to pre-load
    /// all parent layers. It tries the current layer first, then recursively
    /// searches parent layers using link IDs.
    fn open_file_in_chain(&self, path: &str) -> Result<cap_std::fs::File> {
        // Normalize path (remove leading ./)
        let normalized_path = path.strip_prefix("./").unwrap_or(path);

        // Try to open in current layer first
        match self.layer.diff_dir.open(normalized_path) {
            Ok(file) => return Ok(file),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Continue to search parent layers
            }
            Err(e) => return Err(StorageError::Io(e)),
        }

        // Search parent layers on-demand
        self.search_parent_layers(&self.layer, normalized_path, 0)
    }

    /// Recursively search parent layers for a file.
    ///
    /// Uses a depth limit to prevent infinite loops in case of circular references.
    fn search_parent_layers(
        &self,
        current_layer: &Layer,
        path: &str,
        depth: usize,
    ) -> Result<cap_std::fs::File> {
        // Maximum depth to prevent infinite loops
        const MAX_DEPTH: usize = 500;

        if depth >= MAX_DEPTH {
            return Err(StorageError::TarSplitError(format!(
                "Layer chain exceeds maximum depth of {} while searching for file: {}",
                MAX_DEPTH, path
            )));
        }

        // Get parent link IDs
        let parent_links = current_layer.parent_links();

        // Try each parent
        for link_id in parent_links {
            // Resolve link ID to layer ID by reading the symlink directly
            let parent_id = self.resolve_link_direct(link_id)?;

            // Try to open file directly in parent's diff directory
            match self.open_file_in_layer(&parent_id, path) {
                Ok(file) => return Ok(file),
                Err(StorageError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                    // File not in this parent, recursively search its parents
                    match self.search_by_layer_id(&parent_id, path, depth + 1) {
                        Ok(file) => return Ok(file),
                        Err(_) => continue, // Try next parent at this level
                    }
                }
                Err(_) => continue, // Try next parent
            }
        }

        Err(StorageError::TarSplitError(format!(
            "File not found in layer chain: {}",
            path
        )))
    }

    /// Search for a file starting from a layer ID (helper for recursion).
    fn search_by_layer_id(
        &self,
        layer_id: &str,
        path: &str,
        depth: usize,
    ) -> Result<cap_std::fs::File> {
        // Maximum depth to prevent infinite loops
        const MAX_DEPTH: usize = 500;

        if depth >= MAX_DEPTH {
            return Err(StorageError::TarSplitError(format!(
                "Layer chain exceeds maximum depth of {} while searching for file: {}",
                MAX_DEPTH, path
            )));
        }

        // Try to open file in this layer
        match self.open_file_in_layer(layer_id, path) {
            Ok(file) => return Ok(file),
            Err(StorageError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                // File not found, check parents
            }
            Err(e) => return Err(e),
        }

        // Read parent links for this layer
        let parent_links = self.read_layer_parent_links(layer_id)?;

        // Try each parent
        for link_id in parent_links {
            let parent_id = self.resolve_link_direct(&link_id)?;
            match self.search_by_layer_id(&parent_id, path, depth + 1) {
                Ok(file) => return Ok(file),
                Err(_) => continue,
            }
        }

        Err(StorageError::TarSplitError(format!(
            "File not found in layer chain: {}",
            path
        )))
    }

    /// Resolve a link ID to layer ID by directly reading the symlink.
    fn resolve_link_direct(&self, link_id: &str) -> Result<String> {
        let overlay_dir = self.storage_root.open_dir("overlay")?;
        let link_dir = overlay_dir.open_dir("l")?;
        let target = link_dir.read_link(link_id).map_err(|e| {
            StorageError::LinkReadError(format!("Failed to read link {}: {}", link_id, e))
        })?;

        // Extract layer ID from symlink target (format: ../<layer-id>/diff)
        let target_str = target.to_str().ok_or_else(|| {
            StorageError::LinkReadError("Invalid UTF-8 in link target".to_string())
        })?;
        let components: Vec<&str> = target_str.split('/').collect();
        if components.len() >= 2 {
            let layer_id = components[components.len() - 2];
            if !layer_id.is_empty() && layer_id != ".." {
                return Ok(layer_id.to_string());
            }
        }
        Err(StorageError::LinkReadError(format!(
            "Invalid link target format: {}",
            target_str
        )))
    }

    /// Open a file in a specific layer's diff directory.
    fn open_file_in_layer(&self, layer_id: &str, path: &str) -> Result<cap_std::fs::File> {
        let overlay_dir = self.storage_root.open_dir("overlay")?;
        let layer_dir = overlay_dir.open_dir(layer_id)?;
        let diff_dir = layer_dir.open_dir("diff")?;
        diff_dir.open(path).map_err(StorageError::Io)
    }

    /// Read parent link IDs from a layer's lower file.
    fn read_layer_parent_links(&self, layer_id: &str) -> Result<Vec<String>> {
        let overlay_dir = self.storage_root.open_dir("overlay")?;
        let layer_dir = overlay_dir.open_dir(layer_id)?;

        match layer_dir.read_to_string("lower") {
            Ok(content) => Ok(content
                .trim()
                .split(':')
                .filter_map(|s| s.strip_prefix("l/"))
                .map(|s| s.to_string())
                .collect()),
            Err(_) => Ok(Vec::new()), // Base layer has no lower file
        }
    }

    /// Verify CRC64-ISO checksum of a file.
    fn verify_crc64(
        &self,
        file: &mut cap_std::fs::File,
        expected_b64: &str,
        size: u64,
    ) -> Result<()> {
        use std::io::Read;

        // Decode base64 checksum
        let expected_bytes = BASE64_STANDARD.decode(expected_b64).map_err(|e| {
            StorageError::TarSplitError(format!("Failed to decode base64 CRC64: {}", e))
        })?;

        if expected_bytes.len() != 8 {
            return Err(StorageError::TarSplitError(format!(
                "Invalid CRC64 length: {} bytes",
                expected_bytes.len()
            )));
        }

        // Convert to u64 (big-endian)
        let expected = u64::from_be_bytes(expected_bytes.try_into().unwrap());

        // Compute CRC64 of file content
        let mut digest = CRC64_ISO.digest();
        let mut buffer = vec![0u8; 8192];
        let mut bytes_read = 0u64;

        loop {
            let n = file.read(&mut buffer).map_err(|e| {
                StorageError::TarSplitError(format!(
                    "Failed to read file for CRC64 verification: {}",
                    e
                ))
            })?;
            if n == 0 {
                break;
            }
            digest.update(&buffer[..n]);
            bytes_read += n as u64;
        }

        // Verify size matches
        if bytes_read != size {
            return Err(StorageError::TarSplitError(format!(
                "File size mismatch: expected {}, got {}",
                size, bytes_read
            )));
        }

        let computed = digest.finalize();
        if computed != expected {
            return Err(StorageError::TarSplitError(format!(
                "CRC64 mismatch: expected {:016x}, got {:016x}",
                expected, computed
            )));
        }

        Ok(())
    }

    /// Read the next item from the tar-split stream.
    ///
    /// Returns:
    /// - `TarSplitItem::Segment(bytes)`: Raw TAR header/padding bytes to write directly
    /// - `TarSplitItem::FileContent(fd, size)`: File descriptor for content + size for padding
    ///
    /// The segment bytes come from tar-split metadata and must be written as-is to preserve
    /// byte-identical TAR reconstruction. File descriptors are opened read-only with O_CLOEXEC.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(item))` - Next item was read successfully
    /// - `Ok(None)` - End of stream reached
    /// - `Err(...)` - Error occurred during reading or file opening
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::{Storage, Layer, TarSplitFdStream, TarSplitItem};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let storage = Storage::discover()?;
    /// let layer = Layer::open(&storage, "layer-id")?;
    /// let mut stream = TarSplitFdStream::new(&storage, &layer)?;
    ///
    /// while let Some(item) = stream.next()? {
    ///     match item {
    ///         TarSplitItem::Segment(bytes) => {
    ///             // Write raw header/padding bytes
    ///         }
    ///         TarSplitItem::FileContent(fd, size) => {
    ///             // Write file content + padding
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<TarSplitItem>> {
        loop {
            // Read next line from NDJSON stream
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => {
                    // End of stream - return any buffered trailing segments
                    if let Some(payload) = self.current_segment_payload.take() {
                        self.trailing_segments.push(payload);
                    }
                    if let Some(payload) = self.trailing_segments.pop() {
                        return Ok(Some(TarSplitItem::Segment(payload)));
                    }
                    return Ok(None);
                }
                Ok(_) => {
                    // Parse NDJSON entry
                    let raw: TarSplitEntryRaw = serde_json::from_str(&line).map_err(|e| {
                        StorageError::TarSplitError(format!(
                            "Failed to parse tar-split entry: {}",
                            e
                        ))
                    })?;
                    let entry = TarSplitEntry::from_raw(raw)?;

                    match entry {
                        TarSplitEntry::Segment { payload } => {
                            // Type 2: SegmentType with raw TAR header/padding bytes
                            // Return these bytes directly without modification

                            if let Some(payload_b64) = payload {
                                let payload_bytes =
                                    BASE64_STANDARD.decode(&payload_b64).map_err(|e| {
                                        StorageError::TarSplitError(format!(
                                            "Failed to decode base64 payload: {}",
                                            e
                                        ))
                                    })?;

                                // Return segment immediately
                                return Ok(Some(TarSplitItem::Segment(payload_bytes)));
                            }
                            // Empty segment, continue
                        }

                        TarSplitEntry::File { name, size, crc64 } => {
                            // Type 1: FileType with file content metadata
                            self.entry_count += 1;

                            // Check if this file has content to write
                            let file_size = size.unwrap_or(0);
                            if file_size > 0 {
                                // Regular file with content - open it
                                let path = name.as_ref().ok_or_else(|| {
                                    StorageError::TarSplitError(
                                        "FileType entry missing name".to_string(),
                                    )
                                })?;

                                let mut file = self.open_file_in_chain(path)?;

                                // Verify CRC64 if provided
                                if let Some(ref crc64_b64) = crc64 {
                                    self.verify_crc64(&mut file, crc64_b64, file_size)?;

                                    // Reopen file since we consumed it for CRC check
                                    file = self.open_file_in_chain(path)?;
                                }

                                // Convert to OwnedFd and return
                                let std_file = file.into_std();
                                let owned_fd: OwnedFd = std_file.into();
                                return Ok(Some(TarSplitItem::FileContent(owned_fd, file_size)));
                            }
                            // Empty file or directory - header already in preceding Segment, continue
                        }
                    }
                }
                Err(e) => {
                    return Err(StorageError::TarSplitError(format!(
                        "Failed to read tar-split line: {}",
                        e
                    )));
                }
            }
        }
    }

    /// Get the number of entries processed so far.
    ///
    /// Useful for debugging and progress tracking.
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }
}

// Example helper function showing how to open a file and convert to OwnedFd
// This would be used in the full implementation of next()
#[allow(dead_code)]
fn open_file_as_fd(layer: &Layer, path: &str) -> Result<OwnedFd> {
    // Normalize path (remove leading ./)
    let normalized_path = path.strip_prefix("./").unwrap_or(path);

    // Open file using layer's diff_dir Dir handle (fd-relative)
    let file = layer.diff_dir.open(normalized_path).map_err(|e| {
        StorageError::TarSplitError(format!("Failed to open file {}: {}", normalized_path, e))
    })?;

    // Convert cap_std::fs::File to std::fs::File, then to OwnedFd
    // This transfers ownership of the file descriptor
    let std_file = file.into_std();
    let owned_fd: OwnedFd = std_file.into();

    Ok(owned_fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tar_header_type_checks() {
        let mut header = TarHeader {
            name: "test.txt".to_string(),
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            size: 100,
            mtime: 0,
            typeflag: b'0',
            linkname: String::new(),
            uname: "user".to_string(),
            gname: "group".to_string(),
            devmajor: 0,
            devminor: 0,
        };

        assert!(header.is_regular_file());
        assert!(!header.is_directory());
        assert!(!header.is_symlink());

        header.typeflag = b'5';
        assert!(!header.is_regular_file());
        assert!(header.is_directory());

        header.typeflag = b'2';
        assert!(header.is_symlink());
    }

    #[test]
    fn test_tar_split_entry_deserialization() {
        // Test type 2 (Segment) with integer discriminant
        let json_segment = r#"{"type":2,"payload":"dXN0YXIAMDA="}"#;
        let raw: TarSplitEntryRaw = serde_json::from_str(json_segment).unwrap();
        let entry = TarSplitEntry::from_raw(raw).unwrap();
        match entry {
            TarSplitEntry::Segment { payload } => {
                assert_eq!(payload, Some("dXN0YXIAMDA=".to_string()));
            }
            _ => panic!("Expected Segment variant"),
        }

        // Test type 1 (File) with integer discriminant
        let json_file = r#"{"type":1,"name":"./etc/hosts","size":123,"crc64":"AAAAAAAAAA=="}"#;
        let raw: TarSplitEntryRaw = serde_json::from_str(json_file).unwrap();
        let entry = TarSplitEntry::from_raw(raw).unwrap();
        match entry {
            TarSplitEntry::File { name, size, crc64 } => {
                assert_eq!(name, Some("./etc/hosts".to_string()));
                assert_eq!(size, Some(123));
                assert_eq!(crc64, Some("AAAAAAAAAA==".to_string()));
            }
            _ => panic!("Expected File variant"),
        }

        // Test invalid type
        let json_invalid = r#"{"type":99}"#;
        let raw: TarSplitEntryRaw = serde_json::from_str(json_invalid).unwrap();
        let result = TarSplitEntry::from_raw(raw);
        assert!(result.is_err());
    }

    #[test]
    #[ignore] // Requires actual storage with tar-split files
    fn test_tar_split_stream_creation() {
        // This test would require setting up actual storage
        // Mark as ignored for CI
    }

    #[test]
    fn test_tar_header_checksum_validation() {
        // Create a valid tar header with correct checksum
        let mut header = [0u8; 512];

        // Set name: "test.txt"
        header[..8].copy_from_slice(b"test.txt");

        // Set mode: "0000644\0" (octal)
        header[100..108].copy_from_slice(b"0000644\0");

        // Set uid: "0001750\0"
        header[108..116].copy_from_slice(b"0001750\0");

        // Set gid: "0001750\0"
        header[116..124].copy_from_slice(b"0001750\0");

        // Set size: "00000000144\0" (100 bytes in octal)
        header[124..136].copy_from_slice(b"00000000144\0");

        // Set mtime: "14722350757\0"
        header[136..148].copy_from_slice(b"14722350757\0");

        // Set typeflag: '0' (regular file)
        header[156] = b'0';

        // Set magic: "ustar\0"
        header[257..263].copy_from_slice(b"ustar\0");

        // Set version: "00"
        header[263..265].copy_from_slice(b"00");

        // Compute checksum: sum of all bytes with checksum field as spaces
        let checksum: u32 = header[..148]
            .iter()
            .chain(std::iter::repeat(&b' ').take(8))
            .chain(header[156..512].iter())
            .map(|&b| b as u32)
            .sum();

        // Set checksum in octal format with trailing space and null
        let checksum_str = format!("{:06o}\0 ", checksum);
        header[148..156].copy_from_slice(checksum_str.as_bytes());

        // Parse should succeed
        let result = TarHeader::from_bytes(&header);
        assert!(result.is_ok(), "Valid header should parse: {:?}", result);

        let parsed = result.unwrap();
        assert_eq!(parsed.name, "test.txt");
        assert_eq!(parsed.mode, 0o644);
        assert_eq!(parsed.typeflag, b'0');
        assert!(parsed.is_regular_file());
    }

    #[test]
    fn test_tar_header_checksum_rejects_invalid() {
        // Create an invalid tar header (all zeros except for some fields)
        let mut header = [0u8; 512];
        header[0..5].copy_from_slice(b"test\0");

        // No valid checksum - should fail
        let result = TarHeader::from_bytes(&header);
        assert!(result.is_err(), "Invalid header should be rejected");

        // Check that it's rejected due to checksum
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("checksum") || err.contains("Empty"),
            "Error should mention checksum: {}",
            err
        );
    }

    #[test]
    fn test_tar_header_checksum_rejects_padding() {
        // Simulate padding bytes (all zeros) - should fail checksum validation
        let header = [0u8; 512];
        let result = TarHeader::from_bytes(&header);
        assert!(result.is_err(), "Padding block should be rejected");
    }
}
