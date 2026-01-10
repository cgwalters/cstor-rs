//! Table of Contents (TOC) for container image layers.
//!
//! This module provides a serializable representation of layer contents,
//! inspired by the [eStargz TOC format](https://github.com/containerd/stargz-snapshotter/blob/main/docs/estargz.md).
//!
//! The TOC provides a structured view of all files in a layer without requiring
//! tar serialization. This enables efficient operations like:
//! - Listing layer contents
//! - Extracting specific files
//! - Comparing layers
//! - Building filesystem indexes
//!
//! # Example
//!
//! ```no_run
//! use cstor_rs::{Storage, Layer, Toc};
//!
//! let storage = Storage::discover()?;
//! let layer = Layer::open(&storage, "abc123")?;
//! let toc = Toc::from_layer(&storage, &layer)?;
//!
//! for entry in &toc.entries {
//!     println!("{}: {:?}", entry.name.display(), entry.entry_type);
//! }
//! # Ok::<(), cstor_rs::StorageError>(())
//! ```

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use tracing::debug;

use crate::error::{Result, StorageError};
use crate::generic_tree::{FileSystem, Inode, TreeError};
use crate::layer::Layer;
use crate::storage::Storage;
use crate::tar_split::{TarHeader, TarSplitFdStream, TarSplitItem};

/// Table of Contents for a container image layer.
///
/// Contains metadata for all files in the layer, enabling operations
/// without tar serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Toc {
    /// Version of the TOC format (currently 1).
    pub version: u32,

    /// All entries in the layer.
    pub entries: Vec<TocEntry>,
}

impl Default for Toc {
    fn default() -> Self {
        Self::new()
    }
}

/// Type of a TOC entry.
///
/// Matches the eStargz specification types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TocEntryType {
    /// Regular file
    Reg,
    /// Directory
    Dir,
    /// Symbolic link
    Symlink,
    /// Hard link
    Hardlink,
    /// Character device
    Char,
    /// Block device
    Block,
    /// FIFO (named pipe)
    Fifo,
}

impl TocEntryType {
    /// Convert from tar typeflag byte.
    pub fn from_typeflag(typeflag: u8) -> Option<Self> {
        match typeflag {
            b'0' | b'\0' => Some(TocEntryType::Reg),
            b'1' => Some(TocEntryType::Hardlink),
            b'2' => Some(TocEntryType::Symlink),
            b'3' => Some(TocEntryType::Char),
            b'4' => Some(TocEntryType::Block),
            b'5' => Some(TocEntryType::Dir),
            b'6' => Some(TocEntryType::Fifo),
            _ => None,
        }
    }
}

/// Whiteout file prefix used by overlay filesystems.
///
/// Files named `.wh.<name>` indicate that `<name>` should be removed from lower layers.
/// For example, `.wh.passwd` in a directory whiteouts (deletes) the `passwd` file
/// from any lower layer.
const WHITEOUT_PREFIX: &str = ".wh.";

/// Opaque whiteout marker filename.
///
/// A file named `.wh..wh..opq` in a directory indicates that all entries in that
/// directory from lower layers should be hidden. The directory itself is preserved,
/// but its contents from lower layers are not visible. New entries in the same
/// layer (or upper layers) are still visible.
const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";

/// The suffix of OPAQUE_WHITEOUT after stripping WHITEOUT_PREFIX.
/// Computed at compile time: ".wh..wh..opq".split_at(4).1 == ".wh..opq"
const OPAQUE_WHITEOUT_SUFFIX: &str = OPAQUE_WHITEOUT.split_at(WHITEOUT_PREFIX.len()).1;

/// A single entry in the TOC.
///
/// Contains metadata about a file, directory, symlink, or other entry
/// in the layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TocEntry {
    /// Complete path in the layer (e.g., "usr/bin/bash").
    /// Does not include leading "./" or "/".
    pub name: PathBuf,

    /// Type of this entry.
    #[serde(rename = "type")]
    pub entry_type: TocEntryType,

    /// Uncompressed size for regular files.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,

    /// Modification time in RFC3339 format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modtime: Option<String>,

    /// Link target for symlinks and hardlinks.
    #[serde(rename = "linkName", skip_serializing_if = "Option::is_none")]
    pub link_name: Option<String>,

    /// Permission and mode bits.
    pub mode: u32,

    /// User ID of the owner.
    pub uid: u32,

    /// Group ID of the owner.
    pub gid: u32,

    /// Username of the owner.
    #[serde(rename = "userName", skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,

    /// Group name of the owner.
    #[serde(rename = "groupName", skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,

    /// Major device number for char/block devices.
    #[serde(rename = "devMajor", skip_serializing_if = "Option::is_none")]
    pub dev_major: Option<u32>,

    /// Minor device number for char/block devices.
    #[serde(rename = "devMinor", skip_serializing_if = "Option::is_none")]
    pub dev_minor: Option<u32>,

    /// Extended attributes (currently not populated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xattrs: Option<std::collections::HashMap<String, String>>,

    /// Digest of regular file contents (sha256:...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

impl TocEntry {
    /// Check if this entry is an opaque whiteout marker.
    ///
    /// An opaque whiteout (`.wh..wh..opq`) indicates that the directory
    /// should hide all content from lower layers.
    pub fn is_opaque_whiteout(&self) -> bool {
        self.name.file_name() == Some(OsStr::new(OPAQUE_WHITEOUT))
    }

    /// Check if this entry is a whiteout file (but not an opaque marker).
    ///
    /// A whiteout file (`.wh.<filename>`) indicates that the corresponding
    /// file should be deleted from lower layers.
    pub fn is_whiteout(&self) -> bool {
        self.whiteout_target().is_some()
    }

    /// Get the target path that this whiteout entry removes.
    ///
    /// For a whiteout at `foo/bar/.wh.baz`, returns `Some("foo/bar/baz")`.
    /// Returns `None` if this is not a whiteout entry.
    pub fn whiteout_target(&self) -> Option<PathBuf> {
        let filename = self.name.file_name()?.to_str()?;

        // Must start with whiteout prefix and not be the opaque marker
        let target_filename = filename.strip_prefix(WHITEOUT_PREFIX)?;
        if target_filename == OPAQUE_WHITEOUT_SUFFIX {
            // This is an opaque whiteout, not a regular whiteout
            return None;
        }

        match self.name.parent() {
            Some(p) if !p.as_os_str().is_empty() => Some(p.join(target_filename)),
            _ => Some(PathBuf::from(target_filename)),
        }
    }

    /// Get the directory path for an opaque whiteout marker.
    ///
    /// For an opaque marker at `foo/bar/.wh..wh..opq`, returns `Some(Path::new("foo/bar"))`.
    /// Returns `None` if this is not an opaque whiteout.
    pub fn opaque_dir(&self) -> Option<&Path> {
        if !self.is_opaque_whiteout() {
            return None;
        }

        // Return the parent directory, or empty path for root
        Some(self.name.parent().unwrap_or(Path::new("")))
    }

    /// Create a TocEntry from a TarHeader.
    pub fn from_tar_header(header: &TarHeader) -> Option<Self> {
        let entry_type = TocEntryType::from_typeflag(header.typeflag)?;

        // Normalize the name (strip leading "./")
        let name = PathBuf::from(header.normalized_name());

        // Skip empty names (root directory marker)
        if name.as_os_str().is_empty() {
            return None;
        }

        // Convert mtime to RFC3339 format
        let modtime = if header.mtime > 0 {
            Some(format_unix_time(header.mtime))
        } else {
            None
        };

        // Link name for symlinks and hardlinks
        let link_name =
            if entry_type == TocEntryType::Symlink || entry_type == TocEntryType::Hardlink {
                let ln = header
                    .linkname
                    .strip_prefix("./")
                    .unwrap_or(&header.linkname);
                if ln.is_empty() {
                    None
                } else {
                    Some(ln.to_string())
                }
            } else {
                None
            };

        // Size only for regular files
        let size = if entry_type == TocEntryType::Reg && header.size > 0 {
            Some(header.size)
        } else {
            None
        };

        // User/group names
        let user_name = if header.uname.is_empty() {
            None
        } else {
            Some(header.uname.clone())
        };
        let group_name = if header.gname.is_empty() {
            None
        } else {
            Some(header.gname.clone())
        };

        // Device numbers for char/block devices
        let (dev_major, dev_minor) =
            if entry_type == TocEntryType::Char || entry_type == TocEntryType::Block {
                (Some(header.devmajor), Some(header.devminor))
            } else {
                (None, None)
            };

        Some(TocEntry {
            name,
            entry_type,
            size,
            modtime,
            link_name,
            mode: header.mode,
            uid: header.uid,
            gid: header.gid,
            user_name,
            group_name,
            dev_major,
            dev_minor,
            xattrs: None,
            digest: None,
        })
    }
}

/// Format a Unix timestamp as RFC3339.
fn format_unix_time(secs: i64) -> String {
    // Simple implementation without external crate
    // For production, consider using chrono or time crate
    const SECS_PER_DAY: i64 = 86400;
    const DAYS_PER_YEAR: i64 = 365;
    const DAYS_PER_4_YEARS: i64 = 1461;
    const DAYS_PER_100_YEARS: i64 = 36524;
    const DAYS_PER_400_YEARS: i64 = 146097;

    let mut days = secs / SECS_PER_DAY;
    let day_secs = secs % SECS_PER_DAY;

    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    // Days since 1970-01-01
    days += 719468; // Days from year 0 to 1970

    let era = if days >= 0 {
        days / DAYS_PER_400_YEARS
    } else {
        (days - DAYS_PER_400_YEARS + 1) / DAYS_PER_400_YEARS
    };
    let doe = days - era * DAYS_PER_400_YEARS;
    let yoe = (doe - doe / DAYS_PER_4_YEARS + doe / DAYS_PER_100_YEARS - doe / DAYS_PER_400_YEARS)
        / DAYS_PER_YEAR;
    let year = yoe + era * 400;
    let doy = doe - (DAYS_PER_YEAR * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

impl Toc {
    /// Create an empty TOC.
    pub fn new() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }

    /// Merge another TOC into this one, processing whiteouts.
    ///
    /// This implements overlay filesystem semantics:
    /// - Opaque whiteouts (`.wh..wh..opq`) remove all entries under that directory
    /// - Regular whiteouts (`.wh.<name>`) remove the corresponding entry
    /// - Other entries override existing entries at the same path
    ///
    /// Uses a secure tree structure that rejects paths containing `.` or `..`
    /// components to prevent path canonicalization attacks from malicious tar
    /// archives.
    ///
    /// Entries are processed in order, so later layers override earlier ones.
    ///
    /// # Example
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use cstor_rs::toc::{Toc, TocEntry, TocEntryType};
    ///
    /// let mut base = Toc::new();
    /// base.entries.push(TocEntry {
    ///     name: PathBuf::from("etc/passwd"),
    ///     entry_type: TocEntryType::Reg,
    ///     mode: 0o644,
    ///     uid: 0,
    ///     gid: 0,
    ///     size: Some(100),
    ///     modtime: None,
    ///     link_name: None,
    ///     user_name: None,
    ///     group_name: None,
    ///     dev_major: None,
    ///     dev_minor: None,
    ///     xattrs: None,
    ///     digest: None,
    /// });
    ///
    /// let mut upper = Toc::new();
    /// upper.entries.push(TocEntry {
    ///     name: PathBuf::from("etc/.wh.passwd"),
    ///     entry_type: TocEntryType::Reg,
    ///     mode: 0o644,
    ///     uid: 0,
    ///     gid: 0,
    ///     size: Some(0),
    ///     modtime: None,
    ///     link_name: None,
    ///     user_name: None,
    ///     group_name: None,
    ///     dev_major: None,
    ///     dev_minor: None,
    ///     xattrs: None,
    ///     digest: None,
    /// });
    ///
    /// base.merge(upper)?;
    /// assert!(base.entries.is_empty()); // etc/passwd was whited out
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn merge(&mut self, upper: Toc) -> Result<()> {
        // Build a tree from current entries for secure path operations.
        // The tree validates paths (rejecting . and .. components) and
        // provides efficient directory clearing for opaque whiteouts.
        // All entries are stored as leaves - the tree structure is for
        // path handling, not representing the filesystem hierarchy.
        let mut tree: FileSystem<TocEntry> = FileSystem::new();

        // Insert existing entries into tree.
        // InvalidFilename errors (security) are propagated, structural errors are logged.
        for entry in self.entries.drain(..) {
            if let Err(e) = tree.insert(entry.name.as_os_str(), Inode::new_leaf(entry.clone())) {
                match e {
                    TreeError::InvalidFilename(_) => return Err(e.into()),
                    _ => debug!("skipping entry {:?}: {e}", entry.name),
                }
            }
        }

        // Process each entry from the upper layer
        for entry in upper.entries {
            if let Some(opaque_dir) = entry.opaque_dir() {
                // Opaque whiteout: clear all entries UNDER this directory from lower layers.
                // The directory itself is NOT removed - only its contents from lower layers.
                if opaque_dir.as_os_str().is_empty() {
                    // Root opaque marker clears everything
                    tree = FileSystem::new();
                } else {
                    // Clear contents under this directory using tree operation.
                    // First, remove all entries that start with this prefix.
                    // We need to collect and remove since clear_directory only
                    // clears directory inode contents, but we store entries as leaves.
                    let paths_to_remove: Vec<String> = tree
                        .iter_leaves()
                        .filter(|(path, _)| {
                            Path::new(path).starts_with(opaque_dir) && Path::new(path) != opaque_dir
                        })
                        .map(|(path, _)| path.clone())
                        .collect();
                    for path in paths_to_remove {
                        if let Err(e) = tree.remove(OsStr::new(&path)) {
                            debug!("whiteout remove of {path:?} failed: {e}");
                        }
                    }
                }
                // Don't add the opaque marker itself to the TOC
            } else if let Some(target) = entry.whiteout_target() {
                // Regular whiteout: remove the target entry and anything under it.
                // First remove the target itself.
                if let Err(e) = tree.remove(target.as_os_str()) {
                    debug!("whiteout remove of {target:?} failed: {e}");
                }
                // Then remove all entries under the target (if it was a directory).
                let paths_to_remove: Vec<String> = tree
                    .iter_leaves()
                    .filter(|(path, _)| Path::new(path).starts_with(&target))
                    .map(|(path, _)| path.clone())
                    .collect();
                for path in paths_to_remove {
                    if let Err(e) = tree.remove(OsStr::new(&path)) {
                        debug!("whiteout remove of {path:?} failed: {e}");
                    }
                }
                // Don't add the whiteout marker itself to the TOC
            } else {
                // Regular entry: add or replace.
                // InvalidFilename errors (security) are propagated, structural errors are logged.
                if let Err(e) = tree.insert(entry.name.as_os_str(), Inode::new_leaf(entry.clone()))
                {
                    match e {
                        TreeError::InvalidFilename(_) => return Err(e.into()),
                        _ => debug!("skipping entry {:?}: {e}", entry.name),
                    }
                }
            }
        }

        // Convert tree back to entries vector (already sorted by tree iteration order)
        self.entries = tree
            .into_leaves()
            .map(|(path, entry)| {
                // Update the name to the canonical path from the tree
                let mut e = entry;
                e.name = PathBuf::from(path);
                e
            })
            .collect();

        Ok(())
    }

    /// Build a TOC from a layer by reading its tar-split metadata.
    ///
    /// This iterates through all entries in the layer and extracts
    /// metadata without reading file contents.
    pub fn from_layer(storage: &Storage, layer: &Layer) -> Result<Self> {
        let mut stream = TarSplitFdStream::new(storage, layer)?;
        let mut entries = Vec::new();
        let mut current_header: Option<TarHeader> = None;
        let mut gnu_long_name: Option<String> = None;
        let mut gnu_long_linkname: Option<String> = None;
        // Track pending file size to calculate padding offset in next segment
        let mut pending_file_size: u64 = 0;

        while let Some(item) = stream.next()? {
            match item {
                TarSplitItem::Segment(bytes) => {
                    // Calculate padding offset based on previous file size
                    // Tar pads file content to 512-byte boundaries
                    let padding_offset = if pending_file_size > 0 {
                        let remainder = pending_file_size % 512;
                        if remainder > 0 {
                            (512 - remainder) as usize
                        } else {
                            0
                        }
                    } else {
                        0
                    };
                    pending_file_size = 0; // Reset for next iteration

                    // Process segment starting after padding
                    let mut offset = padding_offset;
                    while offset + 512 <= bytes.len() {
                        let block = &bytes[offset..offset + 512];

                        // Check if this is a null block (end of archive marker)
                        if block.iter().all(|&b| b == 0) {
                            offset += 512;
                            continue;
                        }

                        // Try to parse as a tar header
                        match TarHeader::from_bytes(block) {
                            Ok(new_header) => {
                                // Process pending header before storing new one
                                if let Some(mut pending) = current_header.take() {
                                    if let Some(long_name) = gnu_long_name.take() {
                                        pending.name = long_name;
                                    }
                                    if let Some(long_linkname) = gnu_long_linkname.take() {
                                        pending.linkname = long_linkname;
                                    }
                                    if !pending.is_gnu_long_name()
                                        && !pending.is_gnu_long_linkname()
                                    {
                                        if let Some(entry) = TocEntry::from_tar_header(&pending) {
                                            entries.push(entry);
                                        }
                                    }
                                }
                                current_header = Some(new_header);
                            }
                            Err(_) => {
                                // Not a valid header - skip this block
                            }
                        }
                        offset += 512;
                    }
                }
                TarSplitItem::FileContent { fd, size, .. } => {
                    // Remember the file size for calculating padding in next segment
                    pending_file_size = size;

                    if let Some(mut header) = current_header.take() {
                        // Handle GNU long name/linkname
                        if header.is_gnu_long_name() {
                            gnu_long_name = Some(read_gnu_long_string(fd, size)?);
                            continue;
                        } else if header.is_gnu_long_linkname() {
                            gnu_long_linkname = Some(read_gnu_long_string(fd, size)?);
                            continue;
                        }

                        // Apply GNU long name/linkname
                        if let Some(long_name) = gnu_long_name.take() {
                            header.name = long_name;
                        }
                        if let Some(long_linkname) = gnu_long_linkname.take() {
                            header.linkname = long_linkname;
                        }

                        if let Some(entry) = TocEntry::from_tar_header(&header) {
                            entries.push(entry);
                        }
                    }
                    // Drop the fd - we don't need to read the content
                    drop(fd);
                }
            }
        }

        // Handle final pending header
        if let Some(mut pending) = current_header.take() {
            if let Some(long_name) = gnu_long_name.take() {
                pending.name = long_name;
            }
            if let Some(long_linkname) = gnu_long_linkname.take() {
                pending.linkname = long_linkname;
            }
            if !pending.is_gnu_long_name() && !pending.is_gnu_long_linkname() {
                if let Some(entry) = TocEntry::from_tar_header(&pending) {
                    entries.push(entry);
                }
            }
        }

        Ok(Toc {
            version: 1,
            entries,
        })
    }

    /// Build a TOC for an entire image by merging all layer TOCs.
    ///
    /// Layers are processed in order (base to top), with proper overlay
    /// filesystem semantics:
    /// - Whiteout files (`.wh.<name>`) remove entries from lower layers
    /// - Opaque whiteouts (`.wh..wh..opq`) clear directory contents from lower layers
    /// - Regular entries override earlier ones at the same path
    ///
    /// The resulting TOC represents the final flattened view of the image.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::{Storage, Toc};
    ///
    /// let storage = Storage::discover()?;
    /// let images = storage.list_images()?;
    /// if let Some(image) = images.first() {
    ///     let toc = Toc::from_image(&storage, image)?;
    ///     println!("Image has {} total entries", toc.entries.len());
    /// }
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn from_image(storage: &Storage, image: &crate::image::Image) -> Result<Self> {
        let layer_ids = image.layers()?;
        let mut merged = Self::new();

        // Process layers in order (base to top), merging with whiteout handling
        for layer_id in &layer_ids {
            let layer = Layer::open(storage, layer_id)?;
            let layer_toc = Self::from_layer(storage, &layer)?;
            merged.merge(layer_toc)?;
        }

        Ok(merged)
    }

    /// Build a merged TOC for an image along with layer source mapping.
    ///
    /// Returns the merged TOC and a map from path to the layer ID that
    /// contains the file. This is useful for extraction where you need
    /// to know which layer to read each file from.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::{Storage, Toc, Image};
    ///
    /// let storage = Storage::discover()?;
    /// let image = Image::open(&storage, "abc123...")?;
    /// let (toc, layer_map) = Toc::from_image_with_layers(&storage, &image)?;
    ///
    /// for entry in &toc.entries {
    ///     if let Some(layer_id) = layer_map.get(&entry.name) {
    ///         println!("{:?} is from layer {}", entry.name, layer_id);
    ///     }
    /// }
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn from_image_with_layers(
        storage: &Storage,
        image: &crate::image::Image,
    ) -> Result<(Self, HashMap<PathBuf, String>)> {
        let layer_ids = image.layers()?;

        // Use a tree that stores (TocEntry, layer_id) pairs.
        // This ensures path validation and keeps TOC and layer map in sync.
        let mut tree: FileSystem<(TocEntry, String)> = FileSystem::new();

        // Process layers in order (base to top)
        for layer_id in &layer_ids {
            let layer = Layer::open(storage, layer_id)?;
            let layer_toc = Self::from_layer(storage, &layer)?;

            // Process each entry from this layer
            for entry in layer_toc.entries {
                if let Some(opaque_dir) = entry.opaque_dir() {
                    // Opaque whiteout: clear all entries UNDER this directory.
                    if opaque_dir.as_os_str().is_empty() {
                        tree = FileSystem::new();
                    } else {
                        // Remove all entries that start with this prefix
                        let paths_to_remove: Vec<String> = tree
                            .iter_leaves()
                            .filter(|(path, _)| {
                                Path::new(path).starts_with(opaque_dir)
                                    && Path::new(path) != opaque_dir
                            })
                            .map(|(path, _)| path.clone())
                            .collect();
                        for path in paths_to_remove {
                            if let Err(e) = tree.remove(OsStr::new(&path)) {
                                debug!("whiteout remove of {path:?} failed: {e}");
                            }
                        }
                    }
                    // Don't add opaque marker
                } else if let Some(target) = entry.whiteout_target() {
                    // Regular whiteout: remove the target and anything under it.
                    if let Err(e) = tree.remove(target.as_os_str()) {
                        debug!("whiteout remove of {target:?} failed: {e}");
                    }
                    let paths_to_remove: Vec<String> = tree
                        .iter_leaves()
                        .filter(|(path, _)| Path::new(path).starts_with(&target))
                        .map(|(path, _)| path.clone())
                        .collect();
                    for path in paths_to_remove {
                        if let Err(e) = tree.remove(OsStr::new(&path)) {
                            debug!("whiteout remove of {path:?} failed: {e}");
                        }
                    }
                    // Don't add whiteout marker
                } else {
                    // Regular entry: add or replace with layer ID.
                    // InvalidFilename errors (security) are propagated, structural errors are logged.
                    let data = (entry.clone(), layer_id.clone());
                    if let Err(e) = tree.insert(entry.name.as_os_str(), Inode::new_leaf(data)) {
                        match e {
                            TreeError::InvalidFilename(_) => return Err(e.into()),
                            _ => debug!("skipping entry {:?}: {e}", entry.name),
                        }
                    }
                }
            }
        }

        // Convert tree to TOC entries and layer map
        let mut entries = Vec::new();
        let mut layer_map = HashMap::new();

        for (path, (entry, layer_id)) in tree.into_leaves() {
            let mut e = entry;
            let path = PathBuf::from(path);
            e.name = path.clone();
            entries.push(e);
            layer_map.insert(path, layer_id);
        }

        Ok((
            Self {
                version: 1,
                entries,
            },
            layer_map,
        ))
    }
}

/// Read a GNU long name/linkname from a file descriptor.
fn read_gnu_long_string(fd: std::os::unix::io::OwnedFd, size: u64) -> Result<String> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::from(fd);
    let mut buffer = vec![0u8; size as usize];
    file.read_exact(&mut buffer)
        .map_err(|e| StorageError::TarSplitError(format!("Failed to read GNU long name: {}", e)))?;

    // Remove trailing null bytes
    let end = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
    String::from_utf8(buffer[..end].to_vec()).map_err(|e| {
        StorageError::TarSplitError(format!("GNU long name is not valid UTF-8: {}", e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_unix_time() {
        // 2024-01-15T12:40:45Z
        assert_eq!(format_unix_time(1705322445), "2024-01-15T12:40:45Z");
        // Unix epoch
        assert_eq!(format_unix_time(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_toc_entry_type_from_typeflag() {
        assert_eq!(TocEntryType::from_typeflag(b'0'), Some(TocEntryType::Reg));
        assert_eq!(TocEntryType::from_typeflag(b'\0'), Some(TocEntryType::Reg));
        assert_eq!(
            TocEntryType::from_typeflag(b'1'),
            Some(TocEntryType::Hardlink)
        );
        assert_eq!(
            TocEntryType::from_typeflag(b'2'),
            Some(TocEntryType::Symlink)
        );
        assert_eq!(TocEntryType::from_typeflag(b'5'), Some(TocEntryType::Dir));
        assert_eq!(TocEntryType::from_typeflag(b'L'), None); // GNU extension
    }

    /// Helper to create a minimal TocEntry for testing
    fn make_entry(name: &str) -> TocEntry {
        TocEntry {
            name: PathBuf::from(name),
            entry_type: TocEntryType::Reg,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size: Some(100),
            modtime: None,
            link_name: None,
            user_name: None,
            group_name: None,
            dev_major: None,
            dev_minor: None,
            xattrs: None,
            digest: None,
        }
    }

    fn make_dir_entry(name: &str) -> TocEntry {
        TocEntry {
            name: PathBuf::from(name),
            entry_type: TocEntryType::Dir,
            mode: 0o755,
            uid: 0,
            gid: 0,
            size: None,
            modtime: None,
            link_name: None,
            user_name: None,
            group_name: None,
            dev_major: None,
            dev_minor: None,
            xattrs: None,
            digest: None,
        }
    }

    #[test]
    fn test_is_whiteout() {
        assert!(make_entry(".wh.foo").is_whiteout());
        assert!(make_entry("etc/.wh.passwd").is_whiteout());
        assert!(make_entry("usr/bin/.wh.bash").is_whiteout());

        // Not whiteouts
        assert!(!make_entry("foo").is_whiteout());
        assert!(!make_entry("etc/passwd").is_whiteout());
        // Opaque markers are NOT regular whiteouts
        assert!(!make_entry(".wh..wh..opq").is_whiteout());
        assert!(!make_entry("etc/.wh..wh..opq").is_whiteout());
    }

    #[test]
    fn test_is_opaque_whiteout() {
        assert!(make_entry(".wh..wh..opq").is_opaque_whiteout());
        assert!(make_entry("etc/.wh..wh..opq").is_opaque_whiteout());
        assert!(make_entry("usr/share/doc/.wh..wh..opq").is_opaque_whiteout());

        // Not opaque whiteouts
        assert!(!make_entry(".wh.foo").is_opaque_whiteout());
        assert!(!make_entry("etc/.wh.passwd").is_opaque_whiteout());
        assert!(!make_entry("etc/passwd").is_opaque_whiteout());
    }

    #[test]
    fn test_whiteout_target() {
        assert_eq!(
            make_entry(".wh.foo").whiteout_target(),
            Some(PathBuf::from("foo"))
        );
        assert_eq!(
            make_entry("etc/.wh.passwd").whiteout_target(),
            Some(PathBuf::from("etc/passwd"))
        );
        assert_eq!(
            make_entry("usr/bin/.wh.bash").whiteout_target(),
            Some(PathBuf::from("usr/bin/bash"))
        );

        // Not whiteouts return None
        assert_eq!(make_entry("foo").whiteout_target(), None);
        assert_eq!(make_entry(".wh..wh..opq").whiteout_target(), None);
    }

    #[test]
    fn test_opaque_dir() {
        assert_eq!(make_entry(".wh..wh..opq").opaque_dir(), Some(Path::new("")));
        assert_eq!(
            make_entry("etc/.wh..wh..opq").opaque_dir(),
            Some(Path::new("etc"))
        );
        assert_eq!(
            make_entry("usr/share/doc/.wh..wh..opq").opaque_dir(),
            Some(Path::new("usr/share/doc"))
        );

        // Not opaque whiteouts return None
        assert_eq!(make_entry("foo").opaque_dir(), None);
        assert_eq!(make_entry(".wh.foo").opaque_dir(), None);
    }

    #[test]
    fn test_merge_simple_override() {
        // Layer 1: etc/passwd
        // Layer 2: etc/passwd (updated)
        // Result: etc/passwd from layer 2
        let mut base = Toc::new();
        base.entries.push(make_entry("etc/passwd"));

        let mut upper = Toc::new();
        let mut upper_entry = make_entry("etc/passwd");
        upper_entry.size = Some(200); // Different size to distinguish
        upper.entries.push(upper_entry);

        base.merge(upper).unwrap();

        assert_eq!(base.entries.len(), 1);
        assert_eq!(base.entries[0].name, Path::new("etc/passwd"));
        assert_eq!(base.entries[0].size, Some(200)); // Upper layer's version
    }

    #[test]
    fn test_merge_whiteout_removes_file() {
        // Layer 1: etc/passwd, etc/shadow
        // Layer 2: .wh.passwd (whiteout)
        // Result: etc/shadow only
        let mut base = Toc::new();
        base.entries.push(make_entry("etc/passwd"));
        base.entries.push(make_entry("etc/shadow"));

        let mut upper = Toc::new();
        upper.entries.push(make_entry("etc/.wh.passwd"));

        base.merge(upper).unwrap();

        assert_eq!(base.entries.len(), 1);
        assert_eq!(base.entries[0].name, Path::new("etc/shadow"));
    }

    #[test]
    fn test_merge_whiteout_removes_directory_recursively() {
        // Layer 1: usr/share/doc, usr/share/doc/readme.txt, usr/bin/bash
        // Layer 2: .wh.doc (whiteout for directory)
        // Result: usr/bin/bash only
        let mut base = Toc::new();
        base.entries.push(make_dir_entry("usr/share/doc"));
        base.entries.push(make_entry("usr/share/doc/readme.txt"));
        base.entries.push(make_entry("usr/bin/bash"));

        let mut upper = Toc::new();
        upper.entries.push(make_entry("usr/share/.wh.doc"));

        base.merge(upper).unwrap();

        assert_eq!(base.entries.len(), 1);
        assert_eq!(base.entries[0].name, Path::new("usr/bin/bash"));
    }

    #[test]
    fn test_merge_opaque_clears_directory_contents() {
        // Layer 1: etc, etc/passwd, etc/shadow, usr/bin/bash
        // Layer 2: etc/.wh..wh..opq (opaque marker)
        // Result: etc (directory preserved), usr/bin/bash
        // The opaque marker clears contents UNDER etc/, but not etc/ itself
        let mut base = Toc::new();
        base.entries.push(make_dir_entry("etc"));
        base.entries.push(make_entry("etc/passwd"));
        base.entries.push(make_entry("etc/shadow"));
        base.entries.push(make_entry("usr/bin/bash"));

        let mut upper = Toc::new();
        upper.entries.push(make_entry("etc/.wh..wh..opq"));

        base.merge(upper).unwrap();

        assert_eq!(base.entries.len(), 2);
        assert_eq!(base.entries[0].name, Path::new("etc"));
        assert_eq!(base.entries[1].name, Path::new("usr/bin/bash"));
    }

    #[test]
    fn test_merge_opaque_then_recreate() {
        // Layer 1: etc/passwd, etc/shadow
        // Layer 2: etc/.wh..wh..opq, etc/hosts (opaque then new file)
        // Result: etc/hosts only
        let mut base = Toc::new();
        base.entries.push(make_entry("etc/passwd"));
        base.entries.push(make_entry("etc/shadow"));

        let mut upper = Toc::new();
        upper.entries.push(make_entry("etc/.wh..wh..opq"));
        upper.entries.push(make_entry("etc/hosts"));

        base.merge(upper).unwrap();

        assert_eq!(base.entries.len(), 1);
        assert_eq!(base.entries[0].name, Path::new("etc/hosts"));
    }

    #[test]
    fn test_merge_whiteout_then_recreate() {
        // Layer 1: etc/passwd
        // Layer 2: etc/.wh.passwd
        // Layer 3: etc/passwd (recreated)
        // Result: etc/passwd from layer 3
        let mut base = Toc::new();
        base.entries.push(make_entry("etc/passwd"));

        let mut layer2 = Toc::new();
        layer2.entries.push(make_entry("etc/.wh.passwd"));

        let mut layer3 = Toc::new();
        let mut recreated = make_entry("etc/passwd");
        recreated.size = Some(300);
        layer3.entries.push(recreated);

        base.merge(layer2).unwrap();
        assert!(base.entries.is_empty()); // Whiteout removed it

        base.merge(layer3).unwrap();
        assert_eq!(base.entries.len(), 1);
        assert_eq!(base.entries[0].name, Path::new("etc/passwd"));
        assert_eq!(base.entries[0].size, Some(300));
    }

    #[test]
    fn test_merge_root_opaque() {
        // Layer 1: etc/passwd, usr/bin/bash
        // Layer 2: .wh..wh..opq (root opaque - clears everything)
        // Result: empty
        let mut base = Toc::new();
        base.entries.push(make_entry("etc/passwd"));
        base.entries.push(make_entry("usr/bin/bash"));

        let mut upper = Toc::new();
        upper.entries.push(make_entry(".wh..wh..opq"));

        base.merge(upper).unwrap();

        assert!(base.entries.is_empty());
    }

    #[test]
    fn test_merge_preserves_order() {
        // Entries should be sorted alphabetically after merge
        let mut base = Toc::new();
        base.entries.push(make_entry("z_file"));
        base.entries.push(make_entry("a_file"));

        let mut upper = Toc::new();
        upper.entries.push(make_entry("m_file"));

        base.merge(upper).unwrap();

        assert_eq!(base.entries.len(), 3);
        assert_eq!(base.entries[0].name, Path::new("a_file"));
        assert_eq!(base.entries[1].name, Path::new("m_file"));
        assert_eq!(base.entries[2].name, Path::new("z_file"));
    }

    #[test]
    fn test_merge_empty_layers() {
        let mut base = Toc::new();
        base.entries.push(make_entry("foo"));

        let upper = Toc::new(); // Empty layer

        base.merge(upper).unwrap();

        assert_eq!(base.entries.len(), 1);
        assert_eq!(base.entries[0].name, Path::new("foo"));
    }

    #[test]
    fn test_merge_into_empty() {
        let mut base = Toc::new();

        let mut upper = Toc::new();
        upper.entries.push(make_entry("foo"));

        base.merge(upper).unwrap();

        assert_eq!(base.entries.len(), 1);
        assert_eq!(base.entries[0].name, Path::new("foo"));
    }

    #[test]
    fn test_merge_rejects_dotdot_path() {
        // Paths with .. should be rejected for security
        let mut base = Toc::new();
        base.entries.push(make_entry("etc/passwd"));

        let mut upper = Toc::new();
        // Malicious path trying to escape via ..
        upper.entries.push(make_entry("etc/../etc/shadow"));

        // Merge should fail due to invalid path
        assert!(base.merge(upper).is_err());
    }

    #[test]
    fn test_merge_rejects_dot_path() {
        // Paths with . should be rejected for security
        let mut base = Toc::new();

        let mut upper = Toc::new();
        // Paths with . component
        upper.entries.push(make_entry("./etc/passwd"));

        // Merge should fail due to invalid path
        assert!(base.merge(upper).is_err());
    }

    #[test]
    fn test_merge_path_canonicalization_attack() {
        // Test that two paths that would resolve to the same location
        // after canonicalization are handled correctly
        let mut base = Toc::new();
        base.entries.push(make_entry("foo/bar"));

        let mut upper = Toc::new();
        // This path should be rejected, not treated as foo/bar
        upper.entries.push(make_entry("foo/subdir/../bar"));

        // Merge should fail due to invalid path
        assert!(base.merge(upper).is_err());
    }

    #[test]
    fn test_merge_absolute_path_works() {
        // Absolute paths (starting with /) should work
        let mut base = Toc::new();

        let mut upper = Toc::new();
        upper.entries.push(make_entry("/etc/passwd"));

        base.merge(upper).unwrap();

        // Leading / is normalized away by the tree
        assert_eq!(base.entries.len(), 1);
        assert_eq!(base.entries[0].name, Path::new("etc/passwd"));
    }
}
