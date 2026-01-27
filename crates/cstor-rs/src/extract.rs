//! Layer extraction with reflink support.
//!
//! This module provides functionality to extract container layers and images
//! to directories, with optional reflink (copy-on-write) support for efficient
//! extraction on filesystems like btrfs and XFS with reflink=1.
//!
//! # Overview
//!
//! The extraction process works by streaming layer content through the tar-split
//! metadata and creating files in the destination directory. When possible, file
//! content is reflinked from the source file descriptors, avoiding actual data
//! copying.
//!
//! # Extraction Modes
//!
//! - **Direct extraction**: When running with sufficient privileges, files are
//!   opened directly from storage and reflinked to the destination.
//! - **Proxied extraction**: When running unprivileged, file descriptors are
//!   received via IPC from a userns helper process and reflinked from those fds.
//!
//! # Example
//!
//! ```no_run
//! use cstor_rs::extract::{extract_layer, ExtractionOptions, ExtractionStats};
//! use cstor_rs::{Storage, Layer};
//! use cap_std::fs::Dir;
//! use cap_std::ambient_authority;
//!
//! let storage = Storage::discover()?;
//! let layer = Layer::open(&storage, "layer-id")?;
//! let dest = Dir::open_ambient_dir("/tmp/extract", ambient_authority())?;
//!
//! let options = ExtractionOptions::default();
//! let stats = extract_layer(&storage, &layer, &dest, &options)?;
//! println!("Extracted {} files, {} bytes reflinked", stats.files_extracted, stats.bytes_reflinked);
//! # Ok::<(), cstor_rs::StorageError>(())
//! ```

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cap_std::fs::{Dir, Permissions};
use rustix::fs::{AtFlags, Gid, Uid, ioctl_ficlone};

use crate::error::{Result, StorageError};
use crate::layer::Layer;
use crate::storage::Storage;
use crate::tar_split::{TarHeader, TarSplitFdStream, TarSplitItem};
use crate::toc::{Toc, TocEntry, TocEntryType};

/// Whiteout file prefix used by overlay filesystems.
const WHITEOUT_PREFIX: &str = ".wh.";

/// Opaque whiteout marker filename.
const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";

/// Validate that a path is safe.
fn validate_path(path: &Path) -> Result<()> {
    let path_bytes = path.as_os_str().as_encoded_bytes();

    // Check path length against system limit
    if path_bytes.len() > libc::PATH_MAX as usize {
        return Err(StorageError::InvalidStorage(format!(
            "path exceeds PATH_MAX ({} bytes): {}",
            libc::PATH_MAX,
            path.display()
        )));
    }

    // Check for null bytes (would cause truncation in C APIs)
    if path_bytes.contains(&0) {
        return Err(StorageError::InvalidStorage(
            "path contains null byte".into(),
        ));
    }

    Ok(())
}

/// Mode for creating file copies during extraction.
///
/// This controls how file content is duplicated from the source storage
/// to the destination directory.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LinkMode {
    /// Try reflink (copy-on-write) first, fall back to copy.
    ///
    /// This is the most efficient mode on filesystems that support it
    /// (btrfs, XFS with reflink=1). The file appears as a copy but shares
    /// the underlying data blocks until either copy is modified.
    #[default]
    Reflink,

    /// Use hardlinks to the source files.
    ///
    /// This is efficient on any filesystem but requires that source and
    /// destination are on the same filesystem. The destination files will
    /// share inodes with the source storage, so modifications to extracted
    /// files would affect the storage (though this is read-only storage).
    ///
    /// This mode is useful for ext4 and other filesystems that don't support
    /// reflinks but do support hardlinks.
    Hardlink,

    /// Always copy file data (no linking).
    ///
    /// This is the safest but slowest mode. Use when source and destination
    /// are on different filesystems, or when you need fully independent copies.
    Copy,
}

/// ELF magic bytes.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Minimum file size to consider for hardlinking (16 KiB).
///
/// Files smaller than this are copied instead, since the overhead of
/// hardlink management isn't worth it for tiny files, and small config
/// files are more likely to be edited.
pub const HARDLINK_MIN_SIZE_SMALL: u64 = 16 * 1024;

/// File size threshold for unconditional hardlinking (2 MiB).
///
/// Files larger than this are always hardlinked regardless of content type,
/// since the space savings are significant and large files are rarely edited.
pub const HARDLINK_MIN_SIZE_LARGE: u64 = 2 * 1024 * 1024;

/// Filter to determine which files are safe to hardlink.
///
/// When using `LinkMode::Hardlink`, hardlinked files share inodes with the
/// source storage. This can cause issues:
/// - `ls -l` shows `nlink > 1`, which can confuse users
/// - Editors like `vi` may behave unexpectedly
/// - In-place modifications would affect the storage (though it's read-only)
///
/// This filter allows selective hardlinking of files where these issues
/// are unlikely to matter (e.g., large binaries that won't be edited).
pub trait HardlinkFilter: Send + Sync {
    /// Check if a file is safe to hardlink based on its properties.
    ///
    /// # Arguments
    ///
    /// * `path` - Path of the file within the layer
    /// * `size` - Size of the file in bytes
    /// * `header` - First bytes of the file (for magic number detection)
    ///
    /// # Returns
    ///
    /// `true` if the file should be hardlinked, `false` to copy instead.
    fn is_hardlink_safe(&self, path: &Path, size: u64, header: &[u8]) -> bool;
}

/// Default hardlink filter using size and content heuristics.
///
/// This filter hardlinks files that are:
/// 1. ELF executables/libraries larger than 16 KiB, OR
/// 2. Any file larger than 2 MiB
///
/// This filter never hardlinks:
/// - Empty files (no space savings, often placeholders meant to be written)
/// - Small config files (likely to be edited, confuses editors with nlink > 1)
///
/// The rationale is:
/// - Large binaries are unlikely to be edited in place
/// - Space savings matter most for large files
/// - Small config files in `/etc` should be copied to avoid confusing editors
#[derive(Debug, Clone, Default)]
pub struct DefaultHardlinkFilter;

impl HardlinkFilter for DefaultHardlinkFilter {
    fn is_hardlink_safe(&self, _path: &Path, size: u64, header: &[u8]) -> bool {
        // Never hardlink empty files - they're often placeholders meant to be written
        // (e.g., /etc/machine-id, lock files, etc.)
        if size == 0 {
            return false;
        }

        // Very large files: always hardlink
        if size >= HARDLINK_MIN_SIZE_LARGE {
            return true;
        }

        // Medium-sized ELF files: hardlink (binaries/libraries)
        if size >= HARDLINK_MIN_SIZE_SMALL && header.starts_with(&ELF_MAGIC) {
            return true;
        }

        // Small files or non-ELF medium files: copy
        false
    }
}

/// A filter that always allows hardlinking (for testing or when you don't care).
#[derive(Debug, Clone, Default)]
pub struct AllowAllHardlinks;

impl HardlinkFilter for AllowAllHardlinks {
    fn is_hardlink_safe(&self, _path: &Path, _size: u64, _header: &[u8]) -> bool {
        true
    }
}

/// A filter that never allows hardlinking (effectively disables hardlink mode).
#[derive(Debug, Clone, Default)]
pub struct DenyAllHardlinks;

impl HardlinkFilter for DenyAllHardlinks {
    fn is_hardlink_safe(&self, _path: &Path, _size: u64, _header: &[u8]) -> bool {
        false
    }
}

/// Statistics from layer/image extraction.
#[derive(Debug, Clone, Default)]
pub struct ExtractionStats {
    /// Number of regular files successfully extracted.
    pub files_extracted: usize,
    /// Number of directories created.
    pub directories_created: usize,
    /// Number of symlinks created.
    pub symlinks_created: usize,
    /// Number of hardlinks created (from tar entries).
    pub hardlinks_created: usize,
    /// Bytes reflinked (zero-copy via FICLONE).
    pub bytes_reflinked: u64,
    /// Bytes hardlinked (zero-copy via hardlink to source).
    pub bytes_hardlinked: u64,
    /// Bytes copied (fallback when reflink/hardlink fails).
    pub bytes_copied: u64,
    /// Number of whiteouts processed.
    pub whiteouts_processed: usize,
    /// Number of entries skipped (device files, etc.).
    pub entries_skipped: usize,
    /// Number of permission set failures (non-fatal).
    pub permission_failures: usize,
    /// Number of ownership set failures (non-fatal).
    pub ownership_failures: usize,
}

/// Options for extraction.
#[derive(Clone)]
pub struct ExtractionOptions {
    /// Mode for creating file copies (reflink, hardlink, or copy).
    pub link_mode: LinkMode,
    /// Whether to fall back to copy if the requested link mode fails.
    ///
    /// When `false` (default), errors like EXDEV (cross-filesystem) or
    /// EOPNOTSUPP (not supported) will cause extraction to fail with an error.
    /// This makes problems visible rather than silently degrading performance.
    ///
    /// When `true`, these errors will trigger a fallback to copying the file
    /// data instead. This is useful when you want best-effort linking but
    /// need extraction to succeed regardless of filesystem capabilities.
    pub fallback_to_copy: bool,
    /// Filter for determining which files to hardlink in `LinkMode::Hardlink`.
    ///
    /// When set, only files that pass the filter will be hardlinked; others
    /// will be copied. This helps avoid issues with small config files where
    /// hardlinking might confuse editors or users checking link counts.
    ///
    /// If `None`, all files are hardlinked (when using hardlink mode).
    /// Use `Some(Arc::new(DefaultHardlinkFilter))` for sensible defaults.
    pub hardlink_filter: Option<Arc<dyn HardlinkFilter>>,
    /// Preserve file ownership (requires appropriate capabilities).
    pub preserve_ownership: bool,
    /// Preserve file permissions.
    pub preserve_permissions: bool,
    /// Process whiteouts (remove files marked for deletion).
    pub process_whiteouts: bool,
}

impl std::fmt::Debug for ExtractionOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtractionOptions")
            .field("link_mode", &self.link_mode)
            .field("fallback_to_copy", &self.fallback_to_copy)
            .field("hardlink_filter", &self.hardlink_filter.is_some())
            .field("preserve_ownership", &self.preserve_ownership)
            .field("preserve_permissions", &self.preserve_permissions)
            .field("process_whiteouts", &self.process_whiteouts)
            .finish()
    }
}

impl ExtractionOptions {
    /// Create options with reflink mode (default, no fallback).
    pub fn with_reflinks() -> Self {
        Self {
            link_mode: LinkMode::Reflink,
            ..Default::default()
        }
    }

    /// Create options with hardlink mode using the default filter.
    ///
    /// The default filter hardlinks ELF binaries > 16 KiB and any files > 2 MiB,
    /// while copying smaller files to avoid confusing editors.
    pub fn with_hardlinks() -> Self {
        Self {
            link_mode: LinkMode::Hardlink,
            hardlink_filter: Some(Arc::new(DefaultHardlinkFilter)),
            ..Default::default()
        }
    }

    /// Create options with hardlink mode without any filter (hardlink everything).
    ///
    /// Use with caution: this will hardlink all files including small config files,
    /// which may confuse editors and show unexpected link counts.
    pub fn with_hardlinks_unfiltered() -> Self {
        Self {
            link_mode: LinkMode::Hardlink,
            hardlink_filter: None,
            ..Default::default()
        }
    }

    /// Create options with copy mode (no linking).
    pub fn with_copy() -> Self {
        Self {
            link_mode: LinkMode::Copy,
            ..Default::default()
        }
    }
}

impl Default for ExtractionOptions {
    fn default() -> Self {
        Self {
            link_mode: LinkMode::Reflink,
            fallback_to_copy: false,
            hardlink_filter: None,
            preserve_ownership: true,
            preserve_permissions: true,
            process_whiteouts: true,
        }
    }
}

/// Extract a single layer to a directory.
///
/// This extracts all files from the layer to the destination directory,
/// using reflinks when possible for efficient zero-copy extraction.
///
/// # Arguments
///
/// * `storage` - Storage handle
/// * `layer` - Layer to extract
/// * `dest` - Destination directory handle
/// * `options` - Extraction options
///
/// # Returns
///
/// Statistics about the extraction.
///
/// # Errors
///
/// Returns an error if extraction fails.
pub fn extract_layer(
    storage: &Storage,
    layer: &Layer,
    dest: &Dir,
    options: &ExtractionOptions,
) -> Result<ExtractionStats> {
    let mut stats = ExtractionStats::default();
    let mut stream = TarSplitFdStream::new(storage, layer)?;

    // Track the current tar header for file content
    let mut current_header: Option<TarHeader> = None;
    let mut gnu_long_name: Option<String> = None;
    let mut gnu_long_linkname: Option<String> = None;
    let mut pending_file_size: u64 = 0;

    while let Some(item) = stream.next()? {
        match item {
            TarSplitItem::Segment(bytes) => {
                // Calculate padding offset based on previous file size
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
                pending_file_size = 0;

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
                        Ok(mut new_header) => {
                            // Process pending header before storing new one
                            if let Some(mut pending) = current_header.take() {
                                if let Some(long_name) = gnu_long_name.take() {
                                    pending.name = long_name;
                                }
                                if let Some(long_linkname) = gnu_long_linkname.take() {
                                    pending.linkname = long_linkname;
                                }
                                if !pending.is_gnu_long_name() && !pending.is_gnu_long_linkname() {
                                    // Process non-regular-file entries from header
                                    process_non_file_entry(&pending, dest, options, &mut stats)?;
                                }
                            }

                            // Apply any pending GNU long names to new header
                            if let Some(long_name) = gnu_long_name.take() {
                                new_header.name = long_name;
                            }
                            if let Some(long_linkname) = gnu_long_linkname.take() {
                                new_header.linkname = long_linkname;
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
            TarSplitItem::FileContent { fd, size, name: _ } => {
                pending_file_size = size;

                if let Some(header) = current_header.take() {
                    // Handle GNU long name/linkname
                    if header.is_gnu_long_name() {
                        gnu_long_name = Some(read_gnu_long_string(fd, size)?);
                        continue;
                    } else if header.is_gnu_long_linkname() {
                        gnu_long_linkname = Some(read_gnu_long_string(fd, size)?);
                        continue;
                    }

                    // Extract regular file with content
                    if header.is_regular_file() && size > 0 {
                        extract_regular_file(&header, fd, size, dest, options, &mut stats)?;
                    }
                }
            }
        }
    }

    // Handle final pending header (non-file entry)
    if let Some(mut pending) = current_header.take() {
        if let Some(long_name) = gnu_long_name.take() {
            pending.name = long_name;
        }
        if let Some(long_linkname) = gnu_long_linkname.take() {
            pending.linkname = long_linkname;
        }
        if !pending.is_gnu_long_name() && !pending.is_gnu_long_linkname() {
            process_non_file_entry(&pending, dest, options, &mut stats)?;
        }
    }

    Ok(stats)
}

/// Extract an entire image (all layers merged) to a directory.
///
/// This extracts all layers in order, applying overlay semantics:
/// - Upper layer files override lower layer files
/// - Whiteouts remove files from lower layers
/// - Opaque markers clear directory contents
///
/// # Arguments
///
/// * `storage` - Storage handle
/// * `image` - Image to extract
/// * `dest` - Destination directory handle
/// * `options` - Extraction options
///
/// # Returns
///
/// Statistics about the extraction.
pub fn extract_image(
    storage: &Storage,
    image: &crate::image::Image,
    dest: &Dir,
    options: &ExtractionOptions,
) -> Result<ExtractionStats> {
    let mut total_stats = ExtractionStats::default();
    let layer_ids = image.storage_layer_ids(storage)?;

    // Extract layers in order (base to top)
    for layer_id in &layer_ids {
        let layer = Layer::open(storage, layer_id)?;
        let layer_stats = extract_layer(storage, &layer, dest, options)?;

        // Accumulate stats
        total_stats.files_extracted += layer_stats.files_extracted;
        total_stats.directories_created += layer_stats.directories_created;
        total_stats.symlinks_created += layer_stats.symlinks_created;
        total_stats.hardlinks_created += layer_stats.hardlinks_created;
        total_stats.bytes_reflinked += layer_stats.bytes_reflinked;
        total_stats.bytes_copied += layer_stats.bytes_copied;
        total_stats.whiteouts_processed += layer_stats.whiteouts_processed;
        total_stats.entries_skipped += layer_stats.entries_skipped;
        total_stats.permission_failures += layer_stats.permission_failures;
        total_stats.ownership_failures += layer_stats.ownership_failures;
    }

    Ok(total_stats)
}

/// Extract an image using TOC metadata and layer source mapping.
///
/// This is more efficient than `extract_image` when you need to extract
/// an image with complex layer structures, as it uses the merged TOC
/// to determine which layer each file comes from.
///
/// # Arguments
///
/// * `storage` - Storage handle
/// * `image` - Image to extract
/// * `dest` - Destination directory handle
/// * `options` - Extraction options
///
/// # Returns
///
/// Statistics about the extraction.
pub fn extract_image_with_toc(
    storage: &Storage,
    image: &crate::image::Image,
    dest: &Dir,
    options: &ExtractionOptions,
) -> Result<ExtractionStats> {
    let mut stats = ExtractionStats::default();

    // Get merged TOC with layer mapping
    let (toc, layer_map) = Toc::from_image_with_layers(storage, image)?;

    // Build a map of layer ID to Layer handle for efficient access
    let mut layer_cache: HashMap<String, Layer> = HashMap::new();

    // Process each entry in sorted order
    for entry in &toc.entries {
        let layer_id = match layer_map.get(&entry.name) {
            Some(id) => id,
            None => continue, // Skip entries without layer mapping
        };

        // Get or open layer
        let layer = if let Some(layer) = layer_cache.get(layer_id) {
            layer
        } else {
            let layer = Layer::open(storage, layer_id)?;
            layer_cache.insert(layer_id.clone(), layer);
            layer_cache.get(layer_id).unwrap()
        };

        extract_toc_entry(entry, layer, dest, options, &mut stats)?;
    }

    Ok(stats)
}

/// Extract a TOC entry from a layer.
fn extract_toc_entry(
    entry: &TocEntry,
    layer: &Layer,
    dest: &Dir,
    options: &ExtractionOptions,
    stats: &mut ExtractionStats,
) -> Result<()> {
    let path = &entry.name;

    // Skip empty paths
    if path.as_os_str().is_empty() {
        return Ok(());
    }

    // Validate path for security and resource limits
    validate_path(path)?;

    // Create parent directories
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        dest.create_dir_all(parent)?;
    }

    match entry.entry_type {
        TocEntryType::Dir => {
            match dest.create_dir(path) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(StorageError::Io(e)),
            }
            if options.preserve_permissions {
                let perms = Permissions::from_std(std::fs::Permissions::from_mode(entry.mode));
                if dest.set_permissions(path, perms).is_err() {
                    stats.permission_failures += 1;
                }
            }
            if options.preserve_ownership
                && rustix::fs::chownat(
                    dest,
                    path,
                    Some(Uid::from_raw(entry.uid)),
                    Some(Gid::from_raw(entry.gid)),
                    AtFlags::empty(),
                )
                .is_err()
            {
                stats.ownership_failures += 1;
            }
            stats.directories_created += 1;
        }
        TocEntryType::Reg => {
            let size = entry.size.unwrap_or(0);
            if size > 0 {
                // Open source file from layer
                let src_file = layer.open_file_std(path)?;
                let src_fd: OwnedFd = src_file.into();

                // Create and extract
                let _ = dest.remove_file(path);
                extract_file_content(path, src_fd, size, dest, options, stats)?;
            } else {
                // Empty file
                let _ = dest.remove_file(path);
                let file = dest.create(path)?;
                drop(file);
                stats.files_extracted += 1;
            }

            // Set metadata
            if options.preserve_permissions {
                let perms = Permissions::from_std(std::fs::Permissions::from_mode(entry.mode));
                if dest.set_permissions(path, perms).is_err() {
                    stats.permission_failures += 1;
                }
            }
            if options.preserve_ownership
                && rustix::fs::chownat(
                    dest,
                    path,
                    Some(Uid::from_raw(entry.uid)),
                    Some(Gid::from_raw(entry.gid)),
                    AtFlags::empty(),
                )
                .is_err()
            {
                stats.ownership_failures += 1;
            }
        }
        TocEntryType::Symlink => {
            if let Some(ref target) = entry.link_name {
                let _ = dest.remove_file(path);
                dest.symlink_contents(target, path)?;
                if options.preserve_ownership
                    && rustix::fs::chownat(
                        dest,
                        path,
                        Some(Uid::from_raw(entry.uid)),
                        Some(Gid::from_raw(entry.gid)),
                        AtFlags::SYMLINK_NOFOLLOW,
                    )
                    .is_err()
                {
                    stats.ownership_failures += 1;
                }
                stats.symlinks_created += 1;
            }
        }
        TocEntryType::Hardlink => {
            if let Some(ref target) = entry.link_name {
                let target_path: PathBuf = Path::new(target)
                    .strip_prefix("./")
                    .unwrap_or(Path::new(target))
                    .to_path_buf();
                let _ = dest.remove_file(path);
                dest.hard_link(&target_path, dest, path)?;
                stats.hardlinks_created += 1;
            }
        }
        TocEntryType::Char | TocEntryType::Block | TocEntryType::Fifo => {
            // Skip device files - can't create as unprivileged user
            stats.entries_skipped += 1;
        }
    }

    Ok(())
}

/// Process a non-regular-file entry from a tar header.
fn process_non_file_entry(
    header: &TarHeader,
    dest: &Dir,
    options: &ExtractionOptions,
    stats: &mut ExtractionStats,
) -> Result<()> {
    let path_str = header.normalized_name();
    if path_str.is_empty() {
        return Ok(());
    }
    let path = Path::new(path_str);

    // Validate path for security and resource limits
    validate_path(path)?;

    // Check for whiteouts
    if options.process_whiteouts
        && let Some(filename) = path.file_name().and_then(|f| f.to_str())
    {
        if filename == OPAQUE_WHITEOUT {
            // Opaque whiteout - clear directory contents
            if let Some(parent) = path.parent()
                && let Ok(parent_dir) = dest.open_dir(parent)
            {
                for dir_entry in parent_dir.entries()?.flatten() {
                    let name = dir_entry.file_name();
                    if let Ok(ft) = dir_entry.file_type() {
                        if ft.is_dir() {
                            let _ = parent_dir.remove_dir_all(&name);
                        } else {
                            let _ = parent_dir.remove_file(&name);
                        }
                    }
                }
            }
            stats.whiteouts_processed += 1;
            return Ok(());
        } else if let Some(target_name) = filename.strip_prefix(WHITEOUT_PREFIX) {
            // Regular whiteout - remove target
            let target_path = match path.parent() {
                Some(p) if !p.as_os_str().is_empty() => p.join(target_name),
                _ => PathBuf::from(target_name),
            };
            if dest.remove_file(&target_path).is_err() {
                let _ = dest.remove_dir_all(&target_path);
            }
            stats.whiteouts_processed += 1;
            return Ok(());
        }
    }

    // Create parent directories
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        dest.create_dir_all(parent)?;
    }

    // Handle by type
    match header.typeflag {
        b'5' => {
            // Directory
            match dest.create_dir(path) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(StorageError::Io(e)),
            }
            if options.preserve_permissions {
                let perms = Permissions::from_std(std::fs::Permissions::from_mode(header.mode));
                if dest.set_permissions(path, perms).is_err() {
                    stats.permission_failures += 1;
                }
            }
            if options.preserve_ownership
                && rustix::fs::chownat(
                    dest,
                    path,
                    Some(Uid::from_raw(header.uid)),
                    Some(Gid::from_raw(header.gid)),
                    AtFlags::empty(),
                )
                .is_err()
            {
                stats.ownership_failures += 1;
            }
            stats.directories_created += 1;
        }
        b'2' => {
            // Symlink
            if !header.linkname.is_empty() {
                let _ = dest.remove_file(path);
                dest.symlink_contents(&header.linkname, path)?;
                if options.preserve_ownership
                    && rustix::fs::chownat(
                        dest,
                        path,
                        Some(Uid::from_raw(header.uid)),
                        Some(Gid::from_raw(header.gid)),
                        AtFlags::SYMLINK_NOFOLLOW,
                    )
                    .is_err()
                {
                    stats.ownership_failures += 1;
                }
                stats.symlinks_created += 1;
            }
        }
        b'1' => {
            // Hardlink
            if !header.linkname.is_empty() {
                let target: PathBuf = Path::new(&header.linkname)
                    .strip_prefix("./")
                    .unwrap_or(Path::new(&header.linkname))
                    .to_path_buf();
                let _ = dest.remove_file(path);
                dest.hard_link(&target, dest, path)?;
                stats.hardlinks_created += 1;
            }
        }
        b'0' | b'\0' => {
            // Regular file with no content (empty file)
            if header.size == 0 {
                let _ = dest.remove_file(path);
                let file = dest.create(path)?;
                drop(file);
                if options.preserve_permissions {
                    let perms = Permissions::from_std(std::fs::Permissions::from_mode(header.mode));
                    if dest.set_permissions(path, perms).is_err() {
                        stats.permission_failures += 1;
                    }
                }
                if options.preserve_ownership
                    && rustix::fs::chownat(
                        dest,
                        path,
                        Some(Uid::from_raw(header.uid)),
                        Some(Gid::from_raw(header.gid)),
                        AtFlags::empty(),
                    )
                    .is_err()
                {
                    stats.ownership_failures += 1;
                }
                stats.files_extracted += 1;
            }
            // Files with content are handled in extract_regular_file
        }
        b'3' | b'4' | b'6' => {
            // Character device, block device, FIFO - skip
            stats.entries_skipped += 1;
        }
        _ => {
            // Unknown type - skip
            stats.entries_skipped += 1;
        }
    }

    Ok(())
}

/// Extract a regular file with content.
fn extract_regular_file(
    header: &TarHeader,
    fd: OwnedFd,
    size: u64,
    dest: &Dir,
    options: &ExtractionOptions,
    stats: &mut ExtractionStats,
) -> Result<()> {
    let path_str = header.normalized_name();
    if path_str.is_empty() {
        return Ok(());
    }
    let path = Path::new(path_str);

    // Create parent directories
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        dest.create_dir_all(parent)?;
    }

    // Remove existing file
    let _ = dest.remove_file(path);

    // Extract file content
    extract_file_content(path, fd, size, dest, options, stats)?;

    // Set metadata
    if options.preserve_permissions {
        let perms = Permissions::from_std(std::fs::Permissions::from_mode(header.mode));
        if dest.set_permissions(path, perms).is_err() {
            stats.permission_failures += 1;
        }
    }
    if options.preserve_ownership
        && rustix::fs::chownat(
            dest,
            path,
            Some(Uid::from_raw(header.uid)),
            Some(Gid::from_raw(header.gid)),
            AtFlags::empty(),
        )
        .is_err()
    {
        stats.ownership_failures += 1;
    }

    Ok(())
}

/// Extract file content using the configured link mode.
///
/// Depending on the link mode:
/// - Reflink: Try FICLONE ioctl, optionally fall back to copy
/// - Hardlink: Create a hardlink to the source file via /proc/self/fd
/// - Copy: Always copy the file data
///
/// If `fallback_to_copy` is false (default), errors from reflink/hardlink
/// operations will be propagated. If true, we fall back to copying.
fn extract_file_content(
    path: &Path,
    src_fd: OwnedFd,
    size: u64,
    dest: &Dir,
    options: &ExtractionOptions,
    stats: &mut ExtractionStats,
) -> Result<()> {
    match options.link_mode {
        LinkMode::Reflink => {
            extract_file_content_reflink(path, src_fd, size, dest, options.fallback_to_copy, stats)
        }
        LinkMode::Hardlink => extract_file_content_hardlink(
            path,
            src_fd,
            size,
            dest,
            options.fallback_to_copy,
            options.hardlink_filter.as_deref(),
            stats,
        ),
        LinkMode::Copy => extract_file_content_copy(path, src_fd, size, dest, stats),
    }
}

/// Check if an error indicates reflink is not supported on this filesystem.
fn is_reflink_unavailable(errno: i32) -> bool {
    errno == rustix::io::Errno::OPNOTSUPP.raw_os_error()
        || errno == rustix::io::Errno::XDEV.raw_os_error()
        || errno == rustix::io::Errno::INVAL.raw_os_error()
}

/// Check if an error indicates hardlink is not supported/allowed.
fn is_hardlink_unavailable(errno: i32) -> bool {
    errno == rustix::io::Errno::XDEV.raw_os_error()
        || errno == rustix::io::Errno::PERM.raw_os_error()
        || errno == rustix::io::Errno::OPNOTSUPP.raw_os_error()
}

/// Extract file content using reflink.
///
/// If `fallback_to_copy` is true, falls back to copy on EOPNOTSUPP/EXDEV/EINVAL.
/// Otherwise, returns an error.
fn extract_file_content_reflink(
    path: &Path,
    src_fd: OwnedFd,
    size: u64,
    dest: &Dir,
    fallback_to_copy: bool,
    stats: &mut ExtractionStats,
) -> Result<()> {
    // Create destination file
    let dest_file: std::fs::File = dest.create(path)?.into_std();

    // Try reflink
    match ioctl_ficlone(&dest_file, src_fd.as_fd()) {
        Ok(()) => {
            stats.bytes_reflinked += size;
            stats.files_extracted += 1;
            Ok(())
        }
        Err(e) => {
            let errno = e.raw_os_error();
            if is_reflink_unavailable(errno) {
                if fallback_to_copy {
                    tracing::debug!(
                        "reflink not available ({}), falling back to copy for {:?}",
                        e,
                        path
                    );
                    // Remove the empty file we created and copy instead
                    drop(dest_file);
                    extract_file_content_copy(path, src_fd, size, dest, stats)
                } else {
                    Err(StorageError::Io(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        format!(
                            "reflink not supported for {:?}: {} (use --fallback-to-copy to allow copying)",
                            path, e
                        ),
                    )))
                }
            } else {
                // Unexpected error - always propagate
                Err(StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("reflink failed for {:?}: {}", path, e),
                )))
            }
        }
    }
}

/// Number of bytes to read for file header detection (ELF magic, etc.).
const HEADER_PEEK_SIZE: usize = 16;

/// Extract file content using hardlink to the source file.
///
/// Uses /proc/self/fd/<n> to create a hardlink to the source file.
/// If a filter is provided, only files that pass the filter will be hardlinked.
/// If `fallback_to_copy` is true, falls back to copy on EXDEV/EPERM/EOPNOTSUPP.
/// Otherwise, returns an error.
fn extract_file_content_hardlink(
    path: &Path,
    src_fd: OwnedFd,
    size: u64,
    dest: &Dir,
    fallback_to_copy: bool,
    filter: Option<&dyn HardlinkFilter>,
    stats: &mut ExtractionStats,
) -> Result<()> {
    use std::os::fd::AsRawFd;

    // If we have a filter, check if this file should be hardlinked
    if let Some(filter) = filter {
        // Read the file header to check for magic bytes
        let mut header = [0u8; HEADER_PEEK_SIZE];
        let header_len = {
            let mut file = std::fs::File::from(
                rustix::io::dup(&src_fd)
                    .map_err(|e| StorageError::Io(std::io::Error::from_raw_os_error(e.raw_os_error())))?,
            );
            file.read(&mut header).unwrap_or(0)
        };

        if !filter.is_hardlink_safe(path, size, &header[..header_len]) {
            // Filter says don't hardlink - copy instead
            tracing::trace!(
                "hardlink filter rejected {:?} (size={}), copying instead",
                path,
                size
            );
            return extract_file_content_copy(path, src_fd, size, dest, stats);
        }
    }

    // Create hardlink via /proc/self/fd path
    // This allows creating a hardlink from an open fd without knowing the original path
    let proc_fd_path = format!("/proc/self/fd/{}", src_fd.as_raw_fd());

    // Use linkat with AT_SYMLINK_FOLLOW to follow the /proc/self/fd symlink
    // and create a hardlink to the actual file
    match rustix::fs::linkat(
        rustix::fs::CWD,
        &proc_fd_path,
        dest,
        path,
        AtFlags::SYMLINK_FOLLOW,
    ) {
        Ok(()) => {
            stats.bytes_hardlinked += size;
            stats.files_extracted += 1;
            Ok(())
        }
        Err(e) => {
            let errno = e.raw_os_error();
            if is_hardlink_unavailable(errno) {
                if fallback_to_copy {
                    tracing::debug!(
                        "hardlink not available ({}), falling back to copy for {:?}",
                        e,
                        path
                    );
                    extract_file_content_copy(path, src_fd, size, dest, stats)
                } else {
                    Err(StorageError::Io(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        format!(
                            "hardlink not supported for {:?}: {} (use --fallback-to-copy to allow copying)",
                            path, e
                        ),
                    )))
                }
            } else {
                // Unexpected error - always propagate
                Err(StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("hardlink failed for {:?}: {}", path, e),
                )))
            }
        }
    }
}

/// Extract file content by copying data.
fn extract_file_content_copy(
    path: &Path,
    src_fd: OwnedFd,
    size: u64,
    dest: &Dir,
    stats: &mut ExtractionStats,
) -> Result<()> {
    let _ = size; // Size is tracked via actual bytes copied

    let mut src = std::fs::File::from(src_fd);
    src.seek(SeekFrom::Start(0))?;

    // Remove any existing file and create new
    let _ = dest.remove_file(path);
    let mut dest_file = dest.create(path)?.into_std();

    let copied = std::io::copy(&mut src, &mut dest_file)?;
    stats.bytes_copied += copied;
    stats.files_extracted += 1;

    Ok(())
}

/// Read a GNU long name/linkname from a file descriptor.
fn read_gnu_long_string(fd: OwnedFd, size: u64) -> Result<String> {
    if size > libc::PATH_MAX as u64 {
        return Err(StorageError::TarSplitError(
            format!("GNU long name exceeds PATH_MAX ({} bytes)", size),
        ));
    }
    let mut file = std::fs::File::from(fd);
    let mut buffer = vec![0u8; size as usize];
    file.read_exact(&mut buffer)
        .map_err(|e| StorageError::TarSplitError(format!("Failed to read GNU long name: {}", e)))?;

    // Remove trailing null bytes
    let end = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
    String::from_utf8(buffer[..end].to_vec()).map_err(|e| {
        StorageError::TarSplitError(format!("GNU long name is not valid UTF-8: {}", e))
    })
}

/// Extract from a proxied layer stream.
///
/// This is used when extracting via the userns helper, where file descriptors
/// are received via IPC.
pub fn extract_from_stream<F>(
    dest: &Dir,
    options: &ExtractionOptions,
    mut next_item: F,
) -> Result<ExtractionStats>
where
    F: FnMut() -> Result<Option<crate::userns_helper::ProxiedTarSplitItem>>,
{
    use crate::userns_helper::ProxiedTarSplitItem;

    let mut stats = ExtractionStats::default();
    let mut current_header: Option<TarHeader> = None;
    let mut gnu_long_name: Option<String> = None;
    let mut gnu_long_linkname: Option<String> = None;
    let mut pending_file_size: u64 = 0;

    loop {
        let item = match next_item()? {
            Some(item) => item,
            None => break,
        };

        match item {
            ProxiedTarSplitItem::Segment(bytes) => {
                // Calculate padding offset based on previous file size
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
                pending_file_size = 0;

                // Process segment starting after padding
                let mut offset = padding_offset;
                while offset + 512 <= bytes.len() {
                    let block = &bytes[offset..offset + 512];

                    // Check if this is a null block
                    if block.iter().all(|&b| b == 0) {
                        offset += 512;
                        continue;
                    }

                    // Try to parse as a tar header
                    if let Ok(mut new_header) = TarHeader::from_bytes(block) {
                        // Process pending header
                        if let Some(mut pending) = current_header.take() {
                            if let Some(long_name) = gnu_long_name.take() {
                                pending.name = long_name;
                            }
                            if let Some(long_linkname) = gnu_long_linkname.take() {
                                pending.linkname = long_linkname;
                            }
                            if !pending.is_gnu_long_name() && !pending.is_gnu_long_linkname() {
                                process_non_file_entry(&pending, dest, options, &mut stats)?;
                            }
                        }

                        // Apply any pending GNU long names
                        if let Some(long_name) = gnu_long_name.take() {
                            new_header.name = long_name;
                        }
                        if let Some(long_linkname) = gnu_long_linkname.take() {
                            new_header.linkname = long_linkname;
                        }

                        current_header = Some(new_header);
                    }
                    offset += 512;
                }
            }
            ProxiedTarSplitItem::FileContent { fd, size, name: _ } => {
                pending_file_size = size;

                if let Some(header) = current_header.take() {
                    // Handle GNU long name/linkname
                    if header.is_gnu_long_name() {
                        gnu_long_name = Some(read_gnu_long_string(fd, size)?);
                        continue;
                    } else if header.is_gnu_long_linkname() {
                        gnu_long_linkname = Some(read_gnu_long_string(fd, size)?);
                        continue;
                    }

                    // Extract regular file with content
                    if header.is_regular_file() && size > 0 {
                        extract_regular_file(&header, fd, size, dest, options, &mut stats)?;
                    }
                }
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
            process_non_file_entry(&pending, dest, options, &mut stats)?;
        }
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extraction_options_default() {
        let opts = ExtractionOptions::default();
        assert_eq!(opts.link_mode, LinkMode::Reflink);
        assert!(!opts.fallback_to_copy);
        assert!(opts.hardlink_filter.is_none());
        assert!(opts.preserve_ownership);
        assert!(opts.preserve_permissions);
        assert!(opts.process_whiteouts);
    }

    #[test]
    fn test_extraction_options_constructors() {
        let reflink = ExtractionOptions::with_reflinks();
        assert_eq!(reflink.link_mode, LinkMode::Reflink);
        assert!(!reflink.fallback_to_copy);
        assert!(reflink.hardlink_filter.is_none());

        let hardlink = ExtractionOptions::with_hardlinks();
        assert_eq!(hardlink.link_mode, LinkMode::Hardlink);
        assert!(!hardlink.fallback_to_copy);
        assert!(hardlink.hardlink_filter.is_some()); // Default filter

        let hardlink_unfiltered = ExtractionOptions::with_hardlinks_unfiltered();
        assert_eq!(hardlink_unfiltered.link_mode, LinkMode::Hardlink);
        assert!(hardlink_unfiltered.hardlink_filter.is_none()); // No filter

        let copy = ExtractionOptions::with_copy();
        assert_eq!(copy.link_mode, LinkMode::Copy);
        assert!(!copy.fallback_to_copy);
    }

    #[test]
    fn test_default_hardlink_filter_empty_files() {
        let filter = DefaultHardlinkFilter;

        // Empty files should never be hardlinked - no space savings and often
        // placeholders meant to be written (e.g., /etc/machine-id)
        assert!(!filter.is_hardlink_safe(Path::new("etc/machine-id"), 0, b""));
        assert!(!filter.is_hardlink_safe(Path::new("var/lock/file"), 0, b""));
        assert!(!filter.is_hardlink_safe(Path::new("any/path"), 0, &ELF_MAGIC));
    }

    #[test]
    fn test_default_hardlink_filter_small_files() {
        let filter = DefaultHardlinkFilter;
        let path = Path::new("etc/passwd");

        // Small file - should not be hardlinked
        assert!(!filter.is_hardlink_safe(path, 100, b"root:x:0:0"));

        // Small ELF - should not be hardlinked (below threshold)
        assert!(!filter.is_hardlink_safe(path, 1000, &ELF_MAGIC));
    }

    #[test]
    fn test_default_hardlink_filter_elf_binaries() {
        let filter = DefaultHardlinkFilter;
        let path = Path::new("usr/bin/ls");

        // ELF above 16KB threshold - should be hardlinked
        assert!(filter.is_hardlink_safe(path, 20 * 1024, &ELF_MAGIC));

        // Non-ELF above 16KB - should NOT be hardlinked
        assert!(!filter.is_hardlink_safe(path, 20 * 1024, b"#!/bin/bash\n"));
    }

    #[test]
    fn test_default_hardlink_filter_large_files() {
        let filter = DefaultHardlinkFilter;
        let path = Path::new("var/cache/large.dat");

        // Very large file - always hardlink regardless of content
        assert!(filter.is_hardlink_safe(path, 3 * 1024 * 1024, b"random data"));

        // Exactly at 2MB threshold - should be hardlinked
        assert!(filter.is_hardlink_safe(path, 2 * 1024 * 1024, b"random data"));

        // Just below 2MB threshold, non-ELF - should NOT be hardlinked
        assert!(!filter.is_hardlink_safe(path, 2 * 1024 * 1024 - 1, b"random data"));
    }

    #[test]
    fn test_allow_all_hardlinks() {
        let filter = AllowAllHardlinks;
        let path = Path::new("any/path");

        // Always allows
        assert!(filter.is_hardlink_safe(path, 0, b""));
        assert!(filter.is_hardlink_safe(path, 100, b"small"));
    }

    #[test]
    fn test_deny_all_hardlinks() {
        let filter = DenyAllHardlinks;
        let path = Path::new("any/path");

        // Always denies
        assert!(!filter.is_hardlink_safe(path, 0, b""));
        assert!(!filter.is_hardlink_safe(path, 10 * 1024 * 1024, &ELF_MAGIC));
    }

    #[test]
    fn test_link_mode_default() {
        assert_eq!(LinkMode::default(), LinkMode::Reflink);
    }

    #[test]
    fn test_extraction_stats_default() {
        let stats = ExtractionStats::default();
        assert_eq!(stats.files_extracted, 0);
        assert_eq!(stats.directories_created, 0);
        assert_eq!(stats.symlinks_created, 0);
        assert_eq!(stats.hardlinks_created, 0);
        assert_eq!(stats.bytes_reflinked, 0);
        assert_eq!(stats.bytes_hardlinked, 0);
        assert_eq!(stats.bytes_copied, 0);
        assert_eq!(stats.whiteouts_processed, 0);
        assert_eq!(stats.entries_skipped, 0);
        assert_eq!(stats.permission_failures, 0);
        assert_eq!(stats.ownership_failures, 0);
    }

    /// Test that extraction works with real storage.
    ///
    /// This test is ignored by default because it requires actual container
    /// storage to be present.
    #[test]
    #[ignore = "requires actual container storage"]
    fn test_extract_layer_integration() {
        use crate::Storage;
        use cap_std::ambient_authority;
        use tempfile::TempDir;

        let storage = Storage::discover().expect("Storage should be available");
        let images = storage.list_images().expect("Should list images");

        if let Some(image) = images.first() {
            let layers = storage.get_image_layers(image).expect("Should get layers");

            if let Some(layer) = layers.first() {
                let tmpdir = TempDir::new().expect("Should create temp dir");
                let dest =
                    Dir::open_ambient_dir(tmpdir.path(), ambient_authority()).expect("Should open");

                let options = ExtractionOptions::default();
                let stats = extract_layer(&storage, layer, &dest, &options)
                    .expect("Extraction should succeed");

                println!(
                    "Extracted {} files, {} dirs, {} symlinks",
                    stats.files_extracted, stats.directories_created, stats.symlinks_created
                );
                println!(
                    "Bytes: {} reflinked, {} copied",
                    stats.bytes_reflinked, stats.bytes_copied
                );

                // Should have extracted something
                assert!(
                    stats.files_extracted > 0
                        || stats.directories_created > 0
                        || stats.symlinks_created > 0,
                    "Should have extracted at least one entry"
                );
            }
        }
    }

    /// Test that image extraction works with real storage.
    #[test]
    #[ignore = "requires actual container storage"]
    fn test_extract_image_integration() {
        use crate::Storage;
        use cap_std::ambient_authority;
        use tempfile::TempDir;

        let storage = Storage::discover().expect("Storage should be available");
        let images = storage.list_images().expect("Should list images");

        if let Some(image) = images.first() {
            let tmpdir = TempDir::new().expect("Should create temp dir");
            let dest =
                Dir::open_ambient_dir(tmpdir.path(), ambient_authority()).expect("Should open");

            let options = ExtractionOptions::default();
            let stats =
                extract_image(&storage, image, &dest, &options).expect("Extraction should succeed");

            println!(
                "Image extracted: {} files, {} dirs, {} symlinks, {} hardlinks",
                stats.files_extracted,
                stats.directories_created,
                stats.symlinks_created,
                stats.hardlinks_created
            );
            println!(
                "Bytes: {} reflinked, {} copied",
                stats.bytes_reflinked, stats.bytes_copied
            );
            println!(
                "Whiteouts: {}, Skipped: {}",
                stats.whiteouts_processed, stats.entries_skipped
            );

            // Should have extracted something
            assert!(
                stats.files_extracted > 0 || stats.directories_created > 0,
                "Should have extracted at least one entry"
            );
        }
    }
}
