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

use cap_std::fs::{Dir, OpenOptions, Permissions};
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

/// Statistics from layer/image extraction.
#[derive(Debug, Clone, Default)]
pub struct ExtractionStats {
    /// Number of regular files successfully extracted.
    pub files_extracted: usize,
    /// Number of directories created.
    pub directories_created: usize,
    /// Number of symlinks created.
    pub symlinks_created: usize,
    /// Number of hardlinks created.
    pub hardlinks_created: usize,
    /// Bytes reflinked (zero-copy).
    pub bytes_reflinked: u64,
    /// Bytes copied (fallback when reflink fails).
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
#[derive(Debug, Clone)]
pub struct ExtractionOptions {
    /// Try to use reflinks for file copies. Falls back to regular copy if not supported.
    pub use_reflinks: bool,
    /// Preserve file ownership (requires appropriate capabilities).
    pub preserve_ownership: bool,
    /// Preserve file permissions.
    pub preserve_permissions: bool,
    /// Process whiteouts (remove files marked for deletion).
    pub process_whiteouts: bool,
}

impl Default for ExtractionOptions {
    fn default() -> Self {
        Self {
            use_reflinks: true,
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

    // Create parent directories
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            dest.create_dir_all(parent)?;
        }
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
            if options.preserve_ownership {
                if rustix::fs::chownat(
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
            if options.preserve_ownership {
                if rustix::fs::chownat(
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
        }
        TocEntryType::Symlink => {
            if let Some(ref target) = entry.link_name {
                let _ = dest.remove_file(path);
                dest.symlink_contents(target, path)?;
                if options.preserve_ownership {
                    if rustix::fs::chownat(
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

    // Check for whiteouts
    if options.process_whiteouts {
        if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
            if filename == OPAQUE_WHITEOUT {
                // Opaque whiteout - clear directory contents
                if let Some(parent) = path.parent() {
                    if let Ok(parent_dir) = dest.open_dir(parent) {
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
    }

    // Create parent directories
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            dest.create_dir_all(parent)?;
        }
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
            if options.preserve_ownership {
                if rustix::fs::chownat(
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
            }
            stats.directories_created += 1;
        }
        b'2' => {
            // Symlink
            if !header.linkname.is_empty() {
                let _ = dest.remove_file(path);
                dest.symlink_contents(&header.linkname, path)?;
                if options.preserve_ownership {
                    if rustix::fs::chownat(
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
                if options.preserve_ownership {
                    if rustix::fs::chownat(
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
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            dest.create_dir_all(parent)?;
        }
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
    if options.preserve_ownership {
        if rustix::fs::chownat(
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
    }

    Ok(())
}

/// Extract file content using reflink if possible, falling back to copy.
fn extract_file_content(
    path: &Path,
    src_fd: OwnedFd,
    size: u64,
    dest: &Dir,
    options: &ExtractionOptions,
    stats: &mut ExtractionStats,
) -> Result<()> {
    // Create destination file
    let dest_file: std::fs::File = dest.create(path)?.into_std();

    if options.use_reflinks {
        // Try reflink first
        match ioctl_ficlone(&dest_file, src_fd.as_fd()) {
            Ok(()) => {
                stats.bytes_reflinked += size;
                stats.files_extracted += 1;
                return Ok(());
            }
            Err(e) => {
                // Check if reflink is simply not supported
                let errno = e.raw_os_error();
                if errno == rustix::io::Errno::OPNOTSUPP.raw_os_error()
                    || errno == rustix::io::Errno::XDEV.raw_os_error()
                    || errno == rustix::io::Errno::INVAL.raw_os_error()
                {
                    // Fall back to copy
                } else {
                    // Other error - still try to fall back
                    tracing::debug!(
                        "reflink failed with unexpected error: {}, falling back to copy",
                        e
                    );
                }
            }
        }
    }

    // Fall back to copy
    let mut src = std::fs::File::from(src_fd);
    src.seek(SeekFrom::Start(0))?;

    let mut dest_file = dest
        .open_with(path, OpenOptions::new().write(true))?
        .into_std();

    let copied = std::io::copy(&mut src, &mut dest_file)?;
    stats.bytes_copied += copied;
    stats.files_extracted += 1;

    Ok(())
}

/// Maximum size for GNU long names (64KB should be more than enough for any path).
const MAX_GNU_LONG_NAME_SIZE: u64 = 64 * 1024;

/// Read a GNU long name/linkname from a file descriptor.
fn read_gnu_long_string(fd: OwnedFd, size: u64) -> Result<String> {
    if size > MAX_GNU_LONG_NAME_SIZE {
        return Err(StorageError::TarSplitError(
            "GNU long name too large".into(),
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
                    match TarHeader::from_bytes(block) {
                        Ok(mut new_header) => {
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
                        Err(_) => {}
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
        assert!(opts.use_reflinks);
        assert!(opts.preserve_ownership);
        assert!(opts.preserve_permissions);
        assert!(opts.process_whiteouts);
    }

    #[test]
    fn test_extraction_stats_default() {
        let stats = ExtractionStats::default();
        assert_eq!(stats.files_extracted, 0);
        assert_eq!(stats.directories_created, 0);
        assert_eq!(stats.symlinks_created, 0);
        assert_eq!(stats.hardlinks_created, 0);
        assert_eq!(stats.bytes_reflinked, 0);
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
