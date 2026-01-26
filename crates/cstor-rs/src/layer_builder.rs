//! Layer creation with reflink support.
//!
//! This module provides the [`LayerBuilder`] struct for creating new layers
//! in containers-storage with reflink support.
//!
//! # Overview
//!
//! When creating a new layer, files can be added via reflink (copy-on-write)
//! from existing layers, avoiding actual data copying on filesystems that
//! support it (btrfs, XFS with reflink=1).
//!
//! # Workflow
//!
//! 1. Create a `LayerBuilder` from storage
//! 2. Add files, directories, and symlinks
//! 3. Commit the layer to storage
//!
//! # Example
//!
//! ```no_run
//! use cstor_rs::{Storage, LayerBuilder};
//!
//! let storage = Storage::discover()?;
//! let mut builder = LayerBuilder::new(&storage, None)?;
//!
//! // Add a directory
//! builder.add_directory("etc", 0o755, 0, 0)?;
//!
//! // Add a file (would use add_file_reflink for reflinks)
//! // builder.add_file_reflink("etc/hosts", src_fd, &toc_entry)?;
//!
//! // Commit the layer
//! let layer_id = builder.commit()?;
//! println!("Created layer: {}", layer_id);
//! # Ok::<(), cstor_rs::StorageError>(())
//! ```

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::io::BorrowedFd;
use std::path::Path;

use cap_std::fs::{Dir, MetadataExt, OpenOptions, Permissions, PermissionsExt};
use rustix::fs::{AtFlags, Gid, Mode, Uid, ioctl_ficlone};

use crate::error::{Result, StorageError};
use crate::storage::Storage;
use crate::tar_split_writer::TarSplitWriter;
use crate::toc::{TocEntry, TocEntryType};

/// Generate a random 64-character hex layer ID.
fn generate_layer_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Use current time and random data
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    // Simple pseudo-random based on time
    let seed = now.as_nanos();
    let mut id = String::with_capacity(64);

    for i in 0..32 {
        let byte = ((seed >> (i % 16)) ^ (seed >> ((i + 7) % 16))) as u8;
        id.push_str(&format!("{:02x}", byte.wrapping_add(i as u8)));
    }

    id
}

/// Generate a 26-character link ID.
fn generate_link_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let seed = now.as_nanos();
    let mut id = String::with_capacity(26);

    for i in 0..26 {
        let byte = ((seed >> (i % 16)) ^ (seed >> ((i + 5) % 16))) as usize;
        let idx = (byte.wrapping_add(i)) % ALPHABET.len();
        id.push(ALPHABET[idx] as char);
    }

    id
}

/// Builder for creating a new layer in containers-storage.
///
/// This allows adding files, directories, and symlinks to a new layer,
/// with support for reflink-based file addition.
#[derive(Debug)]
pub struct LayerBuilder {
    /// The storage root.
    storage_root: Dir,

    /// Handle to the staging directory for this layer.
    staging_handle: Dir,

    /// Handle to the diff directory where files are placed.
    diff_handle: Dir,

    /// Parent layer ID (if any).
    parent_id: Option<String>,

    /// Entries added to this layer (for tar-split generation).
    entries: Vec<TocEntry>,

    /// Generated layer ID.
    layer_id: String,

    /// Generated link ID.
    link_id: String,
}

impl LayerBuilder {
    /// Create a new layer builder.
    ///
    /// # Arguments
    ///
    /// * `storage` - Storage handle for accessing the storage root
    /// * `parent_id` - Optional parent layer ID
    ///
    /// # Errors
    ///
    /// Returns an error if the staging directory cannot be created.
    pub fn new(storage: &Storage, parent_id: Option<&str>) -> Result<Self> {
        let storage_root = storage.root_dir().try_clone()?;

        // Generate IDs
        let layer_id = generate_layer_id();
        let link_id = generate_link_id();

        // Create staging directory under overlay-layers/.staging/
        let staging_base = storage_root.open_dir("overlay-layers")?;

        // Create .staging directory if it doesn't exist
        match staging_base.create_dir(".staging") {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(StorageError::Io(e)),
        }

        let staging_parent = staging_base.open_dir(".staging")?;

        // Create our staging directory
        staging_parent.create_dir(&layer_id)?;
        let staging = staging_parent.open_dir(&layer_id)?;

        // Create diff directory
        staging.create_dir("diff")?;
        let diff_handle = staging.open_dir("diff")?;

        Ok(Self {
            storage_root,
            staging_handle: staging,
            diff_handle,
            parent_id: parent_id.map(|s| s.to_string()),
            entries: Vec::new(),
            layer_id,
            link_id,
        })
    }

    /// Get the layer ID that will be used when committed.
    pub fn layer_id(&self) -> &str {
        &self.layer_id
    }

    /// Get the link ID that will be used when committed.
    pub fn link_id(&self) -> &str {
        &self.link_id
    }

    /// Ensure parent directories exist for a path.
    fn ensure_parent_dirs(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            self.diff_handle.create_dir_all(parent)?;
        }
        Ok(())
    }

    /// Add a file by reflinking from a source file descriptor.
    ///
    /// Uses `FICLONE` ioctl for copy-on-write on supported filesystems.
    /// Falls back to regular copy if reflink is not supported.
    ///
    /// # Arguments
    ///
    /// * `path` - Path within the layer (e.g., "etc/hosts")
    /// * `src_fd` - Source file descriptor to reflink from
    /// * `entry` - TOC entry with metadata
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created or reflinked.
    pub fn add_file_reflink(
        &mut self,
        path: impl AsRef<Path>,
        src_fd: BorrowedFd<'_>,
        entry: &TocEntry,
    ) -> Result<()> {
        let path = path.as_ref();
        self.ensure_parent_dirs(path)?;

        // Create destination file using the Dir handle
        let dest_file: File = self.diff_handle.create(path)?.into_std();

        // Try reflink first
        let reflink_result = try_reflink(&dest_file, src_fd);

        match reflink_result {
            Ok(()) => {
                // Reflink succeeded
            }
            Err(e) if is_reflink_not_supported(&e) => {
                // Fall back to regular copy
                let mut src = File::from(rustix::io::dup(src_fd).map_err(|e| {
                    StorageError::Io(std::io::Error::from_raw_os_error(e.raw_os_error()))
                })?);
                src.seek(SeekFrom::Start(0))?;
                let mut dest = self
                    .diff_handle
                    .open_with(path, OpenOptions::new().write(true))?
                    .into_std();
                std::io::copy(&mut src, &mut dest)?;
            }
            Err(e) => return Err(e),
        }

        // Set permissions (best effort - may fail in rootless mode)
        let mode = Mode::from_raw_mode(entry.mode);
        let _ = rustix::fs::fchmod(&dest_file, mode);

        // Track entry for tar-split generation
        let mut tracked_entry = entry.clone();
        tracked_entry.name = path.to_path_buf();
        self.entries.push(tracked_entry);

        Ok(())
    }

    /// Add a file by copying content.
    ///
    /// # Arguments
    ///
    /// * `path` - Path within the layer
    /// * `content` - File content
    /// * `entry` - TOC entry with metadata
    pub fn add_file_copy(
        &mut self,
        path: impl AsRef<Path>,
        content: &[u8],
        entry: &TocEntry,
    ) -> Result<()> {
        let path = path.as_ref();
        self.ensure_parent_dirs(path)?;

        let mut dest_file: File = self.diff_handle.create(path)?.into_std();
        dest_file.write_all(content)?;

        // Set permissions (best effort)
        let mode = Mode::from_raw_mode(entry.mode);
        let _ = rustix::fs::fchmod(&dest_file, mode);

        // Track entry
        let mut tracked_entry = entry.clone();
        tracked_entry.name = path.to_path_buf();
        self.entries.push(tracked_entry);

        Ok(())
    }

    /// Add a directory.
    ///
    /// # Arguments
    ///
    /// * `path` - Path within the layer
    /// * `mode` - Directory permissions
    /// * `uid` - Owner user ID
    /// * `gid` - Owner group ID
    pub fn add_directory(
        &mut self,
        path: impl AsRef<Path>,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<()> {
        let path = path.as_ref();
        self.ensure_parent_dirs(path)?;

        self.diff_handle.create_dir(path)?;

        // Set permissions (best effort - may fail in rootless mode)
        let _ = self
            .diff_handle
            .set_permissions(path, Permissions::from_mode(mode));
        // Note: chown requires root or CAP_CHOWN
        let _ = rustix::fs::chownat(
            &self.diff_handle,
            path,
            Some(Uid::from_raw(uid)),
            Some(Gid::from_raw(gid)),
            AtFlags::empty(),
        );

        // Track entry
        self.entries.push(TocEntry {
            name: path.to_path_buf(),
            entry_type: TocEntryType::Dir,
            size: None,
            modtime: None,
            link_name: None,
            mode,
            uid,
            gid,
            user_name: None,
            group_name: None,
            dev_major: None,
            dev_minor: None,
            xattrs: None,
            digest: None,
        });

        Ok(())
    }

    /// Add a symbolic link.
    ///
    /// # Arguments
    ///
    /// * `path` - Path within the layer
    /// * `target` - Symlink target
    /// * `uid` - Owner user ID
    /// * `gid` - Owner group ID
    pub fn add_symlink(
        &mut self,
        path: impl AsRef<Path>,
        target: &str,
        uid: u32,
        gid: u32,
    ) -> Result<()> {
        let path = path.as_ref();
        self.ensure_parent_dirs(path)?;

        // symlink_contents allows the target to be any path (including non-existent)
        self.diff_handle.symlink_contents(target, path)?;

        // Note: lchown for symlinks requires root
        let _ = rustix::fs::chownat(
            &self.diff_handle,
            path,
            Some(Uid::from_raw(uid)),
            Some(Gid::from_raw(gid)),
            AtFlags::SYMLINK_NOFOLLOW,
        );

        // Track entry
        self.entries.push(TocEntry {
            name: path.to_path_buf(),
            entry_type: TocEntryType::Symlink,
            size: None,
            modtime: None,
            link_name: Some(target.to_string()),
            mode: 0o777, // Symlinks are always 0777
            uid,
            gid,
            user_name: None,
            group_name: None,
            dev_major: None,
            dev_minor: None,
            xattrs: None,
            digest: None,
        });

        Ok(())
    }

    /// Add a hard link.
    ///
    /// # Arguments
    ///
    /// * `path` - Path within the layer
    /// * `target` - Target path (must already exist in the layer)
    pub fn add_hardlink(&mut self, path: impl AsRef<Path>, target: &Path) -> Result<()> {
        let path = path.as_ref();
        self.ensure_parent_dirs(path)?;

        // hard_link(old, new) - creates `new` as a hard link to `old`
        self.diff_handle
            .hard_link(target, &self.diff_handle, path)?;

        // Get metadata from target
        let metadata = self.diff_handle.metadata(target)?;

        // Track entry
        self.entries.push(TocEntry {
            name: path.to_path_buf(),
            entry_type: TocEntryType::Hardlink,
            size: None, // Hardlinks don't store size
            modtime: None,
            link_name: Some(target.to_string_lossy().to_string()),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            user_name: None,
            group_name: None,
            dev_major: None,
            dev_minor: None,
            xattrs: None,
            digest: None,
        });

        Ok(())
    }

    /// Get the number of entries added.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Commit the layer to storage.
    ///
    /// This:
    /// 1. Generates tar-split metadata
    /// 2. Moves staging directory to final location
    /// 3. Creates link symlink
    /// 4. Updates layers.json
    ///
    /// # Returns
    ///
    /// The layer ID of the committed layer.
    pub fn commit(self) -> Result<String> {
        // Generate tar-split metadata
        let tar_split_data = self.generate_tar_split()?;

        // Write tar-split file
        let tar_split_path = format!("{}.tar-split.gz", self.layer_id);
        let layers_dir = self.storage_root.open_dir("overlay-layers")?;
        let mut tar_split_file = layers_dir.create(&tar_split_path)?;
        tar_split_file.write_all(&tar_split_data)?;

        // Move staging directory to final overlay location
        let overlay_dir = self.storage_root.open_dir("overlay")?;

        // Create layer directory in overlay/
        overlay_dir.create_dir(&self.layer_id)?;
        let layer_dir = overlay_dir.open_dir(&self.layer_id)?;

        // Move diff directory from staging to final location
        // Note: This requires same filesystem for rename
        // If cross-filesystem, we'd need to copy
        self.staging_handle.rename("diff", &layer_dir, "diff")?;

        // Create link file
        layer_dir.write("link", self.link_id.as_bytes())?;

        // Create lower file if there's a parent
        if let Some(ref parent_id) = self.parent_id {
            // Get parent's link ID
            let parent_layer_dir = overlay_dir.open_dir(parent_id)?;
            let parent_link = parent_layer_dir.read_to_string("link")?;
            let parent_link = parent_link.trim();

            // Read parent's lower file to build complete chain
            let lower = match parent_layer_dir.read_to_string("lower") {
                Ok(parent_lower) => {
                    let parent_lower = parent_lower.trim();
                    if parent_lower.is_empty() {
                        format!("l/{}", parent_link)
                    } else {
                        format!("l/{}:{}", parent_link, parent_lower)
                    }
                }
                Err(_) => format!("l/{}", parent_link),
            };

            layer_dir.write("lower", lower.as_bytes())?;
        }

        // Create symlink in l/ directory
        let links_dir = overlay_dir.open_dir("l")?;
        let link_target = format!("../{}/diff", self.layer_id);
        links_dir.symlink(&link_target, &self.link_id)?;

        // Update layers.json
        self.update_layers_json()?;

        // Clean up staging directory
        let staging_parent = self
            .storage_root
            .open_dir("overlay-layers")?
            .open_dir(".staging")?;
        staging_parent.remove_dir(&self.layer_id)?;

        Ok(self.layer_id.clone())
    }

    /// Generate tar-split metadata for the layer.
    fn generate_tar_split(&self) -> Result<Vec<u8>> {
        let mut writer = TarSplitWriter::new();

        // Sort entries by path for consistent ordering
        let mut sorted_entries = self.entries.clone();
        sorted_entries.sort_by(|a, b| a.name.cmp(&b.name));

        for entry in &sorted_entries {
            if entry.entry_type == TocEntryType::Reg && entry.size.unwrap_or(0) > 0 {
                // Open file for CRC64 computation
                let file: File = self.diff_handle.open(&entry.name)?.into_std();
                writer.add_toc_entry(entry, Some(file))?;
            } else {
                // Directory, symlink, etc. - no content
                writer.add_toc_entry(entry, None::<File>)?;
            }
        }

        writer.finish()
    }

    /// Update layers.json with the new layer.
    fn update_layers_json(&self) -> Result<()> {
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Serialize, Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct LayerEntry {
            id: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            parent: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            created: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            compressed_diff_digest: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            diff_digest: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            compressed_size: Option<u64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            diff_size: Option<u64>,
        }

        let layers_dir = self.storage_root.open_dir("overlay-layers")?;

        // Read existing layers.json
        let mut entries: Vec<LayerEntry> = match layers_dir.read_to_string("layers.json") {
            Ok(content) => serde_json::from_str(&content)?,
            Err(_) => Vec::new(),
        };

        // Calculate diff size from entries
        let diff_size: u64 = self.entries.iter().filter_map(|e| e.size).sum();

        // Create new entry
        let new_entry = LayerEntry {
            id: self.layer_id.clone(),
            parent: self.parent_id.clone(),
            created: Some(chrono::Utc::now().to_rfc3339()),
            compressed_diff_digest: None,
            diff_digest: None,
            compressed_size: None,
            diff_size: Some(diff_size),
        };

        entries.push(new_entry);

        // Write updated layers.json
        let json = serde_json::to_string_pretty(&entries)?;

        // Atomic write via temp file
        let temp_name = format!("layers.json.{}.tmp", self.layer_id);
        layers_dir.write(&temp_name, json.as_bytes())?;
        layers_dir.rename(&temp_name, &layers_dir, "layers.json")?;

        Ok(())
    }
}

impl Drop for LayerBuilder {
    fn drop(&mut self) {
        // Clean up staging directory if not committed
        // This is a best-effort cleanup
        if let Ok(layers_dir) = self.storage_root.open_dir("overlay-layers")
            && let Ok(staging) = layers_dir.open_dir(".staging")
        {
            let _ = staging.remove_dir_all(&self.layer_id);
        }
    }
}

/// Try to reflink a file using FICLONE ioctl.
fn try_reflink(dest: &File, src: BorrowedFd<'_>) -> Result<()> {
    ioctl_ficlone(dest, src)
        .map_err(|e| StorageError::Io(std::io::Error::from_raw_os_error(e.raw_os_error())))
}

/// Check if an error indicates reflink is not supported.
fn is_reflink_not_supported(err: &StorageError) -> bool {
    if let StorageError::Io(io_err) = err {
        if let Some(errno) = io_err.raw_os_error() {
            errno == rustix::io::Errno::OPNOTSUPP.raw_os_error()
                || errno == rustix::io::Errno::XDEV.raw_os_error()
                || errno == rustix::io::Errno::INVAL.raw_os_error()
        } else {
            false
        }
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_layer_id() {
        let id = generate_layer_id();
        assert_eq!(id.len(), 64);
        // Should be valid hex
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_link_id() {
        let id = generate_link_id();
        assert_eq!(id.len(), 26);
        // Should be uppercase letters only
        assert!(id.chars().all(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn test_is_reflink_not_supported() {
        use rustix::io::Errno;

        let eopnotsupp = StorageError::Io(std::io::Error::from_raw_os_error(
            Errno::OPNOTSUPP.raw_os_error(),
        ));
        assert!(is_reflink_not_supported(&eopnotsupp));

        let exdev = StorageError::Io(std::io::Error::from_raw_os_error(
            Errno::XDEV.raw_os_error(),
        ));
        assert!(is_reflink_not_supported(&exdev));

        let enoent = StorageError::Io(std::io::Error::from_raw_os_error(
            Errno::NOENT.raw_os_error(),
        ));
        assert!(!is_reflink_not_supported(&enoent));

        let other = StorageError::InvalidStorage("test".to_string());
        assert!(!is_reflink_not_supported(&other));
    }
}
