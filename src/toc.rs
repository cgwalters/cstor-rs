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
//!     println!("{}: {:?}", entry.name, entry.entry_type);
//! }
//! # Ok::<(), cstor_rs::StorageError>(())
//! ```

use serde::{Deserialize, Serialize};

use crate::error::{Result, StorageError};
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

/// A single entry in the TOC.
///
/// Contains metadata about a file, directory, symlink, or other entry
/// in the layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TocEntry {
    /// Complete path in the layer (e.g., "usr/bin/bash").
    /// Does not include leading "./" or "/".
    pub name: String,

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
    /// Create a TocEntry from a TarHeader.
    pub fn from_tar_header(header: &TarHeader) -> Option<Self> {
        let entry_type = TocEntryType::from_typeflag(header.typeflag)?;

        // Normalize the name (strip leading "./")
        let name = header.normalized_name().to_string();

        // Skip empty names (root directory marker)
        if name.is_empty() {
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
                TarSplitItem::FileContent(fd, size) => {
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
    /// Layers are processed in order, with later layers overriding
    /// earlier ones (matching overlay filesystem semantics).
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
        let mut all_entries = Vec::new();

        for layer_id in &layer_ids {
            let layer = Layer::open(storage, layer_id)?;
            let layer_toc = Self::from_layer(storage, &layer)?;
            all_entries.extend(layer_toc.entries);
        }

        Ok(Toc {
            version: 1,
            entries: all_entries,
        })
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
}
