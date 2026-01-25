//! Tar-split metadata generation for layer creation.
//!
//! This module provides functionality to generate tar-split metadata from
//! filesystem entries. This is the inverse of [`TarSplitFdStream`](crate::TarSplitFdStream)
//! which reads tar-split metadata.
//!
//! # Overview
//!
//! When creating a new layer, we need to generate tar-split metadata that allows
//! the layer to be exported as a valid tar archive. The tar-split format stores:
//! - Raw TAR header bytes (base64-encoded) as Type 2 (Segment) entries
//! - File references with CRC64-ISO checksums as Type 1 (File) entries
//!
//! # Format
//!
//! The tar-split format is NDJSON (newline-delimited JSON), gzip-compressed:
//! ```json
//! {"type":2,"payload":"<base64-encoded tar header>"}
//! {"type":1,"name":"./etc/hosts","size":123,"crc64":"<base64-encoded checksum>"}
//! {"type":2,"payload":"<base64-encoded padding>"}
//! ...
//! {"type":2,"payload":"<base64-encoded footer - 1024 zero bytes>"}
//! ```
//!
//! # Example
//!
//! ```no_run
//! use cstor_rs::tar_split_writer::TarSplitWriter;
//!
//! fn example() -> cstor_rs::Result<()> {
//!     let mut writer = TarSplitWriter::new();
//!
//!     // Add entries (from TocEntry or TarHeader)
//!     // writer.add_entry(&entry, file_content)?;
//!
//!     // Finalize and get compressed output
//!     let tar_split_gz = writer.finish()?;
//!     Ok(())
//! }
//! ```

use std::io::{Read, Write};

use base64::prelude::*;
use crc::{Crc, CRC_64_GO_ISO};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::Serialize;

use crate::error::{Result, StorageError};
use crate::tar_split::TarHeader;
use crate::toc::{TocEntry, TocEntryType};

/// CRC64-ISO implementation for computing file checksums.
const CRC64_ISO: Crc<u64> = Crc::<u64>::new(&CRC_64_GO_ISO);

/// A tar-split entry for serialization.
#[derive(Debug, Serialize)]
struct TarSplitEntry {
    /// Entry type: 1 for File, 2 for Segment.
    #[serde(rename = "type")]
    type_id: u8,

    /// File name (type 1 only).
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    /// File size in bytes (type 1 only).
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<i64>,

    /// CRC64-ISO checksum, base64-encoded (type 1 only).
    #[serde(skip_serializing_if = "Option::is_none")]
    crc64: Option<String>,

    /// Base64-encoded payload (type 2 only).
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<String>,
}

/// Writer for generating tar-split metadata.
///
/// Collects entries and generates the NDJSON tar-split format,
/// which is then gzip-compressed.
#[derive(Debug)]
pub struct TarSplitWriter {
    /// Collected entries in NDJSON format.
    entries: Vec<String>,
}

impl Default for TarSplitWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl TarSplitWriter {
    /// Create a new TarSplitWriter.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a segment entry (raw TAR header bytes).
    fn add_segment(&mut self, bytes: &[u8]) -> Result<()> {
        let entry = TarSplitEntry {
            type_id: 2,
            name: None,
            size: None,
            crc64: None,
            payload: Some(BASE64_STANDARD.encode(bytes)),
        };
        let json = serde_json::to_string(&entry)?;
        self.entries.push(json);
        Ok(())
    }

    /// Add a file entry with CRC64 checksum.
    fn add_file_entry(&mut self, name: &str, size: u64, crc64: u64) -> Result<()> {
        let entry = TarSplitEntry {
            type_id: 1,
            name: Some(name.to_string()),
            size: Some(size as i64),
            crc64: Some(BASE64_STANDARD.encode(crc64.to_be_bytes())),
            payload: None,
        };
        let json = serde_json::to_string(&entry)?;
        self.entries.push(json);
        Ok(())
    }

    /// Add an entry from a TocEntry and optional file content.
    ///
    /// # Arguments
    ///
    /// * `entry` - The TOC entry describing the file
    /// * `content` - Optional file content reader (required for regular files)
    ///
    /// # Errors
    ///
    /// Returns an error if the header cannot be generated or content cannot be read.
    pub fn add_toc_entry<R: Read>(
        &mut self,
        entry: &TocEntry,
        mut content: Option<R>,
    ) -> Result<()> {
        // Generate tar header
        let header = toc_entry_to_tar_header(entry);
        let header_bytes = serialize_tar_header(&header)?;

        // Add segment for the header
        self.add_segment(&header_bytes)?;

        // For regular files with content, add file entry
        if entry.entry_type == TocEntryType::Reg {
            let size = entry.size.unwrap_or(0);
            if size > 0 {
                // Compute CRC64 of content
                let crc64 = if let Some(ref mut reader) = content {
                    compute_crc64(reader)?
                } else {
                    return Err(StorageError::TarSplitError(
                        "Content required for regular file".to_string(),
                    ));
                };

                // Add file entry
                let name = format!("./{}", entry.name.to_string_lossy());
                self.add_file_entry(&name, size, crc64)?;

                // Add padding segment if needed
                let padding = compute_tar_padding(size);
                if padding > 0 {
                    let pad_bytes = vec![0u8; padding];
                    self.add_segment(&pad_bytes)?;
                }
            }
        }

        Ok(())
    }

    /// Add an entry from a TarHeader and optional file content.
    ///
    /// This is useful when you have the raw tar header available.
    pub fn add_tar_header<R: Read>(
        &mut self,
        header: &TarHeader,
        mut content: Option<R>,
    ) -> Result<()> {
        // Serialize the header
        let header_bytes = serialize_tar_header(header)?;

        // Add segment for the header
        self.add_segment(&header_bytes)?;

        // For regular files with content, add file entry
        if header.is_regular_file() && header.size > 0 {
            // Compute CRC64 of content
            let crc64 = if let Some(ref mut reader) = content {
                compute_crc64(reader)?
            } else {
                return Err(StorageError::TarSplitError(
                    "Content required for regular file".to_string(),
                ));
            };

            // Add file entry
            self.add_file_entry(&header.name, header.size, crc64)?;

            // Add padding segment if needed
            let padding = compute_tar_padding(header.size);
            if padding > 0 {
                let pad_bytes = vec![0u8; padding];
                self.add_segment(&pad_bytes)?;
            }
        }

        Ok(())
    }

    /// Finalize the tar-split and return gzip-compressed output.
    ///
    /// Adds the tar footer (two 512-byte zero blocks) and compresses the output.
    pub fn finish(mut self) -> Result<Vec<u8>> {
        // Add tar footer (1024 zero bytes)
        let footer = vec![0u8; 1024];
        self.add_segment(&footer)?;

        // Join entries with newlines
        let mut ndjson = Vec::new();
        for entry in &self.entries {
            ndjson.extend_from_slice(entry.as_bytes());
            ndjson.push(b'\n');
        }

        // Gzip compress
        let mut compressed = Vec::new();
        {
            let mut encoder = GzEncoder::new(&mut compressed, Compression::fast());
            encoder.write_all(&ndjson).map_err(|e| {
                StorageError::TarSplitError(format!("Failed to compress tar-split: {}", e))
            })?;
            encoder.finish().map_err(|e| {
                StorageError::TarSplitError(format!("Failed to finish gzip compression: {}", e))
            })?;
        }

        Ok(compressed)
    }

    /// Get the number of entries added so far.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

/// Convert a TocEntry to a TarHeader.
fn toc_entry_to_tar_header(entry: &TocEntry) -> TarHeader {
    let typeflag = match entry.entry_type {
        TocEntryType::Reg => b'0',
        TocEntryType::Dir => b'5',
        TocEntryType::Symlink => b'2',
        TocEntryType::Hardlink => b'1',
        TocEntryType::Char => b'3',
        TocEntryType::Block => b'4',
        TocEntryType::Fifo => b'6',
    };

    // Add ./ prefix for tar format
    let name = format!("./{}", entry.name.to_string_lossy());

    // Parse mtime from RFC3339 or use 0
    let mtime = entry
        .modtime
        .as_ref()
        .and_then(|s| parse_rfc3339(s))
        .unwrap_or(0);

    TarHeader {
        name,
        mode: entry.mode,
        uid: entry.uid,
        gid: entry.gid,
        size: entry.size.unwrap_or(0),
        mtime,
        typeflag,
        linkname: entry.link_name.clone().unwrap_or_default(),
        uname: entry.user_name.clone().unwrap_or_default(),
        gname: entry.group_name.clone().unwrap_or_default(),
        devmajor: entry.dev_major.unwrap_or(0),
        devminor: entry.dev_minor.unwrap_or(0),
    }
}

/// Parse an RFC3339 timestamp to Unix seconds.
fn parse_rfc3339(s: &str) -> Option<i64> {
    // Simple parser for "YYYY-MM-DDTHH:MM:SSZ" format
    // For production, use chrono crate
    if s.len() < 19 {
        return None;
    }

    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let minute: i64 = s.get(14..16)?.parse().ok()?;
    let second: i64 = s.get(17..19)?.parse().ok()?;

    // Simple calculation (not accounting for leap seconds, etc.)
    // This is a rough approximation
    let days_since_epoch = (year - 1970) * 365 + (year - 1969) / 4 - (year - 1901) / 100
        + (year - 1601) / 400
        + days_before_month(month, is_leap_year(year))
        + day
        - 1;

    Some(days_since_epoch * 86400 + hour * 3600 + minute * 60 + second)
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_before_month(month: i64, leap: bool) -> i64 {
    const DAYS: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let d = DAYS.get((month - 1) as usize).copied().unwrap_or(0);
    if leap && month > 2 {
        d + 1
    } else {
        d
    }
}

/// Serialize a TarHeader to a 512-byte block.
fn serialize_tar_header(header: &TarHeader) -> Result<Vec<u8>> {
    let mut block = vec![0u8; 512];

    // Name (100 bytes)
    let name_bytes = header.name.as_bytes();
    let name_len = name_bytes.len().min(100);
    block[0..name_len].copy_from_slice(&name_bytes[0..name_len]);

    // Mode (8 bytes octal)
    write_octal(&mut block[100..108], header.mode as u64, 7);

    // UID (8 bytes octal)
    write_octal(&mut block[108..116], header.uid as u64, 7);

    // GID (8 bytes octal)
    write_octal(&mut block[116..124], header.gid as u64, 7);

    // Size (12 bytes octal)
    write_octal(&mut block[124..136], header.size, 11);

    // Mtime (12 bytes octal)
    write_octal(&mut block[136..148], header.mtime as u64, 11);

    // Checksum placeholder (8 bytes) - fill with spaces initially
    block[148..156].fill(b' ');

    // Typeflag (1 byte)
    block[156] = header.typeflag;

    // Linkname (100 bytes)
    let link_bytes = header.linkname.as_bytes();
    let link_len = link_bytes.len().min(100);
    block[157..157 + link_len].copy_from_slice(&link_bytes[0..link_len]);

    // Magic ("ustar\0")
    block[257..263].copy_from_slice(b"ustar\0");

    // Version ("00")
    block[263..265].copy_from_slice(b"00");

    // Uname (32 bytes)
    let uname_bytes = header.uname.as_bytes();
    let uname_len = uname_bytes.len().min(32);
    block[265..265 + uname_len].copy_from_slice(&uname_bytes[0..uname_len]);

    // Gname (32 bytes)
    let gname_bytes = header.gname.as_bytes();
    let gname_len = gname_bytes.len().min(32);
    block[297..297 + gname_len].copy_from_slice(&gname_bytes[0..gname_len]);

    // Devmajor (8 bytes octal)
    write_octal(&mut block[329..337], header.devmajor as u64, 7);

    // Devminor (8 bytes octal)
    write_octal(&mut block[337..345], header.devminor as u64, 7);

    // Calculate checksum (sum of all bytes, with checksum field as spaces)
    let checksum: u32 = block.iter().map(|&b| b as u32).sum();

    // Write checksum (6 bytes octal + null + space)
    write_octal(&mut block[148..154], checksum as u64, 6);
    block[154] = 0;
    block[155] = b' ';

    Ok(block)
}

/// Write an octal number to a byte slice.
fn write_octal(dest: &mut [u8], value: u64, width: usize) {
    let octal_str = format!("{:0width$o}", value, width = width);
    let bytes = octal_str.as_bytes();
    let len = bytes.len().min(dest.len());
    dest[..len].copy_from_slice(&bytes[..len]);
}

/// Compute CRC64-ISO checksum of data from a reader.
pub fn compute_crc64<R: Read>(reader: &mut R) -> Result<u64> {
    let mut digest = CRC64_ISO.digest();
    let mut buffer = [0u8; 8192];

    loop {
        let n = reader
            .read(&mut buffer)
            .map_err(|e| StorageError::TarSplitError(format!("Failed to read for CRC64: {}", e)))?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }

    Ok(digest.finalize())
}

/// Compute the padding needed to align to 512-byte boundary.
pub fn compute_tar_padding(size: u64) -> usize {
    let remainder = size % 512;
    if remainder > 0 {
        (512 - remainder) as usize
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_tar_padding() {
        assert_eq!(compute_tar_padding(0), 0);
        assert_eq!(compute_tar_padding(1), 511);
        assert_eq!(compute_tar_padding(100), 412);
        assert_eq!(compute_tar_padding(512), 0);
        assert_eq!(compute_tar_padding(513), 511);
        assert_eq!(compute_tar_padding(1024), 0);
    }

    #[test]
    fn test_compute_crc64() {
        // Test with known data
        let data = b"Hello, World!";
        let crc = compute_crc64(&mut &data[..]).unwrap();
        // CRC64-ISO of "Hello, World!" should be a specific value
        // Just verify it's non-zero and consistent
        assert_ne!(crc, 0);

        // Empty data
        let empty: &[u8] = &[];
        let crc_empty = compute_crc64(&mut &empty[..]).unwrap();
        assert_eq!(crc_empty, 0);
    }

    #[test]
    fn test_serialize_tar_header() {
        let header = TarHeader {
            name: "./test.txt".to_string(),
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            size: 42,
            mtime: 1234567890,
            typeflag: b'0',
            linkname: String::new(),
            uname: "user".to_string(),
            gname: "group".to_string(),
            devmajor: 0,
            devminor: 0,
        };

        let block = serialize_tar_header(&header).unwrap();
        assert_eq!(block.len(), 512);

        // Verify magic
        assert_eq!(&block[257..263], b"ustar\0");

        // Verify the header can be parsed back
        let parsed = TarHeader::from_bytes(&block).unwrap();
        assert_eq!(parsed.name, "./test.txt");
        assert_eq!(parsed.mode, 0o644);
        assert_eq!(parsed.size, 42);
    }

    #[test]
    fn test_tar_split_writer_basic() {
        let mut writer = TarSplitWriter::new();

        // Add a simple file entry
        let header = TarHeader {
            name: "./test.txt".to_string(),
            mode: 0o644,
            uid: 0,
            gid: 0,
            size: 5,
            mtime: 0,
            typeflag: b'0',
            linkname: String::new(),
            uname: String::new(),
            gname: String::new(),
            devmajor: 0,
            devminor: 0,
        };

        let content = b"hello";
        writer.add_tar_header(&header, Some(&content[..])).unwrap();

        // Finish and verify output is gzip compressed
        let output = writer.finish().unwrap();
        assert!(!output.is_empty());

        // First two bytes should be gzip magic
        assert_eq!(output[0], 0x1f);
        assert_eq!(output[1], 0x8b);
    }

    #[test]
    fn test_tar_split_writer_directory() {
        let mut writer = TarSplitWriter::new();

        let header = TarHeader {
            name: "./mydir".to_string(),
            mode: 0o755,
            uid: 0,
            gid: 0,
            size: 0,
            mtime: 0,
            typeflag: b'5', // Directory
            linkname: String::new(),
            uname: String::new(),
            gname: String::new(),
            devmajor: 0,
            devminor: 0,
        };

        // Directories don't need content
        writer.add_tar_header(&header, None::<&[u8]>).unwrap();

        let output = writer.finish().unwrap();
        assert!(!output.is_empty());
    }

    #[test]
    fn test_parse_rfc3339() {
        // Test a known timestamp
        let ts = parse_rfc3339("2024-01-15T12:40:45Z");
        assert!(ts.is_some());
        // Should be approximately 1705322445
        let secs = ts.unwrap();
        assert!(secs > 1700000000);
        assert!(secs < 1800000000);

        // Invalid format
        assert!(parse_rfc3339("not-a-date").is_none());
        assert!(parse_rfc3339("").is_none());
    }
}
