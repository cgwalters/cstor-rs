//! Tar archive writing from TarHeader and file descriptors.
//!
//! This module provides functionality to reassemble tar archives from
//! [`TarSplitFdStream`](crate::TarSplitFdStream) output, converting raw segment
//! bytes and file descriptors into a valid tar stream.
//!
//! # Overview
//!
//! When working with tar-split metadata, you need to reconstruct the original
//! tar archive by:
//! 1. Writing raw segment bytes (TAR headers + padding) exactly as stored
//! 2. Writing file content from file descriptors
//! 3. Adding proper padding to align to 512-byte boundaries
//! 4. Writing the tar footer (two zero blocks)
//!
//! This module provides the primitives to perform these operations while
//! maintaining byte-identical tar reconstruction.
//!
//! # TAR Format
//!
//! TAR archives consist of:
//! - 512-byte header blocks (ustar format)
//! - File content padded to 512-byte boundaries
//! - End-of-archive marker (1024 zero bytes)
//!
//! # Usage Example
//!
//! ```no_run
//! use cstor_rs::{Storage, Layer, TarSplitFdStream, TarSplitItem};
//! use cstor_rs::{write_file_data, write_tar_footer};
//! use std::io::Write;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let storage = Storage::discover()?;
//! let layer = Layer::open(&storage, "layer-id")?;
//! let mut stream = TarSplitFdStream::new(&storage, &layer)?;
//! let mut output = std::io::stdout();
//!
//! // Process all items from the tar-split stream
//! while let Some(item) = stream.next()? {
//!     match item {
//!         TarSplitItem::Segment(bytes) => {
//!             // Write raw TAR header/padding bytes directly
//!             output.write_all(&bytes)?;
//!         }
//!         TarSplitItem::FileContent { fd, size, .. } => {
//!             // Write file content with proper padding
//!             write_file_data(&mut output, fd, size)?;
//!         }
//!     }
//! }
//!
//! // Write tar footer
//! write_tar_footer(&mut output)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Alternative: Manual Header Writing
//!
//! For cases where you need to construct headers from scratch (not using
//! tar-split metadata), you can use [`write_tar_header`]:
//!
//! ```no_run
//! use cstor_rs::{TarHeader, write_tar_header};
//!
//! # fn example() -> std::io::Result<()> {
//! let header = TarHeader {
//!     name: "./test.txt".to_string(),
//!     mode: 0o644,
//!     uid: 1000,
//!     gid: 1000,
//!     size: 42,
//!     mtime: 1234567890,
//!     typeflag: b'0',
//!     linkname: String::new(),
//!     uname: "user".to_string(),
//!     gname: "group".to_string(),
//!     devmajor: 0,
//!     devminor: 0,
//! };
//!
//! let mut output = Vec::new();
//! write_tar_header(&mut output, &header)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Important Notes
//!
//! - Segment bytes from tar-split must be written exactly as provided
//! - File content must be padded to 512-byte boundaries
//! - The tar footer is required to mark the end of the archive
//! - All numeric fields use octal encoding in TAR headers

use crate::tar_split::TarHeader;
use std::io::{self, Read, Write};
use std::os::unix::io::OwnedFd;

/// Write a tar header to a writer.
///
/// This creates a 512-byte tar header block from the TarHeader structure.
pub fn write_tar_header<W: Write>(writer: &mut W, header: &TarHeader) -> io::Result<()> {
    let mut block = [0u8; 512];

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

    writer.write_all(&block)
}

/// Write data from a file descriptor with proper tar padding.
///
/// Reads data from the file descriptor and writes it to the output,
/// adding padding to align to 512-byte boundary.
pub fn write_file_data<W: Write>(writer: &mut W, fd: OwnedFd, size: u64) -> io::Result<()> {
    let mut file = std::fs::File::from(fd);
    let mut remaining = size;
    let mut buffer = [0u8; 8192];

    // Copy file data
    while remaining > 0 {
        let to_read = (remaining as usize).min(buffer.len());
        let n = file.read(&mut buffer[..to_read])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF while reading file data",
            ));
        }
        writer.write_all(&buffer[..n])?;
        remaining -= n as u64;
    }

    // Add padding to 512-byte boundary
    let padding = (512 - (size % 512)) % 512;
    if padding > 0 {
        let pad_buf = [0u8; 512];
        writer.write_all(&pad_buf[..padding as usize])?;
    }

    Ok(())
}

/// Write tar end-of-archive marker (two 512-byte zero blocks).
pub fn write_tar_footer<W: Write>(writer: &mut W) -> io::Result<()> {
    let block = [0u8; 1024];
    writer.write_all(&block)
}

/// Write an octal number to a byte slice.
fn write_octal(dest: &mut [u8], value: u64, width: usize) {
    let octal_str = format!("{:0width$o}", value, width = width);
    let bytes = octal_str.as_bytes();
    let len = bytes.len().min(dest.len());
    dest[..len].copy_from_slice(&bytes[..len]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_octal() {
        let mut buf = [0u8; 8];
        write_octal(&mut buf, 0o755, 7);
        assert_eq!(&buf[..7], b"0000755");

        write_octal(&mut buf, 0o644, 7);
        assert_eq!(&buf[..7], b"0000644");
    }

    #[test]
    fn test_tar_header_write() {
        let header = TarHeader {
            name: "test.txt".to_string(),
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

        let mut buf = Vec::new();
        write_tar_header(&mut buf, &header).unwrap();
        assert_eq!(buf.len(), 512);

        // Check magic
        assert_eq!(&buf[257..263], b"ustar\0");

        // Check version
        assert_eq!(&buf[263..265], b"00");
    }
}
