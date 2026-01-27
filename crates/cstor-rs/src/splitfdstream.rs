//! Split file descriptor stream format for serializing binary data with external chunks.
//!
//! This module implements a binary format for representing serialized binary files
//! (tar archives, zip files, filesystem images, etc.) where data chunks can be stored
//! externally as file descriptors rather than inline in the stream.
//!
//! # Format Overview
//!
//! A splitfdstream is a sequential stream of chunks. Each chunk begins with a signed
//! 64-bit little-endian prefix that determines the chunk type:
//!
//! | Prefix Value | Meaning |
//! |--------------|---------|
//! | `< 0`        | **Inline**: The next `abs(prefix)` bytes are literal data |
//! | `≥ 0`        | **External**: Content comes from `fd[prefix + 1]` |
//!
//! # Use Cases
//!
//! The splitfdstream format is designed for scenarios where:
//!
//! - Large binary files need to be transferred with some data stored externally
//! - File descriptors can be passed alongside the stream (e.g., via Unix sockets)
//! - Deduplication is desired by referencing the same external fd multiple times
//! - Zero-copy operations are possible by referencing files directly
//!
//! # Example
//!
//! ```
//! use cstor_rs::splitfdstream::{SplitfdstreamWriter, SplitfdstreamReader, Chunk};
//!
//! // Write a stream with mixed inline and external chunks
//! let mut buffer = Vec::new();
//! let mut writer = SplitfdstreamWriter::new(&mut buffer);
//! writer.write_inline(b"inline data").unwrap();
//! writer.write_external(0).unwrap();  // Reference fd[1]
//! writer.write_inline(b"more inline").unwrap();
//! writer.finish().unwrap();
//!
//! // Read the stream back
//! let mut reader = SplitfdstreamReader::new(buffer.as_slice());
//! while let Some(chunk) = reader.next_chunk().unwrap() {
//!     match chunk {
//!         Chunk::Inline(data) => println!("Inline: {} bytes", data.len()),
//!         Chunk::External(fd_index) => println!("External: fd[{}]", fd_index + 1),
//!     }
//! }
//! ```
//!
//! # Wire Format Details
//!
//! The stream consists of a sequence of chunks with no framing header or footer.
//! Each chunk is:
//!
//! 1. An 8-byte signed little-endian integer (the prefix)
//! 2. For inline chunks only: `abs(prefix)` bytes of literal data
//!
//! External chunks have no additional data after the prefix; the content is
//! retrieved from the file descriptor array passed alongside the stream.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Maximum size for an inline chunk (256 MB).
///
/// This limit prevents denial-of-service attacks where a malicious stream
/// could specify an extremely large inline chunk size, causing unbounded
/// memory allocation.
const MAX_INLINE_CHUNK_SIZE: usize = 256 * 1024 * 1024;

use crate::readatreader::ReadAtReader;

use cap_std::fs::{Dir, Permissions};
use std::os::unix::fs::PermissionsExt;
use tar::EntryType;

/// Whiteout file prefix used by overlay filesystems.
/// Files named `.wh.<name>` indicate that `<name>` should be removed.
const WHITEOUT_PREFIX: &str = ".wh.";

/// Opaque whiteout marker filename.
/// A file named `.wh..wh..opq` in a directory indicates that all entries
/// in that directory from lower layers should be hidden.
const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";

/// Media type for splitfdstream format.
pub const MEDIA_TYPE: &str = "application/vnd.containers.splitfdstream";

/// Media type for zstd-compressed splitfdstream format.
pub const MEDIA_TYPE_ZSTD: &str = "application/vnd.containers.splitfdstream+zstd";

/// A chunk read from a splitfdstream.
///
/// Chunks are either inline data embedded in the stream, or references to
/// external file descriptors that should be read separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chunk<'a> {
    /// Inline data embedded directly in the stream.
    Inline(&'a [u8]),

    /// Reference to an external file descriptor.
    ///
    /// The value is the fd index (0-based), meaning the actual fd is at
    /// position `fd_index + 1` in the fd array (fd\[0\] is typically the
    /// stream itself).
    External(u32),
}

/// Writer for building a splitfdstream.
///
/// The writer encodes inline data and external fd references into the
/// splitfdstream binary format.
///
/// # Example
///
/// ```
/// use cstor_rs::splitfdstream::SplitfdstreamWriter;
///
/// let mut buffer = Vec::new();
/// let mut writer = SplitfdstreamWriter::new(&mut buffer);
///
/// // Write some inline data
/// writer.write_inline(b"Hello, world!").unwrap();
///
/// // Reference external fd at index 0 (fd[1])
/// writer.write_external(0).unwrap();
///
/// // Finish and get the underlying writer back
/// let buffer = writer.finish().unwrap();
/// ```
#[derive(Debug)]
pub struct SplitfdstreamWriter<W> {
    writer: W,
}

impl<W: Write> SplitfdstreamWriter<W> {
    /// Create a new splitfdstream writer wrapping the given writer.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Write inline data to the stream.
    ///
    /// The data is prefixed with a negative i64 indicating the length,
    /// followed by the literal bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the underlying writer fails.
    pub fn write_inline(&mut self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        // Prefix is negative length
        let len = data.len() as i64;
        let prefix = -len;
        self.writer.write_all(&prefix.to_le_bytes())?;
        self.writer.write_all(data)?;
        Ok(())
    }

    /// Write an external fd reference to the stream.
    ///
    /// The fd_index is the 0-based index into the fd array. The actual
    /// file descriptor is at position `fd_index + 1` (since fd\[0\] is
    /// typically the stream itself).
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the underlying writer fails.
    pub fn write_external(&mut self, fd_index: u32) -> io::Result<()> {
        // Prefix is fd_index (non-negative), actual fd is at fd_index + 1
        let prefix = fd_index as i64;
        self.writer.write_all(&prefix.to_le_bytes())?;
        Ok(())
    }

    /// Finish writing and return the underlying writer.
    ///
    /// This consumes the writer and returns the underlying `Write` impl.
    pub fn finish(self) -> io::Result<W> {
        Ok(self.writer)
    }
}

/// Reader for parsing a splitfdstream.
///
/// The reader parses the binary format and yields chunks that are either
/// inline data or references to external file descriptors.
///
/// # Example
///
/// ```
/// use cstor_rs::splitfdstream::{SplitfdstreamReader, Chunk};
///
/// let data = vec![
///     // Inline chunk: prefix = -5, then 5 bytes
///     0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // -5 as i64 LE
///     b'h', b'e', b'l', b'l', b'o',
/// ];
///
/// let mut reader = SplitfdstreamReader::new(data.as_slice());
/// let chunk = reader.next_chunk().unwrap().unwrap();
/// assert_eq!(chunk, Chunk::Inline(b"hello"));
/// ```
#[derive(Debug)]
pub struct SplitfdstreamReader<R> {
    reader: R,
    /// Buffer for reading inline data
    buffer: Vec<u8>,
}

impl<R: Read> SplitfdstreamReader<R> {
    /// Create a new splitfdstream reader wrapping the given reader.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: Vec::new(),
        }
    }

    /// Consume this reader, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// Read the next chunk from the stream.
    ///
    /// Returns `Ok(None)` when the stream is exhausted.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Reading from the underlying reader fails
    /// - The stream contains invalid data (e.g., inline size exceeds i64::MAX)
    pub fn next_chunk(&mut self) -> io::Result<Option<Chunk<'_>>> {
        // Read the 8-byte prefix
        let mut prefix_bytes = [0u8; 8];
        match self.reader.read_exact(&mut prefix_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }

        let prefix = i64::from_le_bytes(prefix_bytes);

        if prefix < 0 {
            // Inline chunk: read abs(prefix) bytes
            let len = (-prefix) as usize;
            if len > MAX_INLINE_CHUNK_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "inline chunk size {} exceeds maximum allowed size {}",
                        len, MAX_INLINE_CHUNK_SIZE
                    ),
                ));
            }
            self.buffer.clear();
            self.buffer.resize(len, 0);
            self.reader.read_exact(&mut self.buffer)?;
            Ok(Some(Chunk::Inline(&self.buffer)))
        } else {
            // External chunk: prefix is the fd index
            Ok(Some(Chunk::External(prefix as u32)))
        }
    }
}

/// A `Read` adapter that reconstructs a byte stream from a splitfdstream.
///
/// This struct implements `Read` by combining inline chunks and external file
/// descriptor content into a contiguous byte stream. It can be used with
/// `tar::Archive` to parse tar entries from a splitfdstream.
///
/// External files are read using positional read (pread/read_at), so the
/// same file can be referenced multiple times in the splitfdstream without
/// needing to reopen or seek it.
///
/// # Example
///
/// ```no_run
/// use std::fs::File;
/// use cstor_rs::splitfdstream::SplitfdstreamTarReader;
/// use tar::Archive;
///
/// let stream_data: &[u8] = &[/* splitfdstream bytes */];
/// let files: Vec<File> = vec![/* external files */];
///
/// let reader = SplitfdstreamTarReader::new(stream_data, &files);
/// let mut archive = Archive::new(reader);
///
/// for entry in archive.entries().unwrap() {
///     let entry = entry.unwrap();
///     println!("File: {:?}", entry.path().unwrap());
/// }
/// ```
#[derive(Debug)]
pub struct SplitfdstreamTarReader<'files, R: Read> {
    reader: SplitfdstreamReader<R>,
    files: &'files [std::fs::File],
    /// Buffer for inline data (partially consumed)
    inline_buffer: Vec<u8>,
    /// Position within inline_buffer
    inline_pos: usize,
    /// Current external file being read (if any) - uses read_at internally
    current_external: Option<ReadAtReader<'files>>,
}

impl<'files, R: Read> SplitfdstreamTarReader<'files, R> {
    /// Create a new tar reader from a splitfdstream and files.
    ///
    /// The `files` slice provides the external files referenced by the
    /// splitfdstream. Each external chunk at index N reads from `files[N]`.
    pub fn new(splitfdstream: R, files: &'files [std::fs::File]) -> Self {
        Self {
            reader: SplitfdstreamReader::new(splitfdstream),
            files,
            inline_buffer: Vec::new(),
            inline_pos: 0,
            current_external: None,
        }
    }
}

impl<'files, R: Read> Read for SplitfdstreamTarReader<'files, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // First, drain any buffered inline data
        if self.inline_pos < self.inline_buffer.len() {
            let remaining = &self.inline_buffer[self.inline_pos..];
            let n = buf.len().min(remaining.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.inline_pos += n;
            return Ok(n);
        }

        // Next, drain current external file if any
        if let Some(ref mut ext) = self.current_external {
            let n = ext.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            // External exhausted, move to next chunk
            self.current_external = None;
        }

        // Get next chunk from splitfdstream
        match self.reader.next_chunk()? {
            None => Ok(0), // EOF
            Some(Chunk::Inline(data)) => {
                let n = buf.len().min(data.len());
                buf[..n].copy_from_slice(&data[..n]);
                if n < data.len() {
                    // Buffer remaining data for next read
                    self.inline_buffer.clear();
                    self.inline_buffer.extend_from_slice(&data[n..]);
                    self.inline_pos = 0;
                }
                Ok(n)
            }
            Some(Chunk::External(idx)) => {
                let idx = idx as usize;
                if idx >= self.files.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "external chunk references fd index {} but only {} files provided",
                            idx,
                            self.files.len()
                        ),
                    ));
                }
                self.current_external = Some(ReadAtReader::new(&self.files[idx]));
                // Recurse to read from the new external
                self.read(buf)
            }
        }
    }
}

/// Reconstruct a tar stream from splitfdstream + file descriptors.
///
/// This function reads a splitfdstream and writes the reconstructed data to `output`.
/// Inline chunks are written directly, while external chunks are read from the
/// corresponding file descriptors in `fds`.
///
/// # Arguments
///
/// * `splitfdstream` - A reader providing the splitfdstream data
/// * `fds` - Array of file descriptors for external chunks (borrowed, not consumed)
/// * `output` - Writer to receive the reconstructed tar stream
///
/// # Returns
///
/// The total number of bytes written to `output`.
///
/// # Errors
///
/// Returns an error if:
/// * Reading from the splitfdstream fails
/// * An external chunk references an fd index outside the bounds of `fds`
/// * Reading from an external fd fails
/// * Writing to the output fails
///
/// # Example
///
/// ```no_run
/// use std::fs::File;
/// use std::io::Cursor;
/// use std::os::unix::io::OwnedFd;
/// use cstor_rs::splitfdstream::{reconstruct_tar, SplitfdstreamWriter};
///
/// // Create a splitfdstream with inline data
/// let mut stream_buf = Vec::new();
/// let mut writer = SplitfdstreamWriter::new(&mut stream_buf);
/// writer.write_inline(b"tar header data").unwrap();
/// writer.finish().unwrap();
///
/// // Reconstruct to output (empty file slice)
/// let files: &[std::fs::File] = &[];
/// let mut output = Vec::new();
/// let bytes = reconstruct_tar(stream_buf.as_slice(), files, &mut output).unwrap();
/// assert_eq!(output, b"tar header data");
/// ```
pub fn reconstruct_tar<R, W>(
    splitfdstream: R,
    files: &[std::fs::File],
    output: &mut W,
) -> io::Result<u64>
where
    R: Read,
    W: Write,
{
    let mut reader = SplitfdstreamReader::new(splitfdstream);
    let mut bytes_written = 0u64;

    while let Some(chunk) = reader.next_chunk()? {
        match chunk {
            Chunk::Inline(data) => {
                output.write_all(data)?;
                bytes_written += data.len() as u64;
            }
            Chunk::External(idx) => {
                let file = files.get(idx as usize).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "external chunk references fd index {} but only {} files provided",
                            idx,
                            files.len()
                        ),
                    )
                })?;
                let copied = copy_from_file(file, output)?;
                bytes_written += copied;
            }
        }
    }

    Ok(bytes_written)
}

/// Reconstruct a tar stream, seeking external files back to the start before reading.
///
/// This is useful when the files may have been read previously and need to be
/// rewound. Each external file is seeked to the beginning before copying.
///
/// Note: With positional reads, seeking is no longer strictly necessary since
/// `read_at` doesn't use the file position. This function is kept for API
/// compatibility.
///
/// # Arguments
///
/// * `splitfdstream` - A reader providing the splitfdstream data
/// * `files` - Array of files for external chunks
/// * `output` - Writer to receive the reconstructed tar stream
///
/// # Returns
///
/// The total number of bytes written to `output`.
///
/// # Errors
///
/// Returns an error if:
/// * Reading from the splitfdstream fails
/// * An external chunk references a file index outside the bounds of `files`
/// * Reading from an external file fails
/// * Writing to the output fails
pub fn reconstruct_tar_seekable<R, W>(
    splitfdstream: R,
    files: &[std::fs::File],
    output: &mut W,
) -> io::Result<u64>
where
    R: Read,
    W: Write,
{
    // With read_at, we don't need seeking - just delegate to reconstruct_tar
    reconstruct_tar(splitfdstream, files, output)
}

/// Copy all data from a file to a writer using positional read.
///
/// This reads from the file without affecting its file position, starting
/// from offset 0 and reading the entire file.
fn copy_from_file<W: Write>(file: &std::fs::File, output: &mut W) -> io::Result<u64> {
    let mut reader = ReadAtReader::new(file);
    io::copy(&mut reader, output)
}

/// Statistics from splitfdstream extraction.
#[derive(Debug, Clone, Default)]
pub struct ExtractionStats {
    /// Number of files successfully extracted.
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
    /// Bytes written inline (small files embedded in stream).
    pub bytes_inline: u64,
    /// Number of whiteouts processed (files/dirs removed).
    pub whiteouts_processed: usize,
}

/// Process a whiteout entry, returning true if the path was a whiteout.
///
/// Handles both regular whiteouts (`.wh.<name>`) and opaque whiteouts
/// (`.wh..wh..opq`) according to overlay filesystem semantics.
fn process_whiteout(path: &Path, dest: &Dir) -> io::Result<bool> {
    let Some(filename) = path.file_name() else {
        return Ok(false);
    };
    let Some(filename) = filename.to_str() else {
        return Ok(false);
    };

    if filename == OPAQUE_WHITEOUT {
        // Opaque whiteout: remove all contents from parent directory
        let Some(parent) = path.parent() else {
            return Ok(true);
        };
        let Ok(parent_dir) = dest.open_dir(parent) else {
            return Ok(true);
        };
        for dir_entry in parent_dir.entries()?.flatten() {
            let name = dir_entry.file_name();
            let Ok(ft) = dir_entry.file_type() else {
                continue;
            };
            if ft.is_dir() {
                let _ = parent_dir.remove_dir_all(&name);
            } else {
                let _ = parent_dir.remove_file(&name);
            }
        }
        return Ok(true);
    }

    let Some(target_name) = filename.strip_prefix(WHITEOUT_PREFIX) else {
        return Ok(false);
    };

    // Regular whiteout: remove the target file/directory
    let target_path = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(target_name),
        _ => PathBuf::from(target_name),
    };
    // Try to remove as file first, then as directory
    if dest.remove_file(&target_path).is_err() {
        let _ = dest.remove_dir_all(&target_path);
    }
    Ok(true)
}

/// Extract files from a splitfdstream to a directory using `tar::Archive`.
///
/// This function reconstructs the tar stream and uses the tar crate's extraction
/// logic to handle all entry types including GNU long names, PAX headers, etc.
///
/// Note: This version does not use reflinks for zero-copy extraction. For
/// reflink support, use `extract_to_dir_reflink` instead.
///
/// # Arguments
///
/// * `splitfdstream` - A reader providing the splitfdstream data
/// * `files` - Array of files for external chunks
/// * `dest` - Destination directory handle
///
/// # Returns
///
/// Statistics about the extraction including files/bytes processed.
///
/// # Errors
///
/// Returns an error if:
/// * Reading from the splitfdstream fails
/// * An external chunk references a file index outside the bounds of `files`
/// * Creating files/directories fails
///
/// # Example
///
/// ```no_run
/// use cap_std::fs::Dir;
/// use cap_std::ambient_authority;
/// use cstor_rs::splitfdstream::extract_to_dir;
///
/// let stream_data = vec![/* splitfdstream data */];
/// let files: Vec<std::fs::File> = vec![/* files */];
/// let dest = Dir::open_ambient_dir("/tmp/extract", ambient_authority())?;
///
/// let stats = extract_to_dir(stream_data.as_slice(), &files, &dest, true)?;
/// println!("Extracted {} files", stats.files_extracted);
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn extract_to_dir<R: Read>(
    splitfdstream: R,
    files: &[std::fs::File],
    dest: &Dir,
    _force_copy: bool, // Kept for API compatibility, but always copies
) -> io::Result<ExtractionStats> {
    let tar_reader = SplitfdstreamTarReader::new(splitfdstream, files);
    let mut archive = tar::Archive::new(tar_reader);
    let mut stats = ExtractionStats::default();

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;

        // Extract all header info before we mutably borrow entry
        let entry_type = entry.header().entry_type();
        let mode = entry.header().mode().ok();
        let link_name = entry
            .header()
            .link_name()
            .ok()
            .flatten()
            .map(|c| c.into_owned());
        let path = entry.path()?.into_owned();

        // Normalize path by stripping leading "./"
        let normalized_path: PathBuf = path.strip_prefix("./").unwrap_or(&path).to_path_buf();

        if normalized_path.as_os_str().is_empty() {
            continue;
        }

        // Handle whiteout files before creating parent directories
        if process_whiteout(&normalized_path, dest)? {
            stats.whiteouts_processed += 1;
            continue;
        }

        // Create parent directories
        if let Some(parent) = normalized_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            dest.create_dir_all(parent)?;
        }

        match entry_type {
            EntryType::Directory => {
                match dest.create_dir(&normalized_path) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e),
                }
                if let Some(mode) = mode {
                    let perms = Permissions::from_std(std::fs::Permissions::from_mode(mode));
                    dest.set_permissions(&normalized_path, perms)?;
                }
                stats.directories_created += 1;
            }
            EntryType::Symlink => {
                if let Some(ref link_name) = link_name {
                    let _ = dest.remove_file(&normalized_path);
                    dest.symlink(link_name, &normalized_path)?;
                    stats.symlinks_created += 1;
                }
            }
            EntryType::Link => {
                if let Some(ref link_name) = link_name {
                    let target: PathBuf = link_name
                        .strip_prefix("./")
                        .unwrap_or(link_name)
                        .to_path_buf();
                    let _ = dest.remove_file(&normalized_path);
                    dest.hard_link(&target, dest, &normalized_path)?;
                    stats.hardlinks_created += 1;
                }
            }
            EntryType::Regular | EntryType::Continuous => {
                let _ = dest.remove_file(&normalized_path);
                let mut file = dest.create(&normalized_path)?;
                let size = io::copy(&mut entry, &mut file)?;
                if let Some(mode) = mode {
                    let perms = Permissions::from_std(std::fs::Permissions::from_mode(mode));
                    dest.set_permissions(&normalized_path, perms)?;
                }
                stats.files_extracted += 1;
                stats.bytes_copied += size;
            }
            EntryType::Char | EntryType::Block | EntryType::Fifo => {
                // Skip device files and FIFOs - can't create as unprivileged user
            }
            _ => {
                // Skip other entry types (GNU extensions are handled by tar crate)
            }
        }
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to write and read back chunks, verifying round-trip.
    fn roundtrip_chunks(
        inline_chunks: &[&[u8]],
        external_indices: &[u32],
        interleave: bool,
    ) -> Vec<(bool, Vec<u8>, u32)> {
        let mut buffer = Vec::new();
        {
            let mut writer = SplitfdstreamWriter::new(&mut buffer);

            if interleave {
                let max_len = inline_chunks.len().max(external_indices.len());
                for i in 0..max_len {
                    if i < inline_chunks.len() {
                        writer.write_inline(inline_chunks[i]).unwrap();
                    }
                    if i < external_indices.len() {
                        writer.write_external(external_indices[i]).unwrap();
                    }
                }
            } else {
                for chunk in inline_chunks {
                    writer.write_inline(chunk).unwrap();
                }
                for &idx in external_indices {
                    writer.write_external(idx).unwrap();
                }
            }

            writer.finish().unwrap();
        }

        // Read back
        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        let mut results = Vec::new();

        while let Some(chunk) = reader.next_chunk().unwrap() {
            match chunk {
                Chunk::Inline(data) => {
                    results.push((true, data.to_vec(), 0));
                }
                Chunk::External(idx) => {
                    results.push((false, Vec::new(), idx));
                }
            }
        }

        results
    }

    #[test]
    fn test_empty_stream() {
        let buffer: Vec<u8> = Vec::new();
        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        assert!(reader.next_chunk().unwrap().is_none());
    }

    #[test]
    fn test_only_inline_chunks() {
        let chunks: &[&[u8]] = &[b"hello", b"world", b"test"];
        let results = roundtrip_chunks(chunks, &[], false);

        assert_eq!(results.len(), 3);
        assert!(results[0].0); // is_inline
        assert_eq!(results[0].1, b"hello");
        assert!(results[1].0);
        assert_eq!(results[1].1, b"world");
        assert!(results[2].0);
        assert_eq!(results[2].1, b"test");
    }

    #[test]
    fn test_only_external_chunks() {
        let results = roundtrip_chunks(&[], &[0, 5, 42, 100], false);

        assert_eq!(results.len(), 4);
        assert!(!results[0].0); // is_external
        assert_eq!(results[0].2, 0);
        assert!(!results[1].0);
        assert_eq!(results[1].2, 5);
        assert!(!results[2].0);
        assert_eq!(results[2].2, 42);
        assert!(!results[3].0);
        assert_eq!(results[3].2, 100);
    }

    #[test]
    fn test_mixed_inline_external() {
        let inline: &[&[u8]] = &[b"header", b"middle", b"footer"];
        let external: &[u32] = &[0, 1, 2];
        let results = roundtrip_chunks(inline, external, true);

        // Interleaved: inline0, ext0, inline1, ext1, inline2, ext2
        assert_eq!(results.len(), 6);

        assert!(results[0].0);
        assert_eq!(results[0].1, b"header");

        assert!(!results[1].0);
        assert_eq!(results[1].2, 0);

        assert!(results[2].0);
        assert_eq!(results[2].1, b"middle");

        assert!(!results[3].0);
        assert_eq!(results[3].2, 1);

        assert!(results[4].0);
        assert_eq!(results[4].1, b"footer");

        assert!(!results[5].0);
        assert_eq!(results[5].2, 2);
    }

    #[test]
    fn test_large_inline_chunk() {
        // Test with a large chunk to verify i64 handles sizes correctly
        let large_data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

        let mut buffer = Vec::new();
        {
            let mut writer = SplitfdstreamWriter::new(&mut buffer);
            writer.write_inline(&large_data).unwrap();
            writer.finish().unwrap();
        }

        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        let chunk = reader.next_chunk().unwrap().unwrap();

        match chunk {
            Chunk::Inline(data) => {
                assert_eq!(data.len(), 100_000);
                assert_eq!(data, large_data.as_slice());
            }
            Chunk::External(_) => panic!("Expected inline chunk"),
        }

        assert!(reader.next_chunk().unwrap().is_none());
    }

    #[test]
    fn test_empty_inline_chunk_is_skipped() {
        // Empty inline writes should be no-ops
        let mut buffer = Vec::new();
        {
            let mut writer = SplitfdstreamWriter::new(&mut buffer);
            writer.write_inline(b"").unwrap();
            writer.write_inline(b"actual").unwrap();
            writer.write_inline(b"").unwrap();
            writer.finish().unwrap();
        }

        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        let chunk = reader.next_chunk().unwrap().unwrap();
        assert_eq!(chunk, Chunk::Inline(b"actual"));
        assert!(reader.next_chunk().unwrap().is_none());
    }

    #[test]
    fn test_boundary_sizes() {
        // Test various boundary sizes
        let sizes = [
            1, 7, 8, 9, 255, 256, 257, 1023, 1024, 1025, 4095, 4096, 4097,
        ];

        for &size in &sizes {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

            let mut buffer = Vec::new();
            {
                let mut writer = SplitfdstreamWriter::new(&mut buffer);
                writer.write_inline(&data).unwrap();
                writer.finish().unwrap();
            }

            // Verify buffer structure: 8-byte prefix + data
            assert_eq!(buffer.len(), 8 + size);

            // Verify prefix is correct negative value
            let prefix = i64::from_le_bytes(buffer[..8].try_into().unwrap());
            assert_eq!(prefix, -(size as i64));

            // Read back and verify
            let mut reader = SplitfdstreamReader::new(buffer.as_slice());
            let chunk = reader.next_chunk().unwrap().unwrap();
            match chunk {
                Chunk::Inline(read_data) => {
                    assert_eq!(read_data.len(), size);
                    assert_eq!(read_data, data.as_slice());
                }
                Chunk::External(_) => panic!("Expected inline"),
            }
        }
    }

    #[test]
    fn test_external_fd_index_zero() {
        // fd_index 0 means fd[1], test this boundary
        let mut buffer = Vec::new();
        {
            let mut writer = SplitfdstreamWriter::new(&mut buffer);
            writer.write_external(0).unwrap();
            writer.finish().unwrap();
        }

        // Should be exactly 8 bytes (the prefix)
        assert_eq!(buffer.len(), 8);

        // Prefix should be 0
        let prefix = i64::from_le_bytes(buffer[..8].try_into().unwrap());
        assert_eq!(prefix, 0);

        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        let chunk = reader.next_chunk().unwrap().unwrap();
        assert_eq!(chunk, Chunk::External(0));
    }

    #[test]
    fn test_large_fd_index() {
        // Test with maximum u32 fd index
        let mut buffer = Vec::new();
        {
            let mut writer = SplitfdstreamWriter::new(&mut buffer);
            writer.write_external(u32::MAX).unwrap();
            writer.finish().unwrap();
        }

        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        let chunk = reader.next_chunk().unwrap().unwrap();
        assert_eq!(chunk, Chunk::External(u32::MAX));
    }

    #[test]
    fn test_single_byte_inline() {
        let results = roundtrip_chunks(&[b"x"], &[], false);
        assert_eq!(results.len(), 1);
        assert!(results[0].0);
        assert_eq!(results[0].1, b"x");
    }

    #[test]
    fn test_writer_finish_returns_writer() {
        let mut buffer = Vec::new();
        let writer = SplitfdstreamWriter::new(&mut buffer);
        let returned = writer.finish().unwrap();

        // Verify we got the writer back (can write to it)
        returned.len(); // Just verify it's accessible
    }

    #[test]
    fn test_chunk_equality() {
        assert_eq!(Chunk::Inline(b"test"), Chunk::Inline(b"test"));
        assert_ne!(Chunk::Inline(b"test"), Chunk::Inline(b"other"));
        assert_eq!(Chunk::External(5), Chunk::External(5));
        assert_ne!(Chunk::External(5), Chunk::External(6));
        assert_ne!(Chunk::Inline(b"test"), Chunk::External(0));
    }

    #[test]
    fn test_many_small_chunks() {
        // Stress test with many small chunks
        let chunks: Vec<Vec<u8>> = (0..1000).map(|i| vec![i as u8; (i % 10) + 1]).collect();
        let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();

        let mut buffer = Vec::new();
        {
            let mut writer = SplitfdstreamWriter::new(&mut buffer);
            for chunk in &chunk_refs {
                writer.write_inline(chunk).unwrap();
            }
            writer.finish().unwrap();
        }

        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        let mut count = 0;
        while let Some(chunk) = reader.next_chunk().unwrap() {
            match chunk {
                Chunk::Inline(data) => {
                    assert_eq!(data, chunk_refs[count]);
                    count += 1;
                }
                Chunk::External(_) => panic!("Unexpected external"),
            }
        }
        assert_eq!(count, 1000);
    }

    #[test]
    fn test_alternating_inline_external() {
        let mut buffer = Vec::new();
        {
            let mut writer = SplitfdstreamWriter::new(&mut buffer);
            for i in 0..50 {
                writer.write_inline(&[i as u8]).unwrap();
                writer.write_external(i as u32).unwrap();
            }
            writer.finish().unwrap();
        }

        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        let mut inline_count = 0;
        let mut external_count = 0;

        while let Some(chunk) = reader.next_chunk().unwrap() {
            match chunk {
                Chunk::Inline(data) => {
                    assert_eq!(data.len(), 1);
                    assert_eq!(data[0], inline_count as u8);
                    inline_count += 1;
                }
                Chunk::External(idx) => {
                    assert_eq!(idx, external_count as u32);
                    external_count += 1;
                }
            }
        }

        assert_eq!(inline_count, 50);
        assert_eq!(external_count, 50);
    }

    #[test]
    fn test_truncated_prefix_returns_none() {
        // Partial prefix (less than 8 bytes) at end of stream
        let buffer = vec![0x01, 0x02, 0x03]; // Only 3 bytes

        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        // Should return None (EOF) since we can't read a complete prefix
        assert!(reader.next_chunk().unwrap().is_none());
    }

    #[test]
    fn test_truncated_data_is_error() {
        // Valid prefix saying 100 bytes, but only 10 bytes of data
        let mut buffer = Vec::new();
        let prefix: i64 = -100; // Inline, 100 bytes
        buffer.extend_from_slice(&prefix.to_le_bytes());
        buffer.extend_from_slice(&[0u8; 10]); // Only 10 bytes

        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        let result = reader.next_chunk();
        assert!(result.is_err());
    }

    #[test]
    fn test_inline_chunk_size_limit() {
        // Attempt to read a chunk that exceeds MAX_INLINE_CHUNK_SIZE
        let mut buffer = Vec::new();
        // Request 512 MB (exceeds 256 MB limit)
        let prefix: i64 = -(512 * 1024 * 1024);
        buffer.extend_from_slice(&prefix.to_le_bytes());

        let mut reader = SplitfdstreamReader::new(buffer.as_slice());
        let result = reader.next_chunk();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds maximum"));
    }

    mod reconstruct {
        use super::*;
        use std::io::Cursor;
        use tempfile::NamedTempFile;

        #[test]
        fn test_reconstruct_inline_only() {
            // Create a splitfdstream with only inline data
            let mut stream_buf = Vec::new();
            {
                let mut writer = SplitfdstreamWriter::new(&mut stream_buf);
                writer.write_inline(b"Hello, ").unwrap();
                writer.write_inline(b"world!").unwrap();
                writer.finish().unwrap();
            }

            let mut output = Vec::new();
            let fds: &[std::fs::File] = &[];
            let bytes = reconstruct_tar(stream_buf.as_slice(), fds, &mut output).unwrap();

            assert_eq!(output, b"Hello, world!");
            assert_eq!(bytes, 13);
        }

        #[test]
        fn test_reconstruct_empty_stream() {
            let stream_buf: Vec<u8> = Vec::new();
            let mut output = Vec::new();
            let fds: &[std::fs::File] = &[];
            let bytes = reconstruct_tar(stream_buf.as_slice(), fds, &mut output).unwrap();

            assert!(output.is_empty());
            assert_eq!(bytes, 0);
        }

        #[test]
        fn test_reconstruct_with_external_fds() {
            // Create temp files with known content
            let mut file0 = NamedTempFile::new().unwrap();
            let mut file1 = NamedTempFile::new().unwrap();

            use std::io::Write;
            file0.write_all(b"EXTERNAL0").unwrap();
            file1.write_all(b"EXTERNAL1").unwrap();

            // Create splitfdstream that references these files
            let mut stream_buf = Vec::new();
            {
                let mut writer = SplitfdstreamWriter::new(&mut stream_buf);
                writer.write_inline(b"[start]").unwrap();
                writer.write_external(0).unwrap(); // Reference first fd
                writer.write_inline(b"[mid]").unwrap();
                writer.write_external(1).unwrap(); // Reference second fd
                writer.write_inline(b"[end]").unwrap();
                writer.finish().unwrap();
            }

            // Open files for reading
            let f0 = std::fs::File::open(file0.path()).unwrap();
            let f1 = std::fs::File::open(file1.path()).unwrap();
            let fds = [f0, f1];

            let mut output = Vec::new();
            let bytes = reconstruct_tar(stream_buf.as_slice(), &fds, &mut output).unwrap();

            assert_eq!(output, b"[start]EXTERNAL0[mid]EXTERNAL1[end]");
            assert_eq!(bytes, output.len() as u64);
        }

        #[test]
        fn test_reconstruct_external_fd_out_of_bounds() {
            // Create splitfdstream referencing fd index 5, but only provide 2 fds
            let mut stream_buf = Vec::new();
            {
                let mut writer = SplitfdstreamWriter::new(&mut stream_buf);
                writer.write_external(5).unwrap(); // Out of bounds
                writer.finish().unwrap();
            }

            let file = NamedTempFile::new().unwrap();
            let f = std::fs::File::open(file.path()).unwrap();
            let fds = [f];

            let mut output = Vec::new();
            let result = reconstruct_tar(stream_buf.as_slice(), &fds, &mut output);

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
            assert!(err.to_string().contains("fd index 5"));
        }

        #[test]
        fn test_reconstruct_large_external_file() {
            // Create a larger external file to test efficient copying
            let mut file = NamedTempFile::new().unwrap();
            let large_data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

            use std::io::Write;
            file.write_all(&large_data).unwrap();

            let mut stream_buf = Vec::new();
            {
                let mut writer = SplitfdstreamWriter::new(&mut stream_buf);
                writer.write_inline(b"header").unwrap();
                writer.write_external(0).unwrap();
                writer.write_inline(b"footer").unwrap();
                writer.finish().unwrap();
            }

            let f = std::fs::File::open(file.path()).unwrap();
            let fds = [f];

            let mut output = Vec::new();
            let bytes = reconstruct_tar(stream_buf.as_slice(), &fds, &mut output).unwrap();

            // Verify header + large data + footer
            assert_eq!(&output[..6], b"header");
            assert_eq!(&output[6..100_006], large_data.as_slice());
            assert_eq!(&output[100_006..], b"footer");
            assert_eq!(bytes, 6 + 100_000 + 6);
        }

        #[test]
        fn test_reconstruct_same_fd_multiple_times() {
            // Test that the same fd can be referenced multiple times
            let mut file = NamedTempFile::new().unwrap();

            use std::io::Write;
            file.write_all(b"REPEATED").unwrap();

            let mut stream_buf = Vec::new();
            {
                let mut writer = SplitfdstreamWriter::new(&mut stream_buf);
                writer.write_external(0).unwrap();
                writer.write_inline(b"-").unwrap();
                writer.write_external(0).unwrap();
                writer.write_inline(b"-").unwrap();
                writer.write_external(0).unwrap();
                writer.finish().unwrap();
            }

            let f = std::fs::File::open(file.path()).unwrap();
            let fds = [f];

            let mut output = Vec::new();
            let bytes = reconstruct_tar(stream_buf.as_slice(), &fds, &mut output).unwrap();

            // Each reference opens a new file handle via /proc, so each reads from start
            assert_eq!(output, b"REPEATED-REPEATED-REPEATED");
            assert_eq!(bytes, 26);
        }

        #[test]
        fn test_reconstruct_seekable_rewinds_fds() {
            // Create temp files
            let mut file0 = NamedTempFile::new().unwrap();

            use std::io::Write;
            file0.write_all(b"CONTENT").unwrap();

            let mut stream_buf = Vec::new();
            {
                let mut writer = SplitfdstreamWriter::new(&mut stream_buf);
                writer.write_external(0).unwrap();
                writer.write_inline(b"|").unwrap();
                writer.write_external(0).unwrap();
                writer.finish().unwrap();
            }

            // Open file and seek to end (simulating previous read)
            let mut f = std::fs::File::open(file0.path()).unwrap();
            use std::io::Seek;
            f.seek(std::io::SeekFrom::End(0)).unwrap();

            let fds = [f];
            let mut output = Vec::new();
            let bytes = reconstruct_tar_seekable(stream_buf.as_slice(), &fds, &mut output).unwrap();

            // seekable version should rewind before each read
            assert_eq!(output, b"CONTENT|CONTENT");
            assert_eq!(bytes, 15);
        }

        #[test]
        fn test_reconstruct_with_memfd() {
            // Demonstrate that any AsFd impl works with memfd
            use std::os::fd::OwnedFd;

            // Create memfd for in-memory file descriptor
            let fd: OwnedFd =
                rustix::fs::memfd_create(c"test", rustix::fs::MemfdFlags::CLOEXEC).unwrap();

            // Write data to the memfd
            use std::io::Write;
            let mut file = std::fs::File::from(fd);
            file.write_all(b"MEMFD_DATA").unwrap();

            // Seek back for reading
            use std::io::Seek;
            file.seek(std::io::SeekFrom::Start(0)).unwrap();

            let mut stream_buf = Vec::new();
            {
                let mut writer = SplitfdstreamWriter::new(&mut stream_buf);
                writer.write_inline(b"pre-").unwrap();
                writer.write_external(0).unwrap();
                writer.write_inline(b"-post").unwrap();
                writer.finish().unwrap();
            }

            let fds = [file];
            let mut output = Vec::new();
            let bytes = reconstruct_tar(stream_buf.as_slice(), &fds, &mut output).unwrap();

            assert_eq!(output, b"pre-MEMFD_DATA-post");
            assert_eq!(bytes, 19);
        }

        #[test]
        fn test_into_inner() {
            let data = vec![1, 2, 3, 4];
            let cursor = Cursor::new(data.clone());
            let reader = SplitfdstreamReader::new(cursor);
            let inner = reader.into_inner();
            assert_eq!(inner.into_inner(), data);
        }
    }

    mod extraction {
        use super::*;
        use cap_std::ambient_authority;
        use tempfile::TempDir;

        /// Create a valid tar header for testing.
        fn create_tar_header(name: &str, size: u64, typeflag: u8, mode: u32) -> Vec<u8> {
            let mut header = [0u8; 512];

            // name (0-99)
            let name_bytes = name.as_bytes();
            let name_len = name_bytes.len().min(100);
            header[..name_len].copy_from_slice(&name_bytes[..name_len]);

            // mode (100-107) - octal
            let mode_str = format!("{:07o}\0", mode);
            header[100..108].copy_from_slice(mode_str.as_bytes());

            // uid (108-115) - octal
            header[108..116].copy_from_slice(b"0001750\0");

            // gid (116-123) - octal
            header[116..124].copy_from_slice(b"0001750\0");

            // size (124-135) - octal
            let size_str = format!("{:011o}\0", size);
            header[124..136].copy_from_slice(size_str.as_bytes());

            // mtime (136-147) - octal
            header[136..148].copy_from_slice(b"14722350757\0");

            // typeflag (156)
            header[156] = typeflag;

            // magic (257-262)
            header[257..263].copy_from_slice(b"ustar\0");

            // version (263-264)
            header[263..265].copy_from_slice(b"00");

            // Compute checksum
            let checksum: u32 = header[..148]
                .iter()
                .chain(std::iter::repeat_n(&b' ', 8))
                .chain(header[156..512].iter())
                .map(|&b| b as u32)
                .sum();

            // Write checksum (148-155)
            let checksum_str = format!("{:06o}\0 ", checksum);
            header[148..156].copy_from_slice(checksum_str.as_bytes());

            header.to_vec()
        }

        /// Create padding to 512-byte boundary.
        #[allow(dead_code)]
        fn create_padding(size: u64) -> Vec<u8> {
            let remainder = size % 512;
            if remainder == 0 {
                Vec::new()
            } else {
                vec![0u8; (512 - remainder) as usize]
            }
        }

        #[test]
        fn test_extract_empty_stream() {
            let tmpdir = TempDir::new().unwrap();
            let dest = Dir::open_ambient_dir(tmpdir.path(), ambient_authority()).unwrap();

            let stream: Vec<u8> = Vec::new();
            let fds: &[std::fs::File] = &[];

            let stats = extract_to_dir(stream.as_slice(), fds, &dest, true).unwrap();

            assert_eq!(stats.files_extracted, 0);
            assert_eq!(stats.directories_created, 0);
        }

        #[test]
        fn test_extract_directory() {
            let tmpdir = TempDir::new().unwrap();
            let dest = Dir::open_ambient_dir(tmpdir.path(), ambient_authority()).unwrap();

            // Create a splitfdstream with a directory entry
            let header = create_tar_header("testdir", 0, b'5', 0o755);

            let mut stream_buf = Vec::new();
            let mut writer = SplitfdstreamWriter::new(&mut stream_buf);
            writer.write_inline(&header).unwrap();
            writer.finish().unwrap();

            let fds: &[std::fs::File] = &[];
            let stats = extract_to_dir(stream_buf.as_slice(), fds, &dest, true).unwrap();

            assert_eq!(stats.directories_created, 1);
            assert!(dest.is_dir("testdir"));
        }

        #[test]
        fn test_extract_empty_file() {
            let tmpdir = TempDir::new().unwrap();
            let dest = Dir::open_ambient_dir(tmpdir.path(), ambient_authority()).unwrap();

            // Create a splitfdstream with an empty regular file
            let header = create_tar_header("empty.txt", 0, b'0', 0o644);

            let mut stream_buf = Vec::new();
            let mut writer = SplitfdstreamWriter::new(&mut stream_buf);
            writer.write_inline(&header).unwrap();
            writer.finish().unwrap();

            let fds: &[std::fs::File] = &[];
            let stats = extract_to_dir(stream_buf.as_slice(), fds, &dest, true).unwrap();

            assert_eq!(stats.files_extracted, 1);
            assert!(dest.is_file("empty.txt"));
        }

        #[test]
        fn test_extract_symlink() {
            let tmpdir = TempDir::new().unwrap();
            let dest = Dir::open_ambient_dir(tmpdir.path(), ambient_authority()).unwrap();

            // Create a symlink tar header
            let mut header = [0u8; 512];
            header[..8].copy_from_slice(b"link.txt");
            header[100..108].copy_from_slice(b"0000777\0");
            header[108..116].copy_from_slice(b"0001750\0");
            header[116..124].copy_from_slice(b"0001750\0");
            header[124..136].copy_from_slice(b"00000000000\0");
            header[136..148].copy_from_slice(b"14722350757\0");
            header[156] = b'2'; // symlink
            // linkname (157-256)
            header[157..167].copy_from_slice(b"target.txt");
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");

            // Compute checksum
            let checksum: u32 = header[..148]
                .iter()
                .chain(std::iter::repeat_n(&b' ', 8))
                .chain(header[156..512].iter())
                .map(|&b| b as u32)
                .sum();
            let checksum_str = format!("{:06o}\0 ", checksum);
            header[148..156].copy_from_slice(checksum_str.as_bytes());

            let mut stream_buf = Vec::new();
            let mut writer = SplitfdstreamWriter::new(&mut stream_buf);
            writer.write_inline(&header).unwrap();
            writer.finish().unwrap();

            let fds: &[std::fs::File] = &[];
            let stats = extract_to_dir(stream_buf.as_slice(), fds, &dest, true).unwrap();

            assert_eq!(stats.symlinks_created, 1);
            assert!(dest.symlink_metadata("link.txt").unwrap().is_symlink());
            assert_eq!(
                dest.read_link("link.txt").unwrap().to_str().unwrap(),
                "target.txt"
            );
        }

        #[test]
        fn test_extract_nested_directory() {
            let tmpdir = TempDir::new().unwrap();
            let dest = Dir::open_ambient_dir(tmpdir.path(), ambient_authority()).unwrap();

            // Create tar headers for nested structure
            let header1 = create_tar_header("parent", 0, b'5', 0o755);
            let header2 = create_tar_header("parent/child", 0, b'5', 0o755);
            let header3 = create_tar_header("parent/child/file.txt", 0, b'0', 0o644);

            let mut stream_buf = Vec::new();
            let mut writer = SplitfdstreamWriter::new(&mut stream_buf);
            writer.write_inline(&header1).unwrap();
            writer.write_inline(&header2).unwrap();
            writer.write_inline(&header3).unwrap();
            writer.finish().unwrap();

            let fds: &[std::fs::File] = &[];
            let stats = extract_to_dir(stream_buf.as_slice(), fds, &dest, true).unwrap();

            assert_eq!(stats.directories_created, 2);
            assert_eq!(stats.files_extracted, 1);
            assert!(dest.is_dir("parent"));
            assert!(dest.is_dir("parent/child"));
            assert!(dest.is_file("parent/child/file.txt"));
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
            assert_eq!(stats.bytes_inline, 0);
        }
    }
}
