use std::io::{self, Read};
use std::os::unix::fs::FileExt;

/// A `Read` adapter that reads from a file using positional read (pread/read_at).
///
/// This allows reading from a borrowed file without affecting its file position,
/// and without needing to reopen the fd. Each `ReadAtReader` tracks its own
/// offset independently.
#[derive(Debug)]
pub(crate) struct ReadAtReader<'a> {
    file: &'a std::fs::File,
    offset: u64,
}

impl<'a> ReadAtReader<'a> {
    /// Create a new positional reader for the given file, starting at offset 0.
    pub(crate) fn new(file: &'a std::fs::File) -> Self {
        Self { file, offset: 0 }
    }
}

impl Read for ReadAtReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.file.read_at(buf, self.offset)?;
        self.offset += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_complete_file() {
        let mut file = NamedTempFile::new().unwrap();
        let content = b"Hello, world!";
        file.write_all(content).unwrap();

        let f = std::fs::File::open(file.path()).unwrap();
        let mut reader = ReadAtReader::new(&f);

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, content);
    }

    #[test]
    fn test_read_in_multiple_small_chunks() {
        let mut file = NamedTempFile::new().unwrap();
        let content = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        file.write_all(content).unwrap();

        let f = std::fs::File::open(file.path()).unwrap();
        let mut reader = ReadAtReader::new(&f);

        // Read in small chunks of 5 bytes
        let mut result = Vec::new();
        let mut buf = [0u8; 5];

        loop {
            let n = reader.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            result.extend_from_slice(&buf[..n]);
        }

        assert_eq!(result, content);
    }

    #[test]
    fn test_read_past_eof_returns_zero() {
        let mut file = NamedTempFile::new().unwrap();
        let content = b"Short";
        file.write_all(content).unwrap();

        let f = std::fs::File::open(file.path()).unwrap();
        let mut reader = ReadAtReader::new(&f);

        // Read all content first
        let mut buf = [0u8; 100];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], content);

        // Subsequent reads should return 0
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 0);

        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }
}
