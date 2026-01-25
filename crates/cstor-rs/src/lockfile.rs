//! Lock file implementation compatible with containers/storage.
//!
//! This module provides file-based locking that is wire-compatible with
//! the Go implementation in containers/storage. It uses POSIX fcntl locks
//! for cross-process synchronization and in-process RwLock for thread safety.
//!
//! # LastWrite Token
//!
//! The lock file stores a 64-byte "last write" token that allows callers to
//! detect if any writer has modified shared state since they last checked.
//! The format is:
//! - bytes 0-7: Unix timestamp (nanoseconds, little-endian)
//! - bytes 8-15: Counter (little-endian)
//! - bytes 16-19: Process ID (little-endian)
//! - bytes 20-63: Random bytes
//!
//! # Example
//!
//! ```no_run
//! use cstor_rs::lockfile::LockFile;
//!
//! let lockfile = LockFile::open("/var/lib/containers/storage/overlay.lock", false)?;
//!
//! // Acquire exclusive lock
//! let guard = lockfile.lock();
//!
//! // Record that we've written something
//! let token = lockfile.record_write()?;
//!
//! // Lock is released when guard is dropped
//! drop(guard);
//!
//! // Later, check if anything has changed
//! let changed = lockfile.modified_since(&token)?;
//! # Ok::<(), cstor_rs::lockfile::LockError>(())
//! ```

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use rustix::fs::{FlockOperation, fcntl_lock};

/// Size of the LastWrite token in bytes.
const LAST_WRITE_SIZE: usize = 64;

/// Error types for lock file operations.
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    /// I/O error during lock file operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Lock file operation failed.
    #[error("lock operation failed: {0}")]
    LockFailed(#[from] rustix::io::Errno),

    /// Lock is read-only but write operation was attempted.
    #[error("cannot write to read-only lock file")]
    ReadOnly,

    /// Would block on non-blocking lock attempt.
    #[error("lock would block")]
    WouldBlock,

    /// Invalid LastWrite data in lock file.
    #[error("invalid last write data: {0}")]
    InvalidData(String),
}

/// Result type for lock file operations.
pub type Result<T> = std::result::Result<T, LockError>;

/// A 64-byte token representing the last write to the lock file.
///
/// This token can be used to detect if any writer has modified shared state
/// since the token was obtained. The format is compatible with the Go
/// implementation in containers/storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastWrite {
    /// Unix timestamp in nanoseconds.
    timestamp_nanos: u64,
    /// Monotonic counter.
    counter: u64,
    /// Process ID of the writer.
    pid: u32,
    /// Random bytes for uniqueness.
    random: [u8; 44],
}

impl LastWrite {
    /// Create a new LastWrite token with current time and random data.
    fn new(counter: u64) -> Self {
        let timestamp_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let pid = std::process::id();

        // Generate random bytes using /dev/urandom
        let mut random = [0u8; 44];
        if let Ok(mut f) = File::open("/dev/urandom") {
            let _ = f.read_exact(&mut random);
        } else {
            // Fallback: use time-based pseudo-random
            let seed = timestamp_nanos;
            for (i, byte) in random.iter_mut().enumerate() {
                *byte = ((seed >> (i % 8)) ^ (seed >> ((i + 3) % 8))) as u8;
            }
        }

        Self {
            timestamp_nanos,
            counter,
            pid,
            random,
        }
    }

    /// Serialize the LastWrite token to a 64-byte array.
    fn to_bytes(&self) -> [u8; LAST_WRITE_SIZE] {
        let mut buf = [0u8; LAST_WRITE_SIZE];

        buf[0..8].copy_from_slice(&self.timestamp_nanos.to_le_bytes());
        buf[8..16].copy_from_slice(&self.counter.to_le_bytes());
        buf[16..20].copy_from_slice(&self.pid.to_le_bytes());
        buf[20..64].copy_from_slice(&self.random);

        buf
    }

    /// Deserialize a LastWrite token from a 64-byte array.
    fn from_bytes(buf: &[u8; LAST_WRITE_SIZE]) -> Self {
        let timestamp_nanos = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let counter = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let pid = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        let mut random = [0u8; 44];
        random.copy_from_slice(&buf[20..64]);

        Self {
            timestamp_nanos,
            counter,
            pid,
            random,
        }
    }

    /// Check if this token represents an empty/uninitialized state.
    pub fn is_empty(&self) -> bool {
        self.timestamp_nanos == 0 && self.counter == 0 && self.pid == 0
    }
}

impl Default for LastWrite {
    fn default() -> Self {
        Self {
            timestamp_nanos: 0,
            counter: 0,
            pid: 0,
            random: [0u8; 44],
        }
    }
}

/// A file-based lock compatible with containers/storage.
///
/// This provides both cross-process locking (via fcntl) and in-process
/// thread synchronization (via RwLock). The lock file also stores a
/// LastWrite token that can be used to detect modifications.
#[derive(Debug)]
pub struct LockFile {
    /// Path to the lock file.
    path: PathBuf,
    /// File descriptor for the lock file.
    fd: OwnedFd,
    /// Whether the lock file was opened read-only.
    read_only: bool,
    /// In-process synchronization lock.
    in_process_lock: RwLock<()>,
    /// Cached last write token and counter.
    state: Mutex<LockState>,
}

/// Internal state protected by mutex.
#[derive(Debug, Default)]
struct LockState {
    /// The last write token we've seen.
    last_write: LastWrite,
    /// Counter for generating unique tokens.
    counter: u64,
}

/// RAII guard for an exclusive (write) lock.
///
/// The lock is released when this guard is dropped.
#[derive(Debug)]
pub struct LockGuard<'a> {
    lockfile: &'a LockFile,
    /// Hold the in-process write lock guard.
    _guard: RwLockWriteGuard<'a, ()>,
}

impl Drop for LockGuard<'_> {
    fn drop(&mut self) {
        // Release the fcntl lock
        let _ = fcntl_lock(self.lockfile.fd.as_fd(), FlockOperation::Unlock);
    }
}

/// RAII guard for a shared (read) lock.
///
/// The lock is released when this guard is dropped.
#[derive(Debug)]
pub struct RLockGuard<'a> {
    lockfile: &'a LockFile,
    /// Hold the in-process read lock guard.
    _guard: RwLockReadGuard<'a, ()>,
}

impl Drop for RLockGuard<'_> {
    fn drop(&mut self) {
        // Release the fcntl lock
        let _ = fcntl_lock(self.lockfile.fd.as_fd(), FlockOperation::Unlock);
    }
}

impl LockFile {
    /// Open or create a lock file at the specified path.
    ///
    /// If `read_only` is true, the file is opened in read-only mode and
    /// write operations will fail with `LockError::ReadOnly`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or created.
    pub fn open<P: AsRef<Path>>(path: P, read_only: bool) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        let file = if read_only {
            OpenOptions::new().read(true).open(&path)?
        } else {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)?
        };

        let fd: OwnedFd = file.into();

        Ok(Self {
            path,
            fd,
            read_only,
            in_process_lock: RwLock::new(()),
            state: Mutex::new(LockState::default()),
        })
    }

    /// Get the path to the lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Check if the lock file was opened read-only.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Acquire an exclusive (write) lock, blocking until available.
    ///
    /// Returns a guard that releases the lock when dropped.
    pub fn lock(&self) -> LockGuard<'_> {
        // First acquire the in-process lock
        let guard = self
            .in_process_lock
            .write()
            .expect("in-process lock poisoned");

        // Then acquire the fcntl lock (blocking)
        fcntl_lock(self.fd.as_fd(), FlockOperation::LockExclusive)
            .expect("fcntl_lock failed unexpectedly");

        LockGuard {
            lockfile: self,
            _guard: guard,
        }
    }

    /// Acquire a shared (read) lock, blocking until available.
    ///
    /// Returns a guard that releases the lock when dropped.
    pub fn rlock(&self) -> RLockGuard<'_> {
        // First acquire the in-process lock
        let guard = self
            .in_process_lock
            .read()
            .expect("in-process lock poisoned");

        // Then acquire the fcntl lock (blocking)
        fcntl_lock(self.fd.as_fd(), FlockOperation::LockShared)
            .expect("fcntl_lock failed unexpectedly");

        RLockGuard {
            lockfile: self,
            _guard: guard,
        }
    }

    /// Try to acquire an exclusive (write) lock without blocking.
    ///
    /// Returns `Err(LockError::WouldBlock)` if the lock is not available.
    pub fn try_lock(&self) -> Result<LockGuard<'_>> {
        // Try to acquire the in-process lock
        let guard = self
            .in_process_lock
            .try_write()
            .map_err(|_| LockError::WouldBlock)?;

        // Try to acquire the fcntl lock (non-blocking)
        match fcntl_lock(self.fd.as_fd(), FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(LockGuard {
                lockfile: self,
                _guard: guard,
            }),
            Err(rustix::io::Errno::AGAIN) => Err(LockError::WouldBlock),
            Err(e) => Err(LockError::LockFailed(e)),
        }
    }

    /// Try to acquire a shared (read) lock without blocking.
    ///
    /// Returns `Err(LockError::WouldBlock)` if the lock is not available.
    pub fn try_rlock(&self) -> Result<RLockGuard<'_>> {
        // Try to acquire the in-process lock
        let guard = self
            .in_process_lock
            .try_read()
            .map_err(|_| LockError::WouldBlock)?;

        // Try to acquire the fcntl lock (non-blocking)
        match fcntl_lock(self.fd.as_fd(), FlockOperation::NonBlockingLockShared) {
            Ok(()) => Ok(RLockGuard {
                lockfile: self,
                _guard: guard,
            }),
            Err(rustix::io::Errno::AGAIN) => Err(LockError::WouldBlock),
            Err(e) => Err(LockError::LockFailed(e)),
        }
    }

    /// Record a write operation by updating the LastWrite token.
    ///
    /// This should be called while holding an exclusive lock. It updates
    /// the lock file with a new token that can be used to detect changes.
    ///
    /// # Errors
    ///
    /// Returns `LockError::ReadOnly` if the file was opened read-only.
    pub fn record_write(&self) -> Result<LastWrite> {
        if self.read_only {
            return Err(LockError::ReadOnly);
        }

        let mut state = self.state.lock().expect("state lock poisoned");
        state.counter += 1;

        let new_token = LastWrite::new(state.counter);
        let bytes = new_token.to_bytes();

        // Write to the file
        // SAFETY: We're using the fd through File for convenience.
        // This is safe because we own the fd and are under lock.
        let mut file = self.as_file();
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        file.sync_data()?;

        state.last_write = new_token.clone();
        Ok(new_token)
    }

    /// Read the current LastWrite token from the lock file.
    ///
    /// This reads the token directly from the file, not from cache.
    pub fn get_last_write(&self) -> Result<LastWrite> {
        let mut file = self.as_file();
        file.seek(SeekFrom::Start(0))?;

        let mut buf = [0u8; LAST_WRITE_SIZE];
        match file.read_exact(&mut buf) {
            Ok(()) => Ok(LastWrite::from_bytes(&buf)),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // File is empty or too small - return empty token
                Ok(LastWrite::default())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Check if the lock file has been modified since the given token.
    ///
    /// This reads the current token from the file and compares it to
    /// the provided token. Returns `true` if they differ.
    pub fn modified_since(&self, prev: &LastWrite) -> Result<bool> {
        let current = self.get_last_write()?;
        Ok(current != *prev)
    }

    /// Helper to get a File reference for I/O operations.
    ///
    /// This borrows the fd without taking ownership.
    fn as_file(&self) -> File {
        // SAFETY: We're duplicating the fd to create a File for I/O.
        // The original fd remains valid and owned by self.
        use std::os::fd::BorrowedFd;
        let borrowed: BorrowedFd<'_> = self.fd.as_fd();

        // Use dup to create a new fd that File can own
        let duped = rustix::io::fcntl_dupfd_cloexec(borrowed, 0).expect("fcntl_dupfd failed");
        File::from(duped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_lastwrite_serialization_roundtrip() {
        let token = LastWrite::new(42);
        let bytes = token.to_bytes();
        let parsed = LastWrite::from_bytes(&bytes);

        assert_eq!(token.timestamp_nanos, parsed.timestamp_nanos);
        assert_eq!(token.counter, parsed.counter);
        assert_eq!(token.pid, parsed.pid);
        assert_eq!(token.random, parsed.random);
    }

    #[test]
    fn test_lastwrite_default_is_empty() {
        let token = LastWrite::default();
        assert!(token.is_empty());
    }

    #[test]
    fn test_lastwrite_new_is_not_empty() {
        let token = LastWrite::new(1);
        assert!(!token.is_empty());
    }

    #[test]
    fn test_basic_lock_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.lock");

        let lockfile = LockFile::open(&path, false).unwrap();

        // Acquire and release exclusive lock
        {
            let _guard = lockfile.lock();
            // Lock is held here
        }
        // Lock is released

        // Should be able to lock again
        {
            let _guard = lockfile.lock();
        }
    }

    #[test]
    fn test_read_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.lock");

        let lockfile = LockFile::open(&path, false).unwrap();

        // Acquire and release shared lock
        {
            let _guard = lockfile.rlock();
        }
    }

    #[test]
    fn test_record_write_and_modified_since() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.lock");

        let lockfile = LockFile::open(&path, false).unwrap();

        // Initially, get_last_write should return empty
        let initial = lockfile.get_last_write().unwrap();
        assert!(initial.is_empty());

        // Record a write
        let _guard = lockfile.lock();
        let token1 = lockfile.record_write().unwrap();
        drop(_guard);

        // Should not be modified since token1
        assert!(!lockfile.modified_since(&token1).unwrap());

        // Record another write
        let _guard = lockfile.lock();
        let token2 = lockfile.record_write().unwrap();
        drop(_guard);

        // Should be modified since token1
        assert!(lockfile.modified_since(&token1).unwrap());

        // Should not be modified since token2
        assert!(!lockfile.modified_since(&token2).unwrap());
    }

    #[test]
    fn test_read_only_cannot_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.lock");

        // Create the file first
        {
            let _lockfile = LockFile::open(&path, false).unwrap();
        }

        // Open read-only
        let lockfile = LockFile::open(&path, true).unwrap();
        assert!(lockfile.is_read_only());

        let _guard = lockfile.rlock();
        let result = lockfile.record_write();
        assert!(matches!(result, Err(LockError::ReadOnly)));
    }

    #[test]
    fn test_try_lock_succeeds_when_available() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.lock");

        let lockfile = LockFile::open(&path, false).unwrap();

        let guard = lockfile.try_lock();
        assert!(guard.is_ok());
    }

    #[test]
    fn test_multiple_readers_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.lock");

        let lockfile = Arc::new(LockFile::open(&path, false).unwrap());
        let lockfile2 = Arc::clone(&lockfile);

        // First reader
        let guard1 = lockfile.rlock();

        // Second reader should succeed (in same process, sharing in_process_lock)
        let handle = thread::spawn(move || {
            let _guard2 = lockfile2.rlock();
            // Both readers hold the lock
        });

        drop(guard1);
        handle.join().unwrap();
    }

    #[test]
    fn test_try_lock_fails_when_held() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.lock");

        let lockfile = LockFile::open(&path, false).unwrap();

        // Hold the exclusive lock
        let _guard = lockfile.lock();

        // Try to acquire should fail
        let result = lockfile.try_lock();
        assert!(matches!(result, Err(LockError::WouldBlock)));
    }

    #[test]
    fn test_lastwrite_different_tokens_not_equal() {
        let token1 = LastWrite::new(1);
        // Small delay to ensure different timestamp
        std::thread::sleep(std::time::Duration::from_millis(1));
        let token2 = LastWrite::new(2);

        assert_ne!(token1, token2);
    }
}
