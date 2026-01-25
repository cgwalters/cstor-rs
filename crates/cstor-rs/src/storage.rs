//! Storage access for container overlay filesystem.
//!
//! This module provides the main [`Storage`] struct for accessing containers-storage
//! overlay driver data. All file access uses cap-std for fd-relative operations,
//! providing security against path traversal attacks and TOCTOU race conditions.
//!
//! # Overview
//!
//! The `Storage` struct is the primary entry point for interacting with container
//! storage. It holds a capability-based directory handle to the storage root and
//! a SQLite database connection for metadata queries.
//!
//! # Storage Structure
//!
//! Container storage on disk follows this layout:
//! ```text
//! /var/lib/containers/storage/
//! ├── db.sql              # SQLite metadata database
//! ├── overlay/            # Layer data
//! │   ├── <layer-id>/     # Individual layer directories
//! │   │   ├── diff/       # Layer file contents
//! │   │   ├── link        # Short link ID (26 chars)
//! │   │   └── lower       # Parent layer references
//! │   └── l/              # Short link directory (symlinks)
//! ├── overlay-layers/     # Tar-split metadata
//! │   └── <layer-id>.tar-split.gz
//! └── overlay-images/     # Image metadata
//!     └── <image-id>/
//!         ├── manifest    # OCI image manifest
//!         └── =<key>      # Base64-encoded metadata files
//! ```
//!
//! # Discovery
//!
//! Storage can be discovered automatically or opened at a specific path:
//!
//! ```no_run
//! use cstor_rs::Storage;
//!
//! // Automatic discovery from default locations
//! let storage = Storage::discover()?;
//!
//! // Or open at specific path
//! let storage = Storage::open("/var/lib/containers/storage")?;
//! # Ok::<(), cstor_rs::StorageError>(())
//! ```
//!
//! # Security Model
//!
//! All file operations are performed via [`cap_std::fs::Dir`] handles, which provide:
//! - Protection against path traversal attacks
//! - Prevention of TOCTOU race conditions
//! - Guarantee that all access stays within the storage directory tree
//!
//! The SQLite database is opened via `/proc/self/fd/{fd}` to ensure we're accessing
//! the exact file descriptor we opened, not a path that could be replaced.

use crate::error::{Result, StorageError};
use crate::lockfile::{LastWrite, LockFile, LockGuard, RLockGuard};
use cap_std::ambient_authority;
use cap_std::fs::Dir;
use rusqlite::Connection;
use rustix::path::DecInt;
use std::env;
use std::path::{Path, PathBuf};

/// Main storage handle providing access to container storage.
///
/// The Storage struct holds:
/// - A `Dir` handle to the storage root for fd-relative file operations
/// - A SQLite database connection for metadata access
/// - Optional lock files for coordinating access with other processes
///
/// All file access is performed relative to the `Dir` handle, ensuring that
/// operations cannot escape the storage directory hierarchy.
///
/// # Read-Only vs Read-Write Mode
///
/// Storage can be opened in read-only mode (the default) or read-write mode:
///
/// ```no_run
/// use cstor_rs::Storage;
///
/// // Read-only access (default)
/// let ro_storage = Storage::open("/var/lib/containers/storage")?;
/// assert!(!ro_storage.is_writable());
///
/// // Read-write access with locking
/// let rw_storage = Storage::open_writable("/var/lib/containers/storage")?;
/// assert!(rw_storage.is_writable());
/// # Ok::<(), cstor_rs::StorageError>(())
/// ```
///
/// When opened in read-write mode, the storage acquires lock files that coordinate
/// access with other processes (including the Go-based containers/storage).
#[derive(Debug)]
pub struct Storage {
    /// Directory handle for the storage root, used for all fd-relative operations.
    root_dir: Dir,

    /// SQLite database connection for metadata queries.
    db: Connection,

    /// Lock file for layer operations (overlay-layers/layers.lock).
    /// Present when opened in read-write mode.
    layers_lock: Option<LockFile>,

    /// Lock file for image operations (overlay-images/images.lock).
    /// Present when opened in read-write mode.
    images_lock: Option<LockFile>,

    /// Whether this storage is in read-only mode.
    read_only: bool,
}

impl Storage {
    /// Open storage at the given root path.
    ///
    /// This validates that the path points to a valid container storage directory
    /// by checking for required subdirectories and the database file.
    ///
    /// # Arguments
    ///
    /// * `root` - Path to the storage root directory
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path does not exist or is not a directory
    /// - Required subdirectories are missing
    /// - The database file is missing or invalid
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::open("/var/lib/containers/storage")?;
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn open<P: AsRef<Path>>(root: P) -> Result<Self> {
        let root_path = root.as_ref();

        // Open the directory handle for fd-relative operations
        let root_dir = Dir::open_ambient_dir(root_path, ambient_authority()).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::RootNotFound(root_path.to_path_buf())
            } else {
                StorageError::Io(e)
            }
        })?;

        // Validate storage structure
        Self::validate_storage(&root_dir)?;

        // Open database via fd-relative path
        let db = Self::open_database(&root_dir)?;

        Ok(Self {
            root_dir,
            db,
            layers_lock: None,
            images_lock: None,
            read_only: true,
        })
    }

    /// Discover storage root from default locations.
    ///
    /// Searches for container storage in the following order:
    /// 1. `$CONTAINERS_STORAGE_ROOT` environment variable
    /// 2. Rootless storage: `$XDG_DATA_HOME/containers/storage` or `~/.local/share/containers/storage`
    /// 3. Root storage: `/var/lib/containers/storage`
    ///
    /// Returns the first valid storage location found.
    ///
    /// # Errors
    ///
    /// Returns an error if no valid storage location is found.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::discover()?;
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn discover() -> Result<Self> {
        let search_paths = Self::default_search_paths();

        for path in search_paths {
            if path.exists() {
                match Self::open(&path) {
                    Ok(storage) => return Ok(storage),
                    Err(_) => continue,
                }
            }
        }

        Err(StorageError::InvalidStorage(
            "No valid storage location found. Searched default locations.".to_string(),
        ))
    }

    /// Open storage at the given root path in read-write mode.
    ///
    /// This opens the storage with write access and creates lock files for
    /// coordinating access with other processes. The lock files follow the
    /// containers/storage convention:
    /// - `overlay-layers/layers.lock` - protects layer operations
    /// - `overlay-images/images.lock` - protects image operations
    ///
    /// # Arguments
    ///
    /// * `root` - Path to the storage root directory
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path does not exist or is not a directory
    /// - Required subdirectories are missing
    /// - The database file is missing or invalid
    /// - Lock files cannot be created or opened
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::open_writable("/var/lib/containers/storage")?;
    /// assert!(storage.is_writable());
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn open_writable<P: AsRef<Path>>(root: P) -> Result<Self> {
        let root_path = root.as_ref();

        // Open the directory handle for fd-relative operations
        let root_dir = Dir::open_ambient_dir(root_path, ambient_authority()).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::RootNotFound(root_path.to_path_buf())
            } else {
                StorageError::Io(e)
            }
        })?;

        // Validate storage structure
        Self::validate_storage(&root_dir)?;

        // Open database via fd-relative path
        let db = Self::open_database(&root_dir)?;

        // Create lock files for layers and images
        let layers_lock_path = root_path.join("overlay-layers/layers.lock");
        let images_lock_path = root_path.join("overlay-images/images.lock");

        let layers_lock = LockFile::open(&layers_lock_path, false)?;
        let images_lock = LockFile::open(&images_lock_path, false)?;

        Ok(Self {
            root_dir,
            db,
            layers_lock: Some(layers_lock),
            images_lock: Some(images_lock),
            read_only: false,
        })
    }

    /// Discover storage root from default locations and open in read-write mode.
    ///
    /// This is the read-write equivalent of [`discover()`](Self::discover).
    ///
    /// # Errors
    ///
    /// Returns an error if no valid storage location is found or if the storage
    /// cannot be opened for writing.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::discover_writable()?;
    /// assert!(storage.is_writable());
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn discover_writable() -> Result<Self> {
        let search_paths = Self::default_search_paths();

        for path in search_paths {
            if path.exists() {
                match Self::open_writable(&path) {
                    Ok(storage) => return Ok(storage),
                    Err(_) => continue,
                }
            }
        }

        Err(StorageError::InvalidStorage(
            "No valid storage location found. Searched default locations.".to_string(),
        ))
    }

    /// Check if this storage is writable.
    ///
    /// Returns `true` if the storage was opened with [`open_writable()`](Self::open_writable)
    /// or [`discover_writable()`](Self::discover_writable), `false` otherwise.
    pub fn is_writable(&self) -> bool {
        !self.read_only
    }

    /// Get the default search paths for storage discovery.
    fn default_search_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // 1. Check CONTAINERS_STORAGE_ROOT environment variable
        if let Ok(root) = env::var("CONTAINERS_STORAGE_ROOT") {
            paths.push(PathBuf::from(root));
        }

        // 2. Check rootless locations
        if let Ok(home) = env::var("HOME") {
            let home_path = PathBuf::from(home);

            // Try XDG_DATA_HOME first
            if let Ok(xdg_data) = env::var("XDG_DATA_HOME") {
                paths.push(PathBuf::from(xdg_data).join("containers/storage"));
            }

            // Fallback to ~/.local/share/containers/storage
            paths.push(home_path.join(".local/share/containers/storage"));
        }

        // 3. Check root location
        paths.push(PathBuf::from("/var/lib/containers/storage"));

        paths
    }

    /// Validate that the directory structure is a valid overlay storage.
    fn validate_storage(root_dir: &Dir) -> Result<()> {
        // Check for required subdirectories
        let required_dirs = ["overlay", "overlay-layers", "overlay-images"];

        for dir_name in &required_dirs {
            match root_dir.try_exists(dir_name) {
                Ok(exists) if !exists => {
                    return Err(StorageError::InvalidStorage(format!(
                        "Missing required directory: {}",
                        dir_name
                    )));
                }
                Err(e) => return Err(StorageError::Io(e)),
                _ => {}
            }
        }

        // Check for database file
        match root_dir.try_exists("db.sql") {
            Ok(exists) if !exists => {
                return Err(StorageError::InvalidStorage(
                    "Missing database file: db.sql".to_string(),
                ));
            }
            Err(e) => return Err(StorageError::Io(e)),
            _ => {}
        }

        Ok(())
    }

    /// Open the SQLite database using fd-relative access.
    ///
    /// This opens the database file relative to the root directory handle
    /// using a verified /proc/self/fd path to ensure we're accessing
    /// the exact file we opened, preventing TOCTOU vulnerabilities.
    fn open_database(root_dir: &Dir) -> Result<Connection> {
        let db_file = root_dir.open("db.sql")?;

        // Get a verified handle to /proc/self/fd using rustix-linux-procfs.
        // This validates that /proc is actually procfs and hasn't been tampered with.
        let proc_self_fd = rustix_linux_procfs::proc_self_fd()
            .map_err(|e| StorageError::Io(std::io::Error::from_raw_os_error(e.raw_os_error())))?;

        // Validate that our fd is accessible via the verified procfs directory
        // by opening it relative to the proc_self_fd handle.
        let fd_name = DecInt::from_fd(&db_file);
        let _verified = rustix::fs::openat(
            &proc_self_fd,
            fd_name.as_c_str(),
            rustix::fs::OFlags::RDONLY,
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| StorageError::Io(std::io::Error::from_raw_os_error(e.raw_os_error())))?;

        // SQLite requires a path string, so we construct one using the verified fd number.
        // We've already validated that /proc/self/fd is trustworthy above.
        let db_path = format!("/proc/self/fd/{}", fd_name.as_ref().to_string_lossy());
        let conn = Connection::open(&db_path)?;

        // Keep the file handle alive by forgetting it
        // The connection now owns the underlying fd
        std::mem::forget(db_file);

        Ok(conn)
    }

    /// Create storage from an existing root directory handle.
    ///
    /// This is useful when the directory handle has already been opened,
    /// such as when passing storage across threads.
    ///
    /// # Arguments
    ///
    /// * `root_dir` - An already-opened Dir handle to the storage root
    ///
    /// # Errors
    ///
    /// Returns an error if the directory is not a valid container storage.
    pub fn from_root_dir(root_dir: Dir) -> Result<Self> {
        Self::validate_storage(&root_dir)?;
        let db = Self::open_database(&root_dir)?;
        Ok(Self {
            root_dir,
            db,
            layers_lock: None,
            images_lock: None,
            read_only: true,
        })
    }

    /// Get a reference to the root directory handle.
    ///
    /// This provides access to the underlying `Dir` handle for advanced use cases.
    pub fn root_dir(&self) -> &Dir {
        &self.root_dir
    }

    /// Get a reference to the database connection.
    ///
    /// This provides access to the underlying SQLite connection for metadata queries.
    pub fn database(&self) -> &Connection {
        &self.db
    }

    // ========== Locking Methods ==========

    /// Acquire an exclusive lock on the layers store.
    ///
    /// This lock must be held when modifying layer data. The returned guard
    /// releases the lock when dropped.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::ReadOnly`] if the storage was opened in read-only mode.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::open_writable("/var/lib/containers/storage")?;
    /// let guard = storage.lock_layers()?;
    /// // Perform layer modifications...
    /// drop(guard); // Lock released
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn lock_layers(&self) -> Result<LayerLockGuard<'_>> {
        let lock = self.layers_lock.as_ref().ok_or(StorageError::ReadOnly)?;
        let guard = lock.lock();
        Ok(LayerLockGuard {
            storage: self,
            _lock: guard,
        })
    }

    /// Acquire an exclusive lock on the images store.
    ///
    /// This lock must be held when modifying image data. The returned guard
    /// releases the lock when dropped.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::ReadOnly`] if the storage was opened in read-only mode.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::open_writable("/var/lib/containers/storage")?;
    /// let guard = storage.lock_images()?;
    /// // Perform image modifications...
    /// drop(guard); // Lock released
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn lock_images(&self) -> Result<ImageLockGuard<'_>> {
        let lock = self.images_lock.as_ref().ok_or(StorageError::ReadOnly)?;
        let guard = lock.lock();
        Ok(ImageLockGuard {
            storage: self,
            _lock: guard,
        })
    }

    /// Acquire a shared (read) lock on the layers store.
    ///
    /// This lock allows concurrent readers but blocks writers. Use this when
    /// reading layer data to ensure consistency.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::ReadOnly`] if the storage was opened in read-only mode
    /// (read locks require the lock file to be opened).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::open_writable("/var/lib/containers/storage")?;
    /// let guard = storage.rlock_layers()?;
    /// // Read layer data with consistency guarantee...
    /// drop(guard);
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn rlock_layers(&self) -> Result<LayerRLockGuard<'_>> {
        let lock = self.layers_lock.as_ref().ok_or(StorageError::ReadOnly)?;
        let guard = lock.rlock();
        Ok(LayerRLockGuard {
            storage: self,
            _lock: guard,
        })
    }

    /// Acquire a shared (read) lock on the images store.
    ///
    /// This lock allows concurrent readers but blocks writers. Use this when
    /// reading image data to ensure consistency.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::ReadOnly`] if the storage was opened in read-only mode
    /// (read locks require the lock file to be opened).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::open_writable("/var/lib/containers/storage")?;
    /// let guard = storage.rlock_images()?;
    /// // Read image data with consistency guarantee...
    /// drop(guard);
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn rlock_images(&self) -> Result<ImageRLockGuard<'_>> {
        let lock = self.images_lock.as_ref().ok_or(StorageError::ReadOnly)?;
        let guard = lock.rlock();
        Ok(ImageRLockGuard {
            storage: self,
            _lock: guard,
        })
    }

    // ========== Change Detection Methods ==========

    /// Check if the layers store was modified since the given token.
    ///
    /// This reads the current "last write" token from the layers lock file
    /// and compares it to the provided token. Returns `true` if they differ,
    /// indicating another process has modified the layer data.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::ReadOnly`] if the storage was opened in read-only mode.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::open_writable("/var/lib/containers/storage")?;
    ///
    /// // Get initial state
    /// let token = storage.get_layers_last_write()?;
    ///
    /// // Later, check if anything changed
    /// if storage.layers_modified_since(&token)? {
    ///     println!("Layers were modified by another process");
    /// }
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn layers_modified_since(&self, token: &LastWrite) -> Result<bool> {
        let lock = self.layers_lock.as_ref().ok_or(StorageError::ReadOnly)?;
        Ok(lock.modified_since(token)?)
    }

    /// Check if the images store was modified since the given token.
    ///
    /// This reads the current "last write" token from the images lock file
    /// and compares it to the provided token.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::ReadOnly`] if the storage was opened in read-only mode.
    pub fn images_modified_since(&self, token: &LastWrite) -> Result<bool> {
        let lock = self.images_lock.as_ref().ok_or(StorageError::ReadOnly)?;
        Ok(lock.modified_since(token)?)
    }

    /// Get the current "last write" token for the layers store.
    ///
    /// This token can be saved and later used with [`layers_modified_since()`](Self::layers_modified_since)
    /// to detect if any modifications occurred.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::ReadOnly`] if the storage was opened in read-only mode.
    pub fn get_layers_last_write(&self) -> Result<LastWrite> {
        let lock = self.layers_lock.as_ref().ok_or(StorageError::ReadOnly)?;
        Ok(lock.get_last_write()?)
    }

    /// Get the current "last write" token for the images store.
    ///
    /// This token can be saved and later used with [`images_modified_since()`](Self::images_modified_since)
    /// to detect if any modifications occurred.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::ReadOnly`] if the storage was opened in read-only mode.
    pub fn get_images_last_write(&self) -> Result<LastWrite> {
        let lock = self.images_lock.as_ref().ok_or(StorageError::ReadOnly)?;
        Ok(lock.get_last_write()?)
    }

    /// Record a write operation to the layers store.
    ///
    /// This should be called while holding an exclusive layers lock. It updates
    /// the lock file with a new token that allows other processes to detect
    /// that a modification occurred.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::ReadOnly`] if the storage was opened in read-only mode.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::open_writable("/var/lib/containers/storage")?;
    /// let _guard = storage.lock_layers()?;
    ///
    /// // Perform layer modifications...
    ///
    /// // Record that we made changes
    /// let token = storage.record_layers_write()?;
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn record_layers_write(&self) -> Result<LastWrite> {
        let lock = self.layers_lock.as_ref().ok_or(StorageError::ReadOnly)?;
        Ok(lock.record_write()?)
    }

    /// Record a write operation to the images store.
    ///
    /// This should be called while holding an exclusive images lock.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::ReadOnly`] if the storage was opened in read-only mode.
    pub fn record_images_write(&self) -> Result<LastWrite> {
        let lock = self.images_lock.as_ref().ok_or(StorageError::ReadOnly)?;
        Ok(lock.record_write()?)
    }

    /// Resolve a link ID to a layer ID using fd-relative symlink reading.
    ///
    /// The overlay driver uses short link IDs (26 characters) in the `overlay/l/`
    /// directory. These are symlinks that point to the actual layer diff directories.
    ///
    /// # Arguments
    ///
    /// * `link_id` - The short link identifier (26 characters)
    ///
    /// # Returns
    ///
    /// The full layer ID that the link points to.
    ///
    /// # Errors
    ///
    /// Returns an error if the link doesn't exist or has an invalid format.
    pub fn resolve_link(&self, link_id: &str) -> Result<String> {
        // Open overlay directory from storage root
        let overlay_dir = self.root_dir.open_dir("overlay")?;

        // Open link directory
        let link_dir = overlay_dir.open_dir("l")?;

        // Read symlink target using fd-relative operation
        let target = link_dir.read_link(link_id).map_err(|e| {
            StorageError::LinkReadError(format!("Failed to read link {}: {}", link_id, e))
        })?;

        // Extract layer ID from symlink target
        Self::extract_layer_id_from_link(&target)
    }

    /// Extract layer ID from symlink target path.
    ///
    /// Target format: ../<layer-id>/diff
    fn extract_layer_id_from_link(target: &Path) -> Result<String> {
        // Convert to string for processing
        let target_str = target.to_str().ok_or_else(|| {
            StorageError::LinkReadError("Invalid UTF-8 in link target".to_string())
        })?;

        // Split by '/' and find the layer ID component
        let components: Vec<&str> = target_str.split('/').collect();

        // Expected format: ../<layer-id>/diff
        // So we need the second-to-last component
        if components.len() >= 2 {
            let layer_id = components[components.len() - 2];
            if !layer_id.is_empty() && layer_id != ".." {
                return Ok(layer_id.to_string());
            }
        }

        Err(StorageError::LinkReadError(format!(
            "Invalid link target format: {}",
            target_str
        )))
    }

    /// List all images in storage using fd-relative directory iteration.
    ///
    /// Returns a vector of [`Image`](crate::image::Image) instances for each image
    /// found in the `overlay-images/` directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the images directory cannot be read or if any image
    /// metadata is invalid.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::discover()?;
    /// for image in storage.list_images()? {
    ///     println!("Image: {}", image.id());
    /// }
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn list_images(&self) -> Result<Vec<crate::image::Image>> {
        use crate::image::Image;

        let images_dir = self.root_dir.open_dir("overlay-images")?;
        let mut images = Vec::new();

        for entry in images_dir.entries()? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let id = entry
                    .file_name()
                    .to_str()
                    .ok_or_else(|| {
                        StorageError::InvalidStorage(
                            "Invalid UTF-8 in image directory name".to_string(),
                        )
                    })?
                    .to_string();
                images.push(Image::open(self, &id)?);
            }
        }
        Ok(images)
    }

    /// Get an image by ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The image ID (64-character hex digest)
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::ImageNotFound`] if the image doesn't exist.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::discover()?;
    /// let image = storage.get_image("0123456789abcdef...")?;
    /// println!("Got image: {}", image.id());
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn get_image(&self, id: &str) -> Result<crate::image::Image> {
        crate::image::Image::open(self, id)
    }

    /// Get layers for an image (in order from base to top).
    ///
    /// Returns a vector of [`Layer`](crate::layer::Layer) instances corresponding
    /// to the image's layer stack, with the base layer first.
    ///
    /// Note: This method resolves OCI diff_ids from the image config to the
    /// actual storage layer IDs using the `layers.json` mapping file.
    ///
    /// # Arguments
    ///
    /// * `image` - Reference to the Image to get layers for
    ///
    /// # Errors
    ///
    /// Returns an error if any layer cannot be opened or if layer metadata is invalid.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::discover()?;
    /// let images = storage.list_images()?;
    /// if let Some(image) = images.first() {
    ///     let layers = storage.get_image_layers(image)?;
    ///     println!("Image has {} layers", layers.len());
    /// }
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn get_image_layers(
        &self,
        image: &crate::image::Image,
    ) -> Result<Vec<crate::layer::Layer>> {
        use crate::layer::Layer;
        // image.layers() returns diff_ids, which need to be mapped to storage layer IDs
        let diff_ids = image.layers()?;
        let mut layers = Vec::new();
        for diff_id in diff_ids {
            let layer_id = self.resolve_diff_id(&diff_id)?;
            layers.push(Layer::open(self, &layer_id)?);
        }
        Ok(layers)
    }

    /// Find an image by name.
    ///
    /// Searches the images.json index for an image with a matching name.
    /// The name can be a full image reference like "docker.io/library/alpine:latest"
    /// or a partial name like "alpine:latest" or "alpine".
    ///
    /// # Arguments
    ///
    /// * `name` - The image name to search for
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::ImageNotFound`] if no image with the given name is found.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::discover()?;
    /// let image = storage.find_image_by_name("alpine:latest")?;
    /// println!("Found image: {}", image.id());
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn find_image_by_name(&self, name: &str) -> Result<crate::image::Image> {
        use std::io::Read;

        // Read images.json from overlay-images/
        let images_dir = self.root_dir.open_dir("overlay-images")?;
        let mut file = images_dir.open("images.json")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // Parse the JSON array
        let entries: Vec<ImageEntry> = serde_json::from_str(&contents)
            .map_err(|e| StorageError::InvalidStorage(format!("Invalid images.json: {}", e)))?;

        // Search for matching name
        for entry in entries {
            if let Some(names) = &entry.names {
                for image_name in names {
                    if image_name == name {
                        return self.get_image(&entry.id);
                    }
                }
            }
        }

        // Try partial matching (e.g., "alpine:latest" matches "docker.io/library/alpine:latest")
        for entry in serde_json::from_str::<Vec<ImageEntry>>(&contents).unwrap_or_default() {
            if let Some(names) = &entry.names {
                for image_name in names {
                    // Check if name is a suffix (after removing registry/namespace prefix)
                    if image_name.ends_with(name) {
                        // Verify it's a proper boundary (preceded by '/')
                        let prefix = &image_name[..image_name.len() - name.len()];
                        if prefix.is_empty() || prefix.ends_with('/') {
                            return self.get_image(&entry.id);
                        }
                    }
                }
            }
        }

        Err(StorageError::ImageNotFound(name.to_string()))
    }

    /// Resolve a diff-digest to a storage layer ID.
    ///
    /// In containers-storage, layer directories are named with internal IDs,
    /// not the OCI diff_ids from the image config. This method reads the
    /// `overlay-layers/layers.json` file to find the layer with the matching
    /// `diff-digest` and returns its storage ID.
    ///
    /// # Arguments
    ///
    /// * `diff_digest` - The diff digest to look up (with or without "sha256:" prefix)
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::LayerNotFound`] if no layer with the given diff-digest exists.
    pub fn resolve_diff_id(&self, diff_digest: &str) -> Result<String> {
        use std::io::Read;

        // Normalize the diff_digest to include sha256: prefix for comparison
        let normalized = if diff_digest.starts_with("sha256:") {
            diff_digest.to_string()
        } else {
            format!("sha256:{}", diff_digest)
        };

        // Read layers.json from overlay-layers/
        let layers_dir = self.root_dir.open_dir("overlay-layers")?;
        let mut file = layers_dir.open("layers.json")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // Parse the JSON array
        let entries: Vec<LayerEntry> = serde_json::from_str(&contents)
            .map_err(|e| StorageError::InvalidStorage(format!("Invalid layers.json: {}", e)))?;

        // Search for matching diff-digest
        for entry in entries {
            if entry.diff_digest.as_ref() == Some(&normalized) {
                return Ok(entry.id);
            }
        }

        Err(StorageError::LayerNotFound(diff_digest.to_string()))
    }

    /// Get layer metadata including size information.
    ///
    /// Returns the layer entry from layers.json for the given layer ID.
    pub fn get_layer_metadata(&self, layer_id: &str) -> Result<LayerMetadata> {
        use std::io::Read;

        // Read layers.json from overlay-layers/
        let layers_dir = self.root_dir.open_dir("overlay-layers")?;
        let mut file = layers_dir.open("layers.json")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // Parse the JSON array
        let entries: Vec<LayerEntry> = serde_json::from_str(&contents)
            .map_err(|e| StorageError::InvalidStorage(format!("Invalid layers.json: {}", e)))?;

        // Search for matching layer ID
        for entry in entries {
            if entry.id == layer_id {
                return Ok(LayerMetadata {
                    id: entry.id,
                    parent: entry.parent,
                    diff_size: entry.diff_size,
                    compressed_size: entry.compressed_size,
                });
            }
        }

        Err(StorageError::LayerNotFound(layer_id.to_string()))
    }

    /// Calculate the total uncompressed size of an image.
    ///
    /// Walks through all layers and sums their diff_size values.
    pub fn calculate_image_size(&self, image: &crate::image::Image) -> Result<u64> {
        let layers = self.get_image_layers(image)?;
        let mut total_size: u64 = 0;

        for layer in &layers {
            let metadata = self.get_layer_metadata(&layer.id)?;
            if let Some(size) = metadata.diff_size {
                total_size = total_size.saturating_add(size);
            }
        }

        Ok(total_size)
    }
}

/// Entry in images.json for image name lookups.
#[derive(Debug, serde::Deserialize)]
struct ImageEntry {
    id: String,
    names: Option<Vec<String>>,
}

/// Entry in layers.json for layer ID lookups.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
struct LayerEntry {
    id: String,
    parent: Option<String>,
    diff_digest: Option<String>,
    diff_size: Option<u64>,
    compressed_size: Option<u64>,
}

/// Metadata about a layer from layers.json.
#[derive(Debug, Clone)]
pub struct LayerMetadata {
    /// Layer storage ID.
    pub id: String,
    /// Parent layer ID (if not base layer).
    pub parent: Option<String>,
    /// Uncompressed diff size in bytes.
    pub diff_size: Option<u64>,
    /// Compressed size in bytes.
    pub compressed_size: Option<u64>,
}

// ========== Lock Guard Types ==========

/// RAII guard for an exclusive lock on the layers store.
///
/// This guard is returned by [`Storage::lock_layers()`] and provides exclusive
/// access to layer data. The lock is automatically released when the guard is dropped.
///
/// # Example
///
/// ```no_run
/// use cstor_rs::Storage;
///
/// let storage = Storage::open_writable("/var/lib/containers/storage")?;
///
/// {
///     let guard = storage.lock_layers()?;
///     // Exclusive access to layers...
/// } // Lock released here
/// # Ok::<(), cstor_rs::StorageError>(())
/// ```
#[derive(Debug)]
pub struct LayerLockGuard<'a> {
    /// Reference to the storage that owns the lock.
    storage: &'a Storage,
    /// The underlying lock guard from the lockfile module.
    _lock: LockGuard<'a>,
}

impl<'a> LayerLockGuard<'a> {
    /// Get a reference to the storage.
    pub fn storage(&self) -> &Storage {
        self.storage
    }
}

/// RAII guard for a shared (read) lock on the layers store.
///
/// This guard is returned by [`Storage::rlock_layers()`] and provides shared
/// read access to layer data. Multiple readers can hold this lock simultaneously,
/// but writers are blocked.
#[derive(Debug)]
pub struct LayerRLockGuard<'a> {
    /// Reference to the storage that owns the lock.
    storage: &'a Storage,
    /// The underlying read lock guard from the lockfile module.
    _lock: RLockGuard<'a>,
}

impl<'a> LayerRLockGuard<'a> {
    /// Get a reference to the storage.
    pub fn storage(&self) -> &Storage {
        self.storage
    }
}

/// RAII guard for an exclusive lock on the images store.
///
/// This guard is returned by [`Storage::lock_images()`] and provides exclusive
/// access to image data. The lock is automatically released when the guard is dropped.
///
/// # Example
///
/// ```no_run
/// use cstor_rs::Storage;
///
/// let storage = Storage::open_writable("/var/lib/containers/storage")?;
///
/// {
///     let guard = storage.lock_images()?;
///     // Exclusive access to images...
/// } // Lock released here
/// # Ok::<(), cstor_rs::StorageError>(())
/// ```
#[derive(Debug)]
pub struct ImageLockGuard<'a> {
    /// Reference to the storage that owns the lock.
    storage: &'a Storage,
    /// The underlying lock guard from the lockfile module.
    _lock: LockGuard<'a>,
}

impl<'a> ImageLockGuard<'a> {
    /// Get a reference to the storage.
    pub fn storage(&self) -> &Storage {
        self.storage
    }
}

/// RAII guard for a shared (read) lock on the images store.
///
/// This guard is returned by [`Storage::rlock_images()`] and provides shared
/// read access to image data. Multiple readers can hold this lock simultaneously,
/// but writers are blocked.
#[derive(Debug)]
pub struct ImageRLockGuard<'a> {
    /// Reference to the storage that owns the lock.
    storage: &'a Storage,
    /// The underlying read lock guard from the lockfile module.
    _lock: RLockGuard<'a>,
}

impl<'a> ImageRLockGuard<'a> {
    /// Get a reference to the storage.
    pub fn storage(&self) -> &Storage {
        self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_search_paths() {
        let paths = Storage::default_search_paths();
        assert!(!paths.is_empty(), "Should have at least one search path");
    }

    #[test]
    #[ignore] // Requires actual storage to be present
    fn test_storage_discovery() {
        let result = Storage::discover();
        // This test will only pass if storage exists at a default location
        if result.is_ok() {
            println!("Found storage at default location");
        }
    }

    #[test]
    fn test_read_only_storage_is_not_writable() {
        // Create a mock storage directory structure for testing
        let dir = tempfile::tempdir().unwrap();
        let storage_path = dir.path();

        // Create required directories and files
        std::fs::create_dir_all(storage_path.join("overlay")).unwrap();
        std::fs::create_dir_all(storage_path.join("overlay-layers")).unwrap();
        std::fs::create_dir_all(storage_path.join("overlay-images")).unwrap();

        // Create an empty db.sql file
        std::fs::write(storage_path.join("db.sql"), "").unwrap();

        let storage = Storage::open(storage_path).unwrap();
        assert!(!storage.is_writable());

        // Lock operations should fail on read-only storage
        assert!(matches!(storage.lock_layers(), Err(StorageError::ReadOnly)));
        assert!(matches!(storage.lock_images(), Err(StorageError::ReadOnly)));
        assert!(matches!(
            storage.rlock_layers(),
            Err(StorageError::ReadOnly)
        ));
        assert!(matches!(
            storage.rlock_images(),
            Err(StorageError::ReadOnly)
        ));
    }

    #[test]
    fn test_writable_storage_locking() {
        // Create a mock storage directory structure for testing
        let dir = tempfile::tempdir().unwrap();
        let storage_path = dir.path();

        // Create required directories and files
        std::fs::create_dir_all(storage_path.join("overlay")).unwrap();
        std::fs::create_dir_all(storage_path.join("overlay-layers")).unwrap();
        std::fs::create_dir_all(storage_path.join("overlay-images")).unwrap();

        // Create an empty db.sql file
        std::fs::write(storage_path.join("db.sql"), "").unwrap();

        let storage = Storage::open_writable(storage_path).unwrap();
        assert!(storage.is_writable());

        // Exclusive layer lock
        {
            let guard = storage.lock_layers().unwrap();
            assert!(std::ptr::eq(guard.storage(), &storage));
        }

        // Exclusive image lock
        {
            let guard = storage.lock_images().unwrap();
            assert!(std::ptr::eq(guard.storage(), &storage));
        }

        // Shared layer lock
        {
            let guard = storage.rlock_layers().unwrap();
            assert!(std::ptr::eq(guard.storage(), &storage));
        }

        // Shared image lock
        {
            let guard = storage.rlock_images().unwrap();
            assert!(std::ptr::eq(guard.storage(), &storage));
        }
    }

    #[test]
    fn test_change_detection() {
        // Create a mock storage directory structure for testing
        let dir = tempfile::tempdir().unwrap();
        let storage_path = dir.path();

        // Create required directories and files
        std::fs::create_dir_all(storage_path.join("overlay")).unwrap();
        std::fs::create_dir_all(storage_path.join("overlay-layers")).unwrap();
        std::fs::create_dir_all(storage_path.join("overlay-images")).unwrap();

        // Create an empty db.sql file
        std::fs::write(storage_path.join("db.sql"), "").unwrap();

        let storage = Storage::open_writable(storage_path).unwrap();

        // Get initial token (should be empty/default)
        let token1 = storage.get_layers_last_write().unwrap();
        assert!(token1.is_empty());

        // Acquire lock and record a write
        let _guard = storage.lock_layers().unwrap();
        let token2 = storage.record_layers_write().unwrap();
        drop(_guard);

        // Should not be modified since token2
        assert!(!storage.layers_modified_since(&token2).unwrap());

        // Should be modified since token1
        assert!(storage.layers_modified_since(&token1).unwrap());

        // Record another write
        let _guard = storage.lock_layers().unwrap();
        let token3 = storage.record_layers_write().unwrap();
        drop(_guard);

        // token2 should now show modification
        assert!(storage.layers_modified_since(&token2).unwrap());
        assert!(!storage.layers_modified_since(&token3).unwrap());
    }
}
