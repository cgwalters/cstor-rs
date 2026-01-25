//! Test fixtures for isolated containers-storage instances.

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use tempfile::TempDir;

use cstor_rs::Storage;

/// An isolated test storage instance with temporary directories.
///
/// Creates a minimal containers-storage structure suitable for testing
/// layer creation and manipulation. The storage is automatically cleaned
/// up when dropped.
pub struct TestStorage {
    /// Root temporary directory containing the storage.
    _temp_dir: TempDir,
    /// Path to the storage root.
    root_path: PathBuf,
    /// The opened storage instance.
    storage: Storage,
}

impl TestStorage {
    /// Create a new isolated test storage.
    ///
    /// This creates:
    /// - `overlay/` - Layer diff directories
    /// - `overlay-layers/` - Layer metadata (layers.json)
    /// - `overlay-images/` - Image metadata
    /// - `db.sql` - Empty SQLite database
    /// - `storage.lock` - Lock file
    pub fn new() -> color_eyre::Result<Self> {
        let temp_dir = TempDir::new()?;
        let root_path = temp_dir.path().to_path_buf();

        // Create the minimal directory structure
        std::fs::create_dir_all(root_path.join("overlay"))?;
        std::fs::create_dir_all(root_path.join("overlay/l"))?; // Links directory
        std::fs::create_dir_all(root_path.join("overlay-layers"))?;
        std::fs::create_dir_all(root_path.join("overlay-images"))?;

        // Create empty layers.json
        std::fs::write(root_path.join("overlay-layers/layers.json"), "[]")?;

        // Create empty images.json
        std::fs::write(root_path.join("overlay-images/images.json"), "[]")?;

        // Create empty SQLite database (containers-storage requires this)
        let db_path = root_path.join("db.sql");
        let _conn = Connection::open(&db_path)?;

        // Create storage.lock
        std::fs::write(root_path.join("storage.lock"), "")?;

        // Open the storage
        let storage = Storage::open(&root_path)?;

        Ok(Self {
            _temp_dir: temp_dir,
            root_path,
            storage,
        })
    }

    /// Get a reference to the storage.
    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    /// Get the root path of the test storage.
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    /// Get the overlay directory path.
    pub fn overlay_path(&self) -> PathBuf {
        self.root_path.join("overlay")
    }
}

impl std::fmt::Debug for TestStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestStorage")
            .field("root_path", &self.root_path)
            .finish()
    }
}
