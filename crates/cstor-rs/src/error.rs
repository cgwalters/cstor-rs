//! Error types for the cstor-rs library.
//!
//! This module defines the error types used throughout the library. All operations
//! that can fail return a [`Result<T>`] which is an alias for `Result<T, StorageError>`.
//!
//! # Error Categories
//!
//! Errors are organized into several categories:
//!
//! - **Storage errors**: [`RootNotFound`], [`InvalidStorage`]
//! - **Entity errors**: [`LayerNotFound`], [`ImageNotFound`]
//! - **Link resolution**: [`LinkReadError`]
//! - **Tar-split processing**: [`TarSplitError`]
//! - **System errors**: [`Io`], [`Database`], [`JsonParse`]
//!
//! [`RootNotFound`]: StorageError::RootNotFound
//! [`InvalidStorage`]: StorageError::InvalidStorage
//! [`LayerNotFound`]: StorageError::LayerNotFound
//! [`ImageNotFound`]: StorageError::ImageNotFound
//! [`LinkReadError`]: StorageError::LinkReadError
//! [`TarSplitError`]: StorageError::TarSplitError
//! [`Io`]: StorageError::Io
//! [`Database`]: StorageError::Database
//! [`JsonParse`]: StorageError::JsonParse
//!
//! # Error Handling Example
//!
//! ```no_run
//! use cstor_rs::{Storage, StorageError};
//!
//! fn open_storage() -> Result<(), StorageError> {
//!     let storage = match Storage::discover() {
//!         Ok(s) => s,
//!         Err(StorageError::RootNotFound(path)) => {
//!             eprintln!("Storage not found at: {:?}", path);
//!             return Err(StorageError::RootNotFound(path));
//!         }
//!         Err(e) => return Err(e),
//!     };
//!
//!     // Use storage...
//!     Ok(())
//! }
//! ```
//!
//! # Conversion Traits
//!
//! The error type implements `From` conversions for common error types:
//! - `std::io::Error` → `StorageError::Io`
//! - `rusqlite::Error` → `StorageError::Database`
//! - `serde_json::Error` → `StorageError::JsonParse`
//!
//! This allows the `?` operator to work seamlessly with these error types.

use std::path::PathBuf;

use crate::generic_tree::TreeError;

/// Result type alias for operations that may return a StorageError.
pub type Result<T> = std::result::Result<T, StorageError>;

/// Error types for storage operations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Storage root directory was not found at the specified path.
    #[error("storage root not found at {0}")]
    RootNotFound(PathBuf),

    /// Storage validation failed with the provided reason.
    #[error("invalid storage: {0}")]
    InvalidStorage(String),

    /// The requested layer was not found.
    #[error("layer not found: {0}")]
    LayerNotFound(String),

    /// The requested image was not found.
    #[error("image not found: {0}")]
    ImageNotFound(String),

    /// Failed to read a link file.
    #[error("failed to read link file: {0}")]
    LinkReadError(String),

    /// Error related to tar-split processing.
    #[error("tar-split error: {0}")]
    TarSplitError(String),

    /// I/O error occurred during file operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Database error occurred during SQLite operations.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// JSON parsing error occurred.
    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),

    /// Tree operation error (e.g., invalid path).
    #[error("tree error: {0}")]
    Tree(#[from] TreeError),
}
