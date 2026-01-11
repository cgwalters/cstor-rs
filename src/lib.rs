//! Read-only access to containers-storage overlay driver.
//!
//! This library provides efficient, capability-based access to container image
//! storage using the overlay driver. All file operations are performed using
//! file descriptor-relative operations via cap-std, providing security against
//! path traversal attacks and TOCTOU race conditions.
//!
//! # Overview
//!
//! The library is designed to access containers-storage (overlay driver) without
//! requiring tar serialization. Instead, it provides direct file descriptor access
//! to layer content, enabling zero-copy operations.
//!
//! # Key Features
//!
//! - **Capability-based security**: All file access via `cap_std::fs::Dir` handles
//! - **Read-only**: No modifications to storage
//! - **Zero-copy access**: File descriptors instead of data copies
//! - **Safe by design**: No path traversal vulnerabilities
//! - **Tar-split integration**: Bit-for-bit identical TAR reconstruction
//! - **OCI compatibility**: Uses oci-spec and ocidir for standard image formats
//!
//! # Example
//!
//! ```no_run
//! use cstor_rs::Storage;
//!
//! // Discover storage from default locations
//! let storage = Storage::discover()?;
//!
//! // Or open storage at a specific path
//! let storage = Storage::open("/var/lib/containers/storage")?;
//! # Ok::<(), cstor_rs::StorageError>(())
//! ```
//!
//! # Architecture
//!
//! The library uses cap-std for all file operations:
//! - `Storage` holds a `Dir` handle to the storage root
//! - All file access is relative to `Dir` handles
//! - No absolute paths are constructed during operations
//! - SQLite database accessed via fd-relative path
//!
//! This approach eliminates entire classes of vulnerabilities while maintaining
//! clean, idiomatic Rust code.
//!
//! # Command-Line Tools
//!
//! The library includes a `cstor-rs` binary that provides comprehensive access
//! to all library functionality:
//! - List and inspect images and layers
//! - Export layers as tar streams using tar-split metadata
//! - Copy images to OCI directory format (similar to skopeo)
//! - Extract images to directories with reflink support
//! - Generate Table of Contents (TOC) in JSON format
//!
//! Example usage:
//! ```bash
//! # List all images
//! cstor-rs list-images --verbose
//!
//! # Copy image to OCI directory
//! cstor-rs copy-to-oci <image-id> /path/to/oci-dir
//!
//! # Generate TOC for an image
//! cstor-rs toc <image-id> --pretty
//! ```

pub mod client;
pub mod config;
pub mod error;
pub mod generic_tree;
pub mod image;
pub mod layer;
pub mod protocol;
pub mod proxy_v2;
pub mod server;
pub mod storage;
pub mod tar_split;
pub mod tar_writer;
pub mod toc;

// Re-export commonly used types
pub use config::{AdditionalLayerStore, StorageConfig};
pub use error::{Result, StorageError};
pub use generic_tree::{FileSystem, Inode, TreeError};
pub use image::Image;
pub use layer::Layer;
pub use storage::Storage;
pub use tar_split::{TarHeader, TarSplitFdStream, TarSplitItem};
pub use tar_writer::{write_file_data, write_tar_footer, write_tar_header};
pub use toc::{Toc, TocEntry, TocEntryType};

// Re-export OCI spec types for convenience
pub use oci_spec::image::{Descriptor, ImageConfiguration, ImageManifest};
