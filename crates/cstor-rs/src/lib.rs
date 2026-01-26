#![forbid(unsafe_code)]
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
//! For streaming layers over IPC, the [`splitfdstream`] format allows tar archives
//! to reference external file descriptors for large file content, enabling efficient
//! transfer via Unix sockets with fd passing.
//!
//! # Key Features
//!
//! - **Capability-based security**: All file access via `cap_std::fs::Dir` handles
//! - **Layer creation**: Build new layers with reflink support
//! - **Layer extraction**: Extract layers/images with reflink support for zero-copy
//! - **Zero-copy access**: File descriptors instead of data copies
//! - **Safe by design**: No path traversal vulnerabilities
//! - **Tar-split integration**: Bit-for-bit identical TAR reconstruction
//! - **OCI compatibility**: Uses oci-spec and ocidir for standard image formats
//! - **IPC streaming**: JSON-RPC protocol with fd passing for layer transfer
//! - **User namespace support**: Transparent proxied access for unprivileged users
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

// Core storage access
pub mod config;
pub mod error;
pub mod image;
pub mod layer;
pub mod lockfile;
pub mod storage;

// Tar handling
pub mod tar_split;
pub mod tar_split_writer;
pub mod tar_writer;
pub mod toc;

// Layer creation and management
pub mod image_store;
pub mod layer_builder;
pub mod layer_store;

// Layer extraction
pub mod extract;

// Splitfdstream binary format
pub mod splitfdstream;

// IPC protocol (JSON-RPC with fd passing)
pub mod client;
pub mod protocol;
pub mod server;

// Utilities
pub mod generic_tree;
pub mod proxy_v2;
mod readatreader;

// User namespace handling
pub mod userns;
pub mod userns_helper;

// Re-export userns_helper types for convenient access
pub use userns_helper::{
    ImageInfo, ProxiedStorage, ProxiedTarSplitItem, StorageProxy, init_if_helper,
};

// Re-export commonly used types
pub use config::{AdditionalLayerStore, StorageConfig};
pub use error::{Result, StorageError};
pub use generic_tree::{FileSystem, Inode, TreeError};
pub use image::Image;
pub use layer::Layer;
pub use lockfile::LastWrite;
pub use storage::{
    ImageLockGuard, ImageRLockGuard, LayerLockGuard, LayerMetadata, LayerRLockGuard, Storage,
};
pub use tar_split::{
    DEFAULT_INLINE_THRESHOLD, LayerSplitfdstream, TarHeader, TarSplitFdStream, TarSplitItem,
    layer_to_splitfdstream,
};
pub use tar_writer::{write_file_data, write_tar_footer, write_tar_header};
pub use toc::{Toc, TocEntry, TocEntryType};

// Layer creation and management exports
pub use image_store::{ImageRecord, ImageStore};
pub use layer_builder::LayerBuilder;
pub use layer_store::{
    IdMapping, ImportOptions, ImportStats, LayerRecord, LayerStore, generate_layer_id,
    generate_link_id,
};
pub use tar_split_writer::TarSplitWriter;

// Layer extraction exports
pub use extract::{
    AllowAllHardlinks, DefaultHardlinkFilter, DenyAllHardlinks, ExtractionOptions,
    ExtractionStats, HardlinkFilter, LinkMode, extract_image, extract_image_with_toc,
    extract_layer, HARDLINK_MIN_SIZE_LARGE, HARDLINK_MIN_SIZE_SMALL,
};

// Re-export OCI spec types for convenience
pub use oci_spec::image::{Descriptor, ImageConfiguration, ImageManifest};
