//! Configuration parsing for container storage.
//!
//! This module provides structures for parsing storage.conf files used by
//! containers-storage. Configuration files define storage locations, drivers,
//! and additional read-only image stores.
//!
//! # Overview
//!
//! Container storage configuration is typically found in:
//! - System-wide: `/etc/containers/storage.conf`
//! - User-specific: `~/.config/containers/storage.conf`
//!
//! The configuration uses TOML format and specifies the storage driver
//! (overlay, btrfs, etc.), root paths, and additional layer/image stores.
//!
//! # Configuration Structure
//!
//! A typical storage.conf file looks like:
//! ```toml
//! [storage]
//! driver = "overlay"
//! root = "/var/lib/containers/storage"
//! run_root = "/run/containers/storage"
//!
//! # Additional read-only image stores
//! image_stores = [
//!     "/usr/share/containers/storage"
//! ]
//!
//! # Additional layer stores with base64 reference support
//! [[storage.layer_stores]]
//! path = "/mnt/layers"
//! with_reference = true
//! ```
//!
//! # Usage Example
//!
//! ```no_run
//! use cstor_rs::StorageConfig;
//! use std::fs;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Read and parse configuration
//! let config_content = fs::read_to_string("/etc/containers/storage.conf")?;
//! let config = StorageConfig::from_toml(&config_content)?;
//!
//! println!("Driver: {}", config.driver);
//! println!("Root: {:?}", config.root);
//! println!("Additional stores: {}", config.image_stores.len());
//! # Ok(())
//! # }
//! ```
//!
//! # Note
//!
//! This library currently provides read-only access and primarily uses the
//! configuration for discovering storage locations. The [`Storage::discover()`]
//! method searches standard locations and environment variables, typically
//! making explicit configuration parsing unnecessary for basic use cases.
//!
//! [`Storage::discover()`]: crate::Storage::discover

use serde::Deserialize;
use std::path::PathBuf;

/// Storage configuration, typically parsed from storage.conf files.
///
/// Configuration files are searched in:
/// - `/etc/containers/storage.conf`
/// - `$HOME/.config/containers/storage.conf`
#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    /// Storage driver name (should be "overlay" for this library).
    #[serde(default)]
    pub driver: String,

    /// Primary storage root path.
    #[serde(default)]
    pub root: PathBuf,

    /// Runtime root for transient data.
    #[serde(default)]
    pub run_root: PathBuf,

    /// Additional read-only image stores.
    #[serde(default)]
    pub image_stores: Vec<PathBuf>,

    /// Additional layer stores configuration.
    #[serde(default)]
    pub layer_stores: Vec<AdditionalLayerStore>,
}

/// Configuration for an additional layer store.
#[derive(Debug, Clone, Deserialize)]
pub struct AdditionalLayerStore {
    /// Path to the additional layer store.
    pub path: PathBuf,

    /// Whether to use base64-encoded references in paths.
    #[serde(default)]
    pub with_reference: bool,
}

impl StorageConfig {
    /// Parse storage configuration from TOML content.
    pub fn from_toml(content: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(content)
    }
}
