//! Image reading and manifest parsing.
//!
//! This module provides access to OCI image manifests and metadata stored in
//! the `overlay-images/` directory. All operations use fd-relative access via
//! cap-std Dir handles.
//!
//! # Overview
//!
//! The [`Image`] struct represents a container image stored in the overlay driver.
//! It provides access to:
//! - OCI image manifests ([`oci_spec::image::ImageManifest`])
//! - OCI image configurations ([`oci_spec::image::ImageConfiguration`])
//! - Layer information (diff_ids that map to storage layer IDs)
//! - Additional metadata stored in base64-encoded files
//!
//! # OCI Specification
//!
//! This implementation follows the [OCI Image Spec](https://github.com/opencontainers/image-spec):
//! - Images have a manifest describing layers and configuration
//! - Configuration contains rootfs diff_ids (uncompressed layer digests)
//! - These diff_ids correspond to layer directory names in storage
//!
//! # Image Directory Structure
//!
//! Each image is stored in `overlay-images/<image-id>/`:
//! ```text
//! overlay-images/<image-id>/
//! ├── manifest              # OCI image manifest (JSON)
//! └── =<base64-key>         # Additional metadata files
//! ```
//!
//! # Usage Example
//!
//! ```no_run
//! use cstor_rs::{Storage, Image};
//!
//! let storage = Storage::discover()?;
//!
//! // List all images
//! let images = storage.list_images()?;
//! for image in images {
//!     println!("Image: {}", image.id());
//!
//!     // Access manifest
//!     let manifest = image.manifest()?;
//!     println!("  Layers: {}", manifest.layers().len());
//!
//!     // Get layer IDs
//!     let layer_ids = image.layers()?;
//!     for layer_id in layer_ids {
//!         println!("  Layer: {}", layer_id);
//!     }
//! }
//! # Ok::<(), cstor_rs::StorageError>(())
//! ```
//!
//! # Metadata Encoding
//!
//! Additional metadata files use base64-encoded keys as filenames, prefixed with `=`.
//! For example, the image configuration might be stored as `=<base64("sha256:...")>`.

use cap_std::fs::Dir;
use oci_spec::image::{ImageConfiguration, ImageManifest};
use std::io::Read;

use crate::error::{Result, StorageError};
use crate::storage::Storage;

/// Represents an OCI image with its metadata and manifest.
#[derive(Debug)]
pub struct Image {
    /// Image ID (typically a 64-character hex digest).
    id: String,

    /// Directory handle for overlay-images/\<image-id\>/.
    image_dir: Dir,
}

impl Image {
    /// Open an image by ID using fd-relative operations.
    ///
    /// # Arguments
    ///
    /// * `storage` - Reference to the Storage instance
    /// * `id` - Image ID to open
    ///
    /// # Errors
    ///
    /// Returns an error if the image directory doesn't exist or cannot be opened.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::{Storage, Image};
    ///
    /// let storage = Storage::discover()?;
    /// let image = Image::open(&storage, "abc123...")?;
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn open(storage: &Storage, id: &str) -> Result<Self> {
        // Open overlay-images directory from storage root
        let images_dir = storage.root_dir().open_dir("overlay-images")?;

        // Open specific image directory
        let image_dir = images_dir
            .open_dir(id)
            .map_err(|_| StorageError::ImageNotFound(id.to_string()))?;

        Ok(Self {
            id: id.to_string(),
            image_dir,
        })
    }

    /// Get the image ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Read and parse the image manifest.
    ///
    /// The manifest is stored as a JSON file named "manifest" in the image directory.
    /// It follows the OCI Image Manifest specification.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest file cannot be read or parsed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::{Storage, Image};
    ///
    /// let storage = Storage::discover()?;
    /// let image = Image::open(&storage, "abc123...")?;
    /// let manifest = image.manifest()?;
    /// println!("Manifest has {} layers", manifest.layers().len());
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn manifest(&self) -> Result<ImageManifest> {
        let manifest_data = self.image_dir.read_to_string("manifest")?;
        serde_json::from_str(&manifest_data)
            .map_err(|e| StorageError::InvalidStorage(format!("Invalid manifest JSON: {}", e)))
    }

    /// Read and parse the image configuration.
    ///
    /// The image config is stored with a base64-encoded key based on the image digest.
    /// The configuration contains rootfs diff_ids which map to layer directory names.
    ///
    /// # Errors
    ///
    /// Returns an error if the config file cannot be read or parsed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::{Storage, Image};
    ///
    /// let storage = Storage::discover()?;
    /// let image = storage.list_images()?.into_iter().next().unwrap();
    /// let config = image.config()?;
    /// println!("Created: {:?}", config.created());
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn config(&self) -> Result<ImageConfiguration> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        // The config is stored with key: sha256:<image-id>
        // Base64 encode: "sha256:<id>"
        let key = format!("sha256:{}", self.id);
        let encoded_key = STANDARD.encode(key.as_bytes());

        let config_data = self.read_metadata(&encoded_key)?;
        serde_json::from_slice(&config_data)
            .map_err(|e| StorageError::InvalidStorage(format!("Invalid config JSON: {}", e)))
    }

    /// Get the OCI diff_ids for this image in order (base to top).
    ///
    /// This returns the diff_ids from the image config, which are the uncompressed
    /// tar digests. Note that these are **not** the same as the storage layer IDs!
    /// To get the actual storage layer IDs, use [`storage_layer_ids()`](Self::storage_layer_ids).
    ///
    /// # Errors
    ///
    /// Returns an error if the config cannot be read or parsed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::{Storage, Image};
    ///
    /// let storage = Storage::discover()?;
    /// let image = Image::open(&storage, "abc123...")?;
    /// let diff_ids = image.layers()?;
    /// for id in diff_ids {
    ///     println!("Diff ID: {}", id);
    /// }
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn layers(&self) -> Result<Vec<String>> {
        let config = self.config()?;

        // Extract diff_ids from config - these are NOT the storage layer IDs
        let diff_ids: Vec<String> = config
            .rootfs()
            .diff_ids()
            .iter()
            .map(|digest| {
                // Remove the "sha256:" prefix if present
                let diff_id = digest.to_string();
                diff_id
                    .strip_prefix("sha256:")
                    .unwrap_or(&diff_id)
                    .to_string()
            })
            .collect();

        Ok(diff_ids)
    }

    /// Get the storage layer IDs for this image in order (base to top).
    ///
    /// Unlike [`layers()`](Self::layers) which returns OCI diff_ids, this method
    /// returns the actual storage layer directory names by resolving diff_ids
    /// through the `layers.json` mapping file.
    ///
    /// # Arguments
    ///
    /// * `storage` - Reference to the Storage instance for layer lookup
    ///
    /// # Errors
    ///
    /// Returns an error if the config cannot be read, parsed, or if any layer
    /// cannot be resolved.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::{Storage, Image};
    ///
    /// let storage = Storage::discover()?;
    /// let image = Image::open(&storage, "abc123...")?;
    /// let layer_ids = image.storage_layer_ids(&storage)?;
    /// for id in layer_ids {
    ///     println!("Layer: {}", id);
    /// }
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn storage_layer_ids(&self, storage: &Storage) -> Result<Vec<String>> {
        let diff_ids = self.layers()?;
        diff_ids
            .iter()
            .map(|diff_id| storage.resolve_diff_id(diff_id))
            .collect()
    }

    /// Read additional metadata files.
    ///
    /// Metadata files are stored with base64-encoded keys as filenames,
    /// prefixed with '='. For example, a key "config.json" might be stored
    /// as "=Y29uZmlnLmpzb24=".
    ///
    /// # Arguments
    ///
    /// * `key` - The base64-encoded key (without the '=' prefix)
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata file doesn't exist or cannot be read.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::{Storage, Image};
    ///
    /// let storage = Storage::discover()?;
    /// let image = Image::open(&storage, "abc123...")?;
    ///
    /// // Read metadata file with base64-encoded key
    /// let metadata = image.read_metadata("Y29uZmlnLmpzb24")?;
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn read_metadata(&self, key: &str) -> Result<Vec<u8>> {
        let filename = format!("={}", key);
        let mut file = self.image_dir.open(&filename)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    }

    /// Get a reference to the image directory handle.
    ///
    /// This provides direct access to the image directory (`overlay-images/<image-id>/`)
    /// for advanced use cases like reading metadata files directly or listing
    /// directory contents.
    pub fn image_dir(&self) -> &Dir {
        &self.image_dir
    }

    /// Build a merged Table of Contents for this image.
    ///
    /// This creates a TOC representing the final flattened view of the image,
    /// with all layer TOCs merged and whiteouts processed according to overlay
    /// filesystem semantics.
    ///
    /// # Arguments
    ///
    /// * `storage` - Reference to the Storage instance for accessing layers
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::{Storage, Image};
    ///
    /// let storage = Storage::discover()?;
    /// let image = Image::open(&storage, "abc123...")?;
    /// let toc = image.toc(&storage)?;
    /// println!("Image has {} entries", toc.entries.len());
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn toc(&self, storage: &Storage) -> Result<crate::toc::Toc> {
        crate::toc::Toc::from_image(storage, self)
    }

    /// Get the repository names/tags for this image.
    ///
    /// Reads from the `overlay-images/images.json` index file to find the
    /// names associated with this image.
    ///
    /// # Arguments
    ///
    /// * `storage` - Reference to the Storage instance
    ///
    /// # Returns
    ///
    /// Returns an empty vector if the image has no tags.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::{Storage, Image};
    ///
    /// let storage = Storage::discover()?;
    /// let image = Image::open(&storage, "abc123...")?;
    /// let names = image.names(&storage)?;
    /// for name in names {
    ///     println!("  {}", name);
    /// }
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn names(&self, storage: &Storage) -> Result<Vec<String>> {
        let images_dir = storage.root_dir().open_dir("overlay-images")?;
        let mut file = images_dir.open("images.json")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let entries: Vec<ImageJsonEntry> = serde_json::from_str(&contents)
            .map_err(|e| StorageError::InvalidStorage(format!("Invalid images.json: {}", e)))?;

        for entry in entries {
            if entry.id == self.id {
                return Ok(entry.names.unwrap_or_default());
            }
        }

        // Image not found in images.json - return empty names
        Ok(Vec::new())
    }

    /// Get the image creation time.
    ///
    /// Reads from the OCI image config and parses the RFC3339 timestamp.
    ///
    /// # Returns
    ///
    /// Returns `None` if the image config has no creation timestamp.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::{Storage, Image};
    ///
    /// let storage = Storage::discover()?;
    /// let image = Image::open(&storage, "abc123...")?;
    /// if let Some(created) = image.created()? {
    ///     println!("Created: {}", created);
    /// }
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn created(&self) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
        let config = self.config()?;

        match config.created() {
            Some(created_str) => {
                let dt = chrono::DateTime::parse_from_rfc3339(created_str)
                    .map_err(|e| {
                        StorageError::InvalidStorage(format!(
                            "Invalid created timestamp '{}': {}",
                            created_str, e
                        ))
                    })?
                    .with_timezone(&chrono::Utc);
                Ok(Some(dt))
            }
            None => Ok(None),
        }
    }
}

/// Entry in images.json for image name lookups.
#[derive(Debug, serde::Deserialize)]
struct ImageJsonEntry {
    id: String,
    names: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_parsing() {
        let manifest_json = r#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "size": 1234
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                    "size": 5678
                },
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                    "size": 9012
                }
            ]
        }"#;

        let manifest: ImageManifest = serde_json::from_str(manifest_json).unwrap();
        assert_eq!(manifest.schema_version(), 2);
        assert_eq!(manifest.layers().len(), 2);
        assert_eq!(
            manifest.layers()[0].digest().to_string(),
            "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        );
    }

    #[test]
    fn test_layer_id_extraction() {
        let manifest_json = r#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "size": 100
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
                    "size": 1000
                }
            ]
        }"#;

        let manifest: ImageManifest = serde_json::from_str(manifest_json).unwrap();

        let layer_ids: Vec<String> = manifest
            .layers()
            .iter()
            .map(|d| {
                let digest = d.digest().to_string();
                digest
                    .strip_prefix("sha256:")
                    .unwrap_or(&digest)
                    .to_string()
            })
            .collect();

        assert_eq!(
            layer_ids[0],
            "abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
        );
    }
}
