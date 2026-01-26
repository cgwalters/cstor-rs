//! Image store operations for containers-storage compatibility.
//!
//! This module provides the [`ImageStore`] struct for creating, deleting, and
//! managing images in containers-storage format. It handles:
//!
//! - Image creation with proper directory structure
//! - Image deletion with cleanup
//! - Reading and writing `images.json` atomically
//! - Big data management (manifest, config, etc.)
//! - Image name/tag management
//!
//! # Compatibility
//!
//! This implementation is designed to be compatible with the Go-based
//! containers/storage library. Images created here can be read by podman,
//! buildah, and other tools using containers/storage.
//!
//! # Example
//!
//! ```no_run
//! use cstor_rs::Storage;
//!
//! let storage = Storage::open_writable("/var/lib/containers/storage")?;
//! let image_store = storage.image_store();
//!
//! // Create an image
//! let manifest = br#"{"schemaVersion":2}"#;
//! let config = br#"{"architecture":"amd64"}"#;
//! let image = image_store.create_image(
//!     None,
//!     "abc123...",  // top layer ID
//!     manifest,
//!     config,
//!     &["docker.io/library/alpine:latest"],
//! )?;
//! println!("Created image: {}", image.id);
//!
//! // List all images
//! for image in image_store.list_images()? {
//!     println!("Image: {} (names: {:?})", image.id, image.names);
//! }
//!
//! // Delete an image
//! image_store.delete_image(&image.id)?;
//! # Ok::<(), cstor_rs::StorageError>(())
//! ```

use std::collections::HashMap;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Result, StorageError};
use crate::layer_store::generate_layer_id;
use crate::storage::Storage;

/// An image record as stored in `images.json`.
///
/// This struct matches the JSON schema used by containers/storage for image
/// metadata. All fields except `id` are optional to handle partial records.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct ImageRecord {
    /// Unique image identifier (64-character hex string, typically config digest).
    pub id: String,

    /// Digest of the image manifest (with algorithm prefix, e.g., "sha256:...").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,

    /// Image names/tags (e.g., "docker.io/library/alpine:latest").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,

    /// Top layer storage ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<String>,

    /// User-defined metadata string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,

    /// List of big data keys stored for this image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub big_data_names: Option<Vec<String>>,

    /// Sizes of big data items by key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub big_data_sizes: Option<HashMap<String, i64>>,

    /// Digests of big data items by key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub big_data_digests: Option<HashMap<String, String>>,

    /// Creation timestamp in RFC3339 format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
}

impl ImageRecord {
    /// Create a new image record with the given ID.
    pub fn new(id: String) -> Self {
        Self {
            id,
            digest: None,
            names: None,
            layer: None,
            metadata: None,
            big_data_names: None,
            big_data_sizes: None,
            big_data_digests: None,
            created: None,
        }
    }
}

/// Image store for managing images in containers-storage.
///
/// This provides operations for creating, deleting, and listing images
/// while maintaining compatibility with the containers/storage format.
#[derive(Debug)]
pub struct ImageStore<'a> {
    storage: &'a Storage,
}

impl<'a> ImageStore<'a> {
    /// Create a new image store backed by the given storage.
    pub fn new(storage: &'a Storage) -> Self {
        Self { storage }
    }

    /// Create a new image with manifest and config.
    ///
    /// # Arguments
    ///
    /// * `id` - Optional image ID; if None, derived from config digest
    /// * `top_layer_id` - Storage ID of the top layer
    /// * `manifest` - OCI image manifest bytes
    /// * `config` - OCI image configuration bytes
    /// * `names` - Image names/tags
    ///
    /// # Returns
    ///
    /// The created image record.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The storage is read-only
    /// - The top layer doesn't exist
    /// - Directory creation fails
    /// - JSON serialization fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::open_writable("/var/lib/containers/storage")?;
    /// let image_store = storage.image_store();
    ///
    /// let manifest = br#"{"schemaVersion":2}"#;
    /// let config = br#"{"architecture":"amd64"}"#;
    ///
    /// let image = image_store.create_image(
    ///     None,
    ///     "abc123def456...",
    ///     manifest,
    ///     config,
    ///     &["myimage:latest"],
    /// )?;
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn create_image(
        &self,
        id: Option<&str>,
        top_layer_id: &str,
        manifest: &[u8],
        config: &[u8],
        names: &[&str],
    ) -> Result<ImageRecord> {
        // Compute config digest for image ID if not provided
        let config_digest = compute_sha256(config);
        let image_id = id
            .map(String::from)
            .unwrap_or_else(|| config_digest.clone());

        // Compute manifest digest
        let manifest_digest = format!("sha256:{}", compute_sha256(manifest));

        // Verify top layer exists
        let layer_store = self.storage.layer_store();
        if !layer_store.exists(top_layer_id)? {
            return Err(StorageError::LayerNotFound(top_layer_id.to_string()));
        }

        // Check if image already exists
        let images = self.load_images()?;
        if images.iter().any(|i| i.id == image_id) {
            return Err(StorageError::InvalidStorage(format!(
                "image {} already exists",
                image_id
            )));
        }

        // Create image directory: overlay-images/<image-id>/
        let images_dir = self.storage.root_dir().open_dir("overlay-images")?;
        images_dir.create_dir(&image_id)?;
        let image_dir = images_dir.open_dir(&image_id)?;

        // Write manifest as "manifest" file
        image_dir.write("manifest", manifest)?;

        // Write config with base64-encoded key: =<base64("sha256:<id>")>
        let config_key = format!("sha256:{}", image_id);
        let encoded_key = STANDARD.encode(config_key.as_bytes());
        let config_filename = format!("={}", encoded_key);
        image_dir.write(&config_filename, config)?;

        // Build big data tracking
        let big_data_names = vec!["manifest".to_string(), config_key.clone()];
        let mut big_data_sizes = HashMap::new();
        let mut big_data_digests = HashMap::new();

        big_data_sizes.insert("manifest".to_string(), manifest.len() as i64);
        big_data_digests.insert("manifest".to_string(), manifest_digest.clone());

        big_data_sizes.insert(config_key.clone(), config.len() as i64);
        big_data_digests.insert(
            config_key.clone(),
            format!("sha256:{}", compute_sha256(config)),
        );

        // Create the image record
        let mut record = ImageRecord::new(image_id.clone());
        record.digest = Some(manifest_digest);
        record.layer = Some(top_layer_id.to_string());
        record.created = Some(chrono::Utc::now().to_rfc3339());

        if !names.is_empty() {
            record.names = Some(names.iter().map(|s| s.to_string()).collect());
        }

        record.big_data_names = Some(big_data_names);
        record.big_data_sizes = Some(big_data_sizes);
        record.big_data_digests = Some(big_data_digests);

        // Add to images.json
        let mut images = self.load_images()?;
        images.push(record.clone());
        self.save_images(&images)?;

        Ok(record)
    }

    /// Delete an image.
    ///
    /// This removes the image from `images.json` and deletes the image directory.
    ///
    /// # Arguments
    ///
    /// * `id` - The image ID to delete
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The image doesn't exist
    /// - Directory deletion fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::open_writable("/var/lib/containers/storage")?;
    /// let image_store = storage.image_store();
    /// image_store.delete_image("abc123...")?;
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn delete_image(&self, id: &str) -> Result<()> {
        let images = self.load_images()?;

        // Check that the image exists
        if !images.iter().any(|i| i.id == id) {
            return Err(StorageError::ImageNotFound(id.to_string()));
        }

        // Remove from images.json
        let images: Vec<ImageRecord> = images.into_iter().filter(|i| i.id != id).collect();
        self.save_images(&images)?;

        // Delete image directory
        let images_dir = self.storage.root_dir().open_dir("overlay-images")?;
        images_dir.remove_dir_all(id)?;

        Ok(())
    }

    /// List all images.
    ///
    /// # Returns
    ///
    /// A vector of all image records from `images.json`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::open("/var/lib/containers/storage")?;
    /// let image_store = storage.image_store();
    /// for image in image_store.list_images()? {
    ///     println!("Image: {}", image.id);
    /// }
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn list_images(&self) -> Result<Vec<ImageRecord>> {
        self.load_images()
    }

    /// Get a specific image by ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The image ID to look up
    ///
    /// # Returns
    ///
    /// The image record if found.
    ///
    /// # Errors
    ///
    /// Returns `ImageNotFound` if the image doesn't exist.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::open("/var/lib/containers/storage")?;
    /// let image_store = storage.image_store();
    /// let image = image_store.get_image("abc123...")?;
    /// println!("Image layer: {:?}", image.layer);
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn get_image(&self, id: &str) -> Result<ImageRecord> {
        let images = self.load_images()?;
        images
            .into_iter()
            .find(|i| i.id == id)
            .ok_or_else(|| StorageError::ImageNotFound(id.to_string()))
    }

    /// Add a name/tag to an image.
    ///
    /// # Arguments
    ///
    /// * `id` - The image ID
    /// * `name` - The name to add (e.g., "docker.io/library/alpine:latest")
    ///
    /// # Errors
    ///
    /// Returns an error if the image doesn't exist.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::open_writable("/var/lib/containers/storage")?;
    /// let image_store = storage.image_store();
    /// image_store.add_name("abc123...", "myimage:v2")?;
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn add_name(&self, id: &str, name: &str) -> Result<()> {
        let mut images = self.load_images()?;

        // Find the image and add the name
        let mut found = false;
        for image in &mut images {
            if image.id == id {
                let names = image.names.get_or_insert_with(Vec::new);
                if !names.contains(&name.to_string()) {
                    names.push(name.to_string());
                }
                found = true;
                break;
            }
        }

        if !found {
            return Err(StorageError::ImageNotFound(id.to_string()));
        }

        self.save_images(&images)?;
        Ok(())
    }

    /// Remove a name/tag from an image.
    ///
    /// # Arguments
    ///
    /// * `id` - The image ID
    /// * `name` - The name to remove
    ///
    /// # Errors
    ///
    /// Returns an error if the image doesn't exist.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::open_writable("/var/lib/containers/storage")?;
    /// let image_store = storage.image_store();
    /// image_store.remove_name("abc123...", "myimage:old")?;
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn remove_name(&self, id: &str, name: &str) -> Result<()> {
        let mut images = self.load_images()?;

        // Find the image and remove the name
        let mut found = false;
        for image in &mut images {
            if image.id == id {
                if let Some(names) = &mut image.names {
                    names.retain(|n| n != name);
                    if names.is_empty() {
                        image.names = None;
                    }
                }
                found = true;
                break;
            }
        }

        if !found {
            return Err(StorageError::ImageNotFound(id.to_string()));
        }

        self.save_images(&images)?;
        Ok(())
    }

    /// Check if an image exists.
    pub fn exists(&self, id: &str) -> Result<bool> {
        let images = self.load_images()?;
        Ok(images.iter().any(|i| i.id == id))
    }

    /// Find an image by name.
    ///
    /// # Arguments
    ///
    /// * `name` - The image name to search for
    ///
    /// # Returns
    ///
    /// The image record if found.
    ///
    /// # Errors
    ///
    /// Returns `ImageNotFound` if no image with that name exists.
    pub fn find_by_name(&self, name: &str) -> Result<ImageRecord> {
        let images = self.load_images()?;

        // Exact match first
        for image in &images {
            if let Some(names) = &image.names {
                if names.iter().any(|n| n == name) {
                    return Ok(image.clone());
                }
            }
        }

        // Partial match (e.g., "alpine:latest" matches "docker.io/library/alpine:latest")
        for image in &images {
            if let Some(names) = &image.names {
                for image_name in names {
                    if image_name.ends_with(name) {
                        let prefix = &image_name[..image_name.len() - name.len()];
                        if prefix.is_empty() || prefix.ends_with('/') {
                            return Ok(image.clone());
                        }
                    }
                }
            }
        }

        Err(StorageError::ImageNotFound(name.to_string()))
    }

    /// Load images from `images.json`.
    fn load_images(&self) -> Result<Vec<ImageRecord>> {
        let images_dir = self.storage.root_dir().open_dir("overlay-images")?;

        match images_dir.read_to_string("images.json") {
            Ok(content) => {
                let images: Vec<ImageRecord> = serde_json::from_str(&content)?;
                Ok(images)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    /// Save images to `images.json` atomically.
    ///
    /// This writes to a temporary file first, then renames it to ensure
    /// atomic updates.
    fn save_images(&self, images: &[ImageRecord]) -> Result<()> {
        let images_dir = self.storage.root_dir().open_dir("overlay-images")?;

        let json = serde_json::to_string_pretty(images)?;

        // Atomic write via temp file
        let temp_name = format!("images.json.{}.tmp", generate_layer_id());
        images_dir.write(&temp_name, json.as_bytes())?;
        images_dir.rename(&temp_name, &images_dir, "images.json")?;

        Ok(())
    }
}

/// Compute SHA256 hash and return as hex string.
fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// Add helper method to Storage
impl Storage {
    /// Get an image store for managing images.
    ///
    /// This provides access to image creation, deletion, and listing operations.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::open("/var/lib/containers/storage")?;
    /// let image_store = storage.image_store();
    ///
    /// for image in image_store.list_images()? {
    ///     println!("Image: {}", image.id);
    /// }
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn image_store(&self) -> ImageStore<'_> {
        ImageStore::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_image_record_new() {
        let record = ImageRecord::new("test123".to_string());
        assert_eq!(record.id, "test123");
        assert!(record.digest.is_none());
        assert!(record.names.is_none());
        assert!(record.layer.is_none());
        assert!(record.metadata.is_none());
        assert!(record.big_data_names.is_none());
        assert!(record.big_data_sizes.is_none());
        assert!(record.big_data_digests.is_none());
        assert!(record.created.is_none());
    }

    #[test]
    fn test_image_record_serialization() {
        let mut record = ImageRecord::new("abc123".to_string());
        record.digest = Some("sha256:def456".to_string());
        record.names = Some(vec!["alpine:latest".to_string()]);
        record.layer = Some("layer789".to_string());
        record.created = Some("2024-01-01T00:00:00Z".to_string());

        let json = serde_json::to_string(&record).unwrap();
        let parsed: ImageRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id, "abc123");
        assert_eq!(parsed.digest, Some("sha256:def456".to_string()));
        assert_eq!(parsed.names, Some(vec!["alpine:latest".to_string()]));
        assert_eq!(parsed.layer, Some("layer789".to_string()));
        assert_eq!(parsed.created, Some("2024-01-01T00:00:00Z".to_string()));
    }

    #[test]
    fn test_image_record_kebab_case() {
        // Verify that kebab-case serialization works correctly
        let mut record = ImageRecord::new("test".to_string());
        record.big_data_names = Some(vec!["manifest".to_string()]);
        record.big_data_sizes = Some(HashMap::from([("manifest".to_string(), 1024)]));
        record.big_data_digests = Some(HashMap::from([(
            "manifest".to_string(),
            "sha256:abc".to_string(),
        )]));

        let json = serde_json::to_string(&record).unwrap();

        // Check that the JSON uses kebab-case
        assert!(json.contains("big-data-names"));
        assert!(json.contains("big-data-sizes"));
        assert!(json.contains("big-data-digests"));
    }

    #[test]
    fn test_image_record_skip_none_fields() {
        let record = ImageRecord::new("test".to_string());
        let json = serde_json::to_string(&record).unwrap();

        // Only 'id' should be present
        assert!(json.contains("\"id\""));
        assert!(!json.contains("\"digest\""));
        assert!(!json.contains("\"names\""));
        assert!(!json.contains("\"layer\""));
        assert!(!json.contains("\"metadata\""));
    }

    #[test]
    fn test_compute_sha256() {
        let data = b"hello world";
        let hash = compute_sha256(data);
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_image_record_with_big_data() {
        let mut record = ImageRecord::new("abc123".to_string());
        record.big_data_names = Some(vec!["manifest".to_string(), "sha256:abc123".to_string()]);

        let mut sizes = HashMap::new();
        sizes.insert("manifest".to_string(), 1024);
        sizes.insert("sha256:abc123".to_string(), 2048);
        record.big_data_sizes = Some(sizes);

        let mut digests = HashMap::new();
        digests.insert("manifest".to_string(), "sha256:manifestdigest".to_string());
        digests.insert(
            "sha256:abc123".to_string(),
            "sha256:configdigest".to_string(),
        );
        record.big_data_digests = Some(digests);

        let json = serde_json::to_string_pretty(&record).unwrap();
        let parsed: ImageRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.big_data_names.as_ref().unwrap().len(), 2);
        assert_eq!(
            parsed
                .big_data_sizes
                .as_ref()
                .unwrap()
                .get("manifest")
                .copied(),
            Some(1024)
        );
        assert_eq!(
            parsed.big_data_digests.as_ref().unwrap().get("manifest"),
            Some(&"sha256:manifestdigest".to_string())
        );
    }

    #[test]
    fn test_image_record_roundtrip_with_all_fields() {
        let mut record = ImageRecord::new("fulltest".to_string());
        record.digest = Some("sha256:manifestdig".to_string());
        record.names = Some(vec![
            "docker.io/library/alpine:latest".to_string(),
            "alpine:latest".to_string(),
        ]);
        record.layer = Some("toplayer123".to_string());
        record.metadata = Some("custom metadata".to_string());
        record.big_data_names = Some(vec!["manifest".to_string()]);
        record.big_data_sizes = Some(HashMap::from([("manifest".to_string(), 512)]));
        record.big_data_digests = Some(HashMap::from([(
            "manifest".to_string(),
            "sha256:x".to_string(),
        )]));
        record.created = Some("2024-06-15T12:30:00Z".to_string());

        let json = serde_json::to_string(&record).unwrap();
        let parsed: ImageRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(record, parsed);
    }
}
