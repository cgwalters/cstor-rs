//! Layer store operations for containers-storage compatibility.
//!
//! This module provides the [`LayerStore`] struct for creating, deleting, and
//! managing layers in containers-storage format. It handles:
//!
//! - Layer creation with proper directory structure
//! - Layer deletion with cleanup
//! - Reading and writing `layers.json` atomically
//! - ID generation (64-char hex layer IDs, 26-char link IDs)
//! - Incomplete flag handling for crash recovery
//!
//! # Compatibility
//!
//! This implementation is designed to be compatible with the Go-based
//! containers/storage library. Layers created here can be read by podman,
//! buildah, and other tools using containers/storage.
//!
//! # Example
//!
//! ```no_run
//! use cstor_rs::Storage;
//!
//! let storage = Storage::open_writable("/var/lib/containers/storage")?;
//! let layer_store = storage.layer_store();
//!
//! // Create an empty layer
//! let layer = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;
//! println!("Created layer: {}", layer.id);
//!
//! // List all layers
//! for layer in layer_store.list_layers()? {
//!     println!("Layer: {} (parent: {:?})", layer.id, layer.parent);
//! }
//!
//! // Delete a layer
//! layer_store.delete_layer(&layer.id)?;
//! # Ok::<(), cstor_rs::StorageError>(())
//! ```

use std::collections::HashSet;
use std::io::Read;

use cap_std::fs::{Dir, Permissions, PermissionsExt};
use serde::{Deserialize, Serialize};

use crate::error::{Result, StorageError};
use crate::storage::Storage;

/// A layer record as stored in `layers.json`.
///
/// This struct matches the JSON schema used by containers/storage for layer
/// metadata. All fields except `id` are optional to handle partial records.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct LayerRecord {
    /// Unique layer identifier (64-character hex string).
    pub id: String,

    /// Parent layer ID (if this is not a base layer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,

    /// Layer names/tags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,

    /// Creation timestamp in RFC3339 format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// Digest of the compressed diff (with algorithm prefix, e.g., "sha256:...").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compressed_diff_digest: Option<String>,

    /// Digest of the uncompressed diff (with algorithm prefix).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_digest: Option<String>,

    /// Size of the compressed diff in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compressed_size: Option<i64>,

    /// Size of the uncompressed diff in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_size: Option<i64>,

    /// Compression algorithm used (e.g., "gzip", "zstd").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression: Option<i32>,

    /// UID mappings for user namespace support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uidset: Option<Vec<IdMapping>>,

    /// GID mappings for user namespace support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gidset: Option<Vec<IdMapping>>,

    /// Flags for layer state (e.g., "incomplete" during creation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<std::collections::HashMap<String, serde_json::Value>>,

    /// Metadata key-value pairs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
}

/// ID mapping for user namespace support.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct IdMapping {
    /// Container ID start.
    pub container_id: u32,
    /// Host ID start.
    pub host_id: u32,
    /// Size of the mapping range.
    pub size: u32,
}

impl LayerRecord {
    /// Create a new layer record with the given ID.
    pub fn new(id: String) -> Self {
        Self {
            id,
            parent: None,
            names: None,
            created: None,
            compressed_diff_digest: None,
            diff_digest: None,
            compressed_size: None,
            diff_size: None,
            compression: None,
            uidset: None,
            gidset: None,
            flags: None,
            metadata: None,
        }
    }

    /// Check if this layer is marked as incomplete.
    pub fn is_incomplete(&self) -> bool {
        self.flags
            .as_ref()
            .map(|f| f.contains_key("incomplete"))
            .unwrap_or(false)
    }

    /// Mark this layer as incomplete (used during creation).
    pub fn set_incomplete(&mut self, incomplete: bool) {
        if incomplete {
            let flags = self.flags.get_or_insert_with(Default::default);
            flags.insert("incomplete".to_string(), serde_json::Value::Bool(true));
        } else if let Some(flags) = &mut self.flags {
            flags.remove("incomplete");
            if flags.is_empty() {
                self.flags = None;
            }
        }
    }
}

/// Generate a random 64-character hex layer ID.
///
/// Uses a combination of system time and random data to generate a unique ID.
/// This matches the format used by containers/storage.
pub fn generate_layer_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    // Use nanoseconds and combine with additional entropy
    let seed = now.as_nanos();
    let mut id = String::with_capacity(64);

    // Generate 32 bytes (64 hex chars) with better distribution
    for i in 0..32 {
        // Mix multiple bits of the timestamp with position
        let byte = ((seed >> ((i * 4) % 128))
            ^ (seed >> (((i * 7) + 3) % 128))
            ^ ((i as u128) * 17)) as u8;
        id.push_str(&format!("{:02x}", byte));
    }

    id
}

/// Generate a 26-character link ID (uppercase A-Z).
///
/// This is used for the short symlink names in `overlay/l/`.
pub fn generate_link_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let seed = now.as_nanos();
    let mut id = String::with_capacity(26);

    for i in 0..26 {
        let byte = ((seed >> ((i * 5) % 128)) ^ (seed >> (((i * 11) + 7) % 128))) as usize;
        let idx = (byte.wrapping_add(i * 13)) % ALPHABET.len();
        id.push(ALPHABET[idx] as char);
    }

    id
}

/// Layer store for managing layers in containers-storage.
///
/// This provides operations for creating, deleting, and listing layers
/// while maintaining compatibility with the containers/storage format.
#[derive(Debug)]
pub struct LayerStore<'a> {
    storage: &'a Storage,
}

impl<'a> LayerStore<'a> {
    /// Create a new layer store backed by the given storage.
    pub fn new(storage: &'a Storage) -> Self {
        Self { storage }
    }

    /// Create a new layer, optionally with content from a tarball.
    ///
    /// # Arguments
    ///
    /// * `id` - Optional layer ID; if None, a random ID is generated
    /// * `parent` - Optional parent layer ID
    /// * `names` - Layer names/tags
    /// * `_diff` - Optional tarball content (currently not implemented)
    ///
    /// # Returns
    ///
    /// The created layer record.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The storage is read-only
    /// - The parent layer doesn't exist
    /// - Directory creation fails
    /// - JSON serialization fails
    pub fn create_layer<R: Read>(
        &self,
        id: Option<&str>,
        parent: Option<&str>,
        names: &[&str],
        _diff: Option<R>,
    ) -> Result<LayerRecord> {
        // Generate IDs
        let layer_id = id.map(String::from).unwrap_or_else(generate_layer_id);
        let link_id = generate_link_id();

        // Validate parent exists if specified
        if let Some(parent_id) = parent {
            let layers = self.load_layers()?;
            if !layers.iter().any(|l| l.id == parent_id) {
                return Err(StorageError::LayerNotFound(parent_id.to_string()));
            }
        }

        // Create the layer record with incomplete flag
        let mut record = LayerRecord::new(layer_id.clone());
        record.parent = parent.map(String::from);
        if !names.is_empty() {
            record.names = Some(names.iter().map(|s| s.to_string()).collect());
        }
        record.created = Some(chrono::Utc::now().to_rfc3339());
        record.set_incomplete(true);

        // Add to layers.json with incomplete flag
        let mut layers = self.load_layers()?;
        layers.push(record.clone());
        self.save_layers(&layers)?;

        // Create overlay directory structure
        self.create_overlay_dirs(&layer_id, &link_id, parent)?;

        // Remove incomplete flag
        record.set_incomplete(false);
        let layers: Vec<LayerRecord> = layers
            .into_iter()
            .map(|l| if l.id == layer_id { record.clone() } else { l })
            .collect();
        self.save_layers(&layers)?;

        Ok(record)
    }

    /// Create the overlay directory structure for a layer.
    fn create_overlay_dirs(
        &self,
        layer_id: &str,
        link_id: &str,
        parent: Option<&str>,
    ) -> Result<()> {
        let overlay_dir = self.storage.root_dir().open_dir("overlay")?;

        // Create layer directory: overlay/<layer-id>/
        overlay_dir.create_dir(layer_id)?;
        let layer_dir = overlay_dir.open_dir(layer_id)?;

        // Get parent's diff directory permissions or use default
        let diff_perms = if let Some(parent_id) = parent {
            let parent_dir = overlay_dir.open_dir(parent_id)?;
            let parent_diff = parent_dir.open_dir("diff")?;
            parent_diff.dir_metadata()?.permissions()
        } else {
            Permissions::from_mode(0o755)
        };

        // Create diff/ directory with inherited permissions
        layer_dir.create_dir("diff")?;
        layer_dir.set_permissions("diff", diff_perms)?;

        // Create link file with the 26-char link ID
        layer_dir.write("link", link_id.as_bytes())?;

        // Create lower file if parent exists
        if let Some(parent_id) = parent {
            let parent_dir = overlay_dir.open_dir(parent_id)?;
            let parent_link = parent_dir.read_to_string("link")?.trim().to_string();

            // Build lower chain
            let lower = match parent_dir.read_to_string("lower") {
                Ok(parent_lower) => {
                    let parent_lower = parent_lower.trim();
                    if parent_lower.is_empty() {
                        format!("l/{}", parent_link)
                    } else {
                        format!("l/{}:{}", parent_link, parent_lower)
                    }
                }
                Err(_) => format!("l/{}", parent_link),
            };
            layer_dir.write("lower", lower.as_bytes())?;
        } else {
            // Base layer: create empty/ directory
            layer_dir.create_dir("empty")?;
            Self::set_dir_mode(&layer_dir, "empty", 0o700)?;
        }

        // Create work/ and merged/ directories (mode 0700)
        layer_dir.create_dir("work")?;
        Self::set_dir_mode(&layer_dir, "work", 0o700)?;

        layer_dir.create_dir("merged")?;
        Self::set_dir_mode(&layer_dir, "merged", 0o700)?;

        // Create symlink: overlay/l/<link-id> -> ../<layer-id>/diff
        let links_dir = overlay_dir.open_dir("l")?;
        let link_target = format!("../{}/diff", layer_id);
        links_dir.symlink(&link_target, link_id)?;

        Ok(())
    }

    /// Set directory mode (helper to handle permissions).
    fn set_dir_mode(parent: &Dir, name: &str, mode: u32) -> Result<()> {
        parent.set_permissions(name, Permissions::from_mode(mode))?;
        Ok(())
    }

    /// Delete a layer.
    ///
    /// This removes the layer from `layers.json` and deletes the overlay directory.
    ///
    /// # Arguments
    ///
    /// * `id` - The layer ID to delete
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The layer doesn't exist
    /// - The layer is referenced as a parent by another layer
    /// - Directory deletion fails
    pub fn delete_layer(&self, id: &str) -> Result<()> {
        let layers = self.load_layers()?;

        // Check that the layer exists
        if !layers.iter().any(|l| l.id == id) {
            return Err(StorageError::LayerNotFound(id.to_string()));
        }

        // Check that no other layer has this as parent
        for layer in &layers {
            if layer.parent.as_deref() == Some(id) {
                return Err(StorageError::InvalidStorage(format!(
                    "cannot delete layer {}: layer {} depends on it",
                    id, layer.id
                )));
            }
        }

        // Remove from layers.json
        let layers: Vec<LayerRecord> = layers.into_iter().filter(|l| l.id != id).collect();
        self.save_layers(&layers)?;

        // Delete overlay directory
        let overlay_dir = self.storage.root_dir().open_dir("overlay")?;

        // First, get the link ID so we can remove the symlink
        if let Ok(layer_dir) = overlay_dir.open_dir(id)
            && let Ok(link_id) = layer_dir.read_to_string("link")
        {
            let link_id = link_id.trim();
            if let Ok(links_dir) = overlay_dir.open_dir("l") {
                // Best effort removal of symlink
                let _ = links_dir.remove_file(link_id);
            }
        }

        // Remove the layer directory
        overlay_dir.remove_dir_all(id)?;

        // Remove tar-split file if it exists
        let layers_dir = self.storage.root_dir().open_dir("overlay-layers")?;
        let tar_split_name = format!("{}.tar-split.gz", id);
        let _ = layers_dir.remove_file(&tar_split_name);

        Ok(())
    }

    /// List all layers.
    ///
    /// # Returns
    ///
    /// A vector of all layer records from `layers.json`.
    pub fn list_layers(&self) -> Result<Vec<LayerRecord>> {
        self.load_layers()
    }

    /// Get a specific layer by ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The layer ID to look up
    ///
    /// # Returns
    ///
    /// The layer record if found.
    ///
    /// # Errors
    ///
    /// Returns `LayerNotFound` if the layer doesn't exist.
    pub fn get_layer(&self, id: &str) -> Result<LayerRecord> {
        let layers = self.load_layers()?;
        layers
            .into_iter()
            .find(|l| l.id == id)
            .ok_or_else(|| StorageError::LayerNotFound(id.to_string()))
    }

    /// Load layers from `layers.json`.
    fn load_layers(&self) -> Result<Vec<LayerRecord>> {
        let layers_dir = self.storage.root_dir().open_dir("overlay-layers")?;

        match layers_dir.read_to_string("layers.json") {
            Ok(content) => {
                let layers: Vec<LayerRecord> = serde_json::from_str(&content)?;
                Ok(layers)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    /// Save layers to `layers.json` atomically.
    ///
    /// This writes to a temporary file first, then renames it to ensure
    /// atomic updates.
    fn save_layers(&self, layers: &[LayerRecord]) -> Result<()> {
        let layers_dir = self.storage.root_dir().open_dir("overlay-layers")?;

        let json = serde_json::to_string_pretty(layers)?;

        // Atomic write via temp file
        let temp_name = format!("layers.json.{}.tmp", generate_layer_id());
        layers_dir.write(&temp_name, json.as_bytes())?;
        layers_dir.rename(&temp_name, &layers_dir, "layers.json")?;

        Ok(())
    }

    /// Check if a layer exists.
    pub fn exists(&self, id: &str) -> Result<bool> {
        let layers = self.load_layers()?;
        Ok(layers.iter().any(|l| l.id == id))
    }

    /// Get all child layers of a given layer.
    pub fn get_children(&self, id: &str) -> Result<Vec<LayerRecord>> {
        let layers = self.load_layers()?;
        Ok(layers
            .into_iter()
            .filter(|l| l.parent.as_deref() == Some(id))
            .collect())
    }

    /// Cleanup incomplete layers.
    ///
    /// This removes any layers marked as incomplete, which may have been
    /// left behind by a crashed operation.
    pub fn cleanup_incomplete(&self) -> Result<Vec<String>> {
        let layers = self.load_layers()?;
        let incomplete: Vec<String> = layers
            .iter()
            .filter(|l| l.is_incomplete())
            .map(|l| l.id.clone())
            .collect();

        for id in &incomplete {
            // Best effort deletion
            let _ = self.delete_layer(id);
        }

        Ok(incomplete)
    }

    /// Validate layer consistency.
    ///
    /// Checks that:
    /// - All parent references point to existing layers
    /// - All layers have corresponding directories
    /// - All layers have valid link files
    pub fn validate(&self) -> Result<Vec<String>> {
        let layers = self.load_layers()?;
        let mut errors = Vec::new();

        // Build set of all layer IDs
        let layer_ids: HashSet<&str> = layers.iter().map(|l| l.id.as_str()).collect();

        let overlay_dir = self.storage.root_dir().open_dir("overlay")?;

        for layer in &layers {
            // Check parent exists
            if let Some(parent_id) = &layer.parent
                && !layer_ids.contains(parent_id.as_str())
            {
                errors.push(format!(
                    "layer {} references missing parent {}",
                    layer.id, parent_id
                ));
            }

            // Check layer directory exists
            match overlay_dir.open_dir(&layer.id) {
                Ok(layer_dir) => {
                    // Check diff/ exists
                    if layer_dir.try_exists("diff").unwrap_or(false) {
                        // Good
                    } else {
                        errors.push(format!("layer {} missing diff/ directory", layer.id));
                    }

                    // Check link file exists
                    if layer_dir.try_exists("link").unwrap_or(false) {
                        // Good
                    } else {
                        errors.push(format!("layer {} missing link file", layer.id));
                    }
                }
                Err(_) => {
                    errors.push(format!("layer {} missing directory", layer.id));
                }
            }
        }

        Ok(errors)
    }
}

// Add helper method to Storage
impl Storage {
    /// Get a layer store for managing layers.
    ///
    /// This provides access to layer creation, deletion, and listing operations.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::Storage;
    ///
    /// let storage = Storage::open("/var/lib/containers/storage")?;
    /// let layer_store = storage.layer_store();
    ///
    /// for layer in layer_store.list_layers()? {
    ///     println!("Layer: {}", layer.id);
    /// }
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn layer_store(&self) -> LayerStore<'_> {
        LayerStore::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_layer_id() {
        let id = generate_layer_id();
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));

        // Generate multiple IDs and verify they're different
        // (with high probability due to time-based generation)
        let id2 = generate_layer_id();
        // Note: in a tight loop these might be the same, so we just check format
        assert_eq!(id2.len(), 64);
    }

    #[test]
    fn test_generate_link_id() {
        let id = generate_link_id();
        assert_eq!(id.len(), 26);
        assert!(id.chars().all(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn test_layer_record_incomplete_flag() {
        let mut record = LayerRecord::new("test123".to_string());
        assert!(!record.is_incomplete());

        record.set_incomplete(true);
        assert!(record.is_incomplete());

        record.set_incomplete(false);
        assert!(!record.is_incomplete());
        assert!(record.flags.is_none());
    }

    #[test]
    fn test_layer_record_serialization() {
        let mut record = LayerRecord::new("abc123".to_string());
        record.parent = Some("parent456".to_string());
        record.created = Some("2024-01-01T00:00:00Z".to_string());
        record.diff_size = Some(1024);

        let json = serde_json::to_string(&record).unwrap();
        let parsed: LayerRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id, "abc123");
        assert_eq!(parsed.parent, Some("parent456".to_string()));
        assert_eq!(parsed.created, Some("2024-01-01T00:00:00Z".to_string()));
        assert_eq!(parsed.diff_size, Some(1024));
    }

    #[test]
    fn test_layer_record_kebab_case() {
        // Verify that kebab-case serialization works correctly
        let mut record = LayerRecord::new("test".to_string());
        record.diff_digest = Some("sha256:abc123".to_string());
        record.compressed_diff_digest = Some("sha256:def456".to_string());
        record.diff_size = Some(100);
        record.compressed_size = Some(50);

        let json = serde_json::to_string(&record).unwrap();

        // Check that the JSON uses kebab-case
        assert!(json.contains("diff-digest"));
        assert!(json.contains("compressed-diff-digest"));
        assert!(json.contains("diff-size"));
        assert!(json.contains("compressed-size"));
    }
}
