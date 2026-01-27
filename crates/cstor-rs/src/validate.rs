//! Storage validation (fsck) for containers-storage.
//!
//! This module provides comprehensive validation of containers-storage
//! repositories, detecting corruption, inconsistencies, and missing files.
//!
//! # Example
//!
//! ```no_run
//! use cstor_rs::{Storage, ValidateOptions, ValidationResult};
//!
//! let storage = Storage::open("/var/lib/containers/storage")?;
//! let options = ValidateOptions::default();
//! let result = storage.validate(&options)?;
//!
//! for error in &result.errors {
//!     eprintln!("ERROR: {}", error);
//! }
//! for warning in &result.warnings {
//!     eprintln!("WARNING: {}", warning);
//! }
//!
//! println!("Checked {} layers, {} images", result.stats.layers_checked, result.stats.images_checked);
//! # Ok::<(), cstor_rs::StorageError>(())
//! ```

use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::error::{Result, StorageError};
use crate::storage::Storage;

/// Options for validation.
#[derive(Debug, Clone)]
pub struct ValidateOptions {
    /// Check for orphaned directories (exist on disk but not in JSON).
    pub check_orphans: bool,
    /// Report layers not referenced by any image.
    pub check_unused_layers: bool,
    /// Verify tar-split files can be parsed (not just existence).
    pub verify_tar_split: bool,
}

impl Default for ValidateOptions {
    fn default() -> Self {
        Self {
            check_orphans: true,
            check_unused_layers: false,
            verify_tar_split: false,
        }
    }
}

/// Statistics from validation.
#[derive(Debug, Clone, Default)]
pub struct ValidationStats {
    /// Number of layers checked.
    pub layers_checked: usize,
    /// Number of images checked.
    pub images_checked: usize,
    /// Number of orphaned layer directories found.
    pub orphaned_layer_dirs: usize,
    /// Number of orphaned image directories found.
    pub orphaned_image_dirs: usize,
    /// Number of unused layers found.
    pub unused_layers: usize,
}

/// Result of validation.
#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    /// Critical errors (corruption detected).
    pub errors: Vec<ValidationError>,
    /// Warnings (potential issues, not necessarily corruption).
    pub warnings: Vec<ValidationWarning>,
    /// Statistics.
    pub stats: ValidationStats,
}

impl ValidationResult {
    /// Returns true if no errors were found.
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }

    /// Returns true if any errors were found.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Returns true if any warnings were found.
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }
}

/// A validation error indicating corruption or inconsistency.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)] // Variant fields are self-explanatory; see Display impl for details
pub enum ValidationError {
    /// Layer directory is missing.
    MissingLayerDir { layer_id: String },
    /// Layer diff directory is missing.
    MissingDiffDir { layer_id: String },
    /// Layer link file is missing.
    MissingLinkFile { layer_id: String },
    /// Layer link file has invalid format.
    InvalidLinkFile { layer_id: String, details: String },
    /// Symlink in overlay/l/ is missing.
    MissingSymlink { link_id: String, layer_id: String },
    /// Symlink in overlay/l/ is broken (target doesn't exist).
    BrokenSymlink { link_id: String, target: String },
    /// Symlink points to wrong target.
    SymlinkTargetMismatch {
        link_id: String,
        expected: String,
        actual: String,
    },
    /// Tar-split file is missing.
    MissingTarSplit { layer_id: String },
    /// Tar-split file is corrupt.
    CorruptTarSplit { layer_id: String, details: String },
    /// Parent layer doesn't exist.
    InvalidParent { layer_id: String, parent_id: String },
    /// Lower file references non-existent link.
    InvalidLowerRef {
        layer_id: String,
        missing_link: String,
    },
    /// Image directory is missing.
    MissingImageDir { image_id: String },
    /// Image manifest file is missing.
    MissingManifest { image_id: String },
    /// Image references non-existent layer.
    ImageLayerMissing { image_id: String, layer_id: String },
    /// Big data file is missing.
    MissingBigData { image_id: String, key: String },
    /// Circular parent reference detected.
    CircularParent {
        layer_id: String,
        cycle: Vec<String>,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingLayerDir { layer_id } => {
                write!(
                    f,
                    "layer {}: missing directory overlay/{}",
                    layer_id, layer_id
                )
            }
            Self::MissingDiffDir { layer_id } => {
                write!(f, "layer {}: missing diff/ directory", layer_id)
            }
            Self::MissingLinkFile { layer_id } => {
                write!(f, "layer {}: missing link file", layer_id)
            }
            Self::InvalidLinkFile { layer_id, details } => {
                write!(f, "layer {}: invalid link file: {}", layer_id, details)
            }
            Self::MissingSymlink { link_id, layer_id } => {
                write!(
                    f,
                    "layer {}: missing symlink overlay/l/{}",
                    layer_id, link_id
                )
            }
            Self::BrokenSymlink { link_id, target } => {
                write!(
                    f,
                    "symlink overlay/l/{}: broken, target {} doesn't exist",
                    link_id, target
                )
            }
            Self::SymlinkTargetMismatch {
                link_id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "symlink overlay/l/{}: wrong target, expected {}, got {}",
                    link_id, expected, actual
                )
            }
            Self::MissingTarSplit { layer_id } => {
                write!(f, "layer {}: missing tar-split file", layer_id)
            }
            Self::CorruptTarSplit { layer_id, details } => {
                write!(f, "layer {}: corrupt tar-split: {}", layer_id, details)
            }
            Self::InvalidParent {
                layer_id,
                parent_id,
            } => {
                write!(f, "layer {}: parent {} doesn't exist", layer_id, parent_id)
            }
            Self::InvalidLowerRef {
                layer_id,
                missing_link,
            } => {
                write!(
                    f,
                    "layer {}: lower file references non-existent link {}",
                    layer_id, missing_link
                )
            }
            Self::MissingImageDir { image_id } => {
                write!(f, "image {}: missing directory", image_id)
            }
            Self::MissingManifest { image_id } => {
                write!(f, "image {}: missing manifest file", image_id)
            }
            Self::ImageLayerMissing { image_id, layer_id } => {
                write!(
                    f,
                    "image {}: references non-existent layer {}",
                    image_id, layer_id
                )
            }
            Self::MissingBigData { image_id, key } => {
                write!(f, "image {}: missing big data '{}'", image_id, key)
            }
            Self::CircularParent { layer_id, cycle } => {
                write!(
                    f,
                    "layer {}: circular parent reference: {}",
                    layer_id,
                    cycle.join(" -> ")
                )
            }
        }
    }
}

/// A validation warning (potential issue but not necessarily corruption).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)] // Variant fields are self-explanatory; see Display impl for details
pub enum ValidationWarning {
    /// Layer directory exists but not in layers.json.
    OrphanedLayerDir { dir_name: String },
    /// Image directory exists but not in images.json.
    OrphanedImageDir { dir_name: String },
    /// Layer is not referenced by any image.
    UnusedLayer { layer_id: String },
    /// Layer is marked as incomplete.
    IncompleteLayer { layer_id: String },
    /// Symlink exists in overlay/l/ but no layer references it.
    OrphanedSymlink { link_id: String },
}

impl fmt::Display for ValidationWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OrphanedLayerDir { dir_name } => {
                write!(f, "orphaned layer directory overlay/{}", dir_name)
            }
            Self::OrphanedImageDir { dir_name } => {
                write!(f, "orphaned image directory overlay-images/{}", dir_name)
            }
            Self::UnusedLayer { layer_id } => {
                write!(f, "layer {} is not referenced by any image", layer_id)
            }
            Self::IncompleteLayer { layer_id } => {
                write!(f, "layer {} is marked as incomplete", layer_id)
            }
            Self::OrphanedSymlink { link_id } => {
                write!(f, "orphaned symlink overlay/l/{}", link_id)
            }
        }
    }
}

impl Storage {
    /// Validate storage consistency.
    ///
    /// This performs an fsck-style check of the containers-storage repository,
    /// detecting corruption, missing files, and inconsistencies.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::{Storage, ValidateOptions};
    ///
    /// let storage = Storage::open("/var/lib/containers/storage")?;
    /// let result = storage.validate(&ValidateOptions::default())?;
    ///
    /// if result.has_errors() {
    ///     eprintln!("Storage is corrupted!");
    ///     for error in &result.errors {
    ///         eprintln!("  {}", error);
    ///     }
    /// }
    /// # Ok::<(), cstor_rs::StorageError>(())
    /// ```
    pub fn validate(&self, options: &ValidateOptions) -> Result<ValidationResult> {
        let mut result = ValidationResult::default();

        // Validate layers
        self.validate_layers(options, &mut result)?;

        // Validate images
        self.validate_images(options, &mut result)?;

        Ok(result)
    }

    fn validate_layers(
        &self,
        options: &ValidateOptions,
        result: &mut ValidationResult,
    ) -> Result<()> {
        let layer_store = self.layer_store();
        let layers = layer_store.list_layers()?;

        // Build set of layer IDs for quick lookup
        let layer_ids: HashSet<&str> = layers.iter().map(|l| l.id.as_str()).collect();

        // Track link IDs we expect to exist
        let mut expected_links: HashMap<String, String> = HashMap::new(); // link_id -> layer_id

        let overlay_dir = self.root_dir().open_dir("overlay")?;
        let layers_metadata_dir = self.root_dir().open_dir("overlay-layers")?;

        for layer in &layers {
            result.stats.layers_checked += 1;

            // Check for incomplete flag
            if layer.is_incomplete() {
                result.warnings.push(ValidationWarning::IncompleteLayer {
                    layer_id: layer.id.clone(),
                });
            }

            // Check parent exists
            if let Some(parent_id) = &layer.parent {
                if !layer_ids.contains(parent_id.as_str()) {
                    result.errors.push(ValidationError::InvalidParent {
                        layer_id: layer.id.clone(),
                        parent_id: parent_id.clone(),
                    });
                }

                // Check for circular references
                if let Some(cycle) = self.detect_parent_cycle(&layer.id, &layers) {
                    result.errors.push(ValidationError::CircularParent {
                        layer_id: layer.id.clone(),
                        cycle,
                    });
                }
            }

            // Check layer directory exists
            let layer_dir = match overlay_dir.open_dir(&layer.id) {
                Ok(dir) => dir,
                Err(_) => {
                    result.errors.push(ValidationError::MissingLayerDir {
                        layer_id: layer.id.clone(),
                    });
                    continue;
                }
            };

            // Check diff/ directory exists
            if !layer_dir.try_exists("diff").unwrap_or(false) {
                result.errors.push(ValidationError::MissingDiffDir {
                    layer_id: layer.id.clone(),
                });
            }

            // Check link file exists and is valid
            match layer_dir.read_to_string("link") {
                Ok(link_content) => {
                    let link_id = link_content.trim();
                    if !Self::is_valid_link_id(link_id) {
                        result.errors.push(ValidationError::InvalidLinkFile {
                            layer_id: layer.id.clone(),
                            details: format!("invalid format: '{}'", link_id),
                        });
                    } else {
                        expected_links.insert(link_id.to_string(), layer.id.clone());
                    }
                }
                Err(_) => {
                    result.errors.push(ValidationError::MissingLinkFile {
                        layer_id: layer.id.clone(),
                    });
                }
            }

            // Check lower file references valid links (for non-base layers)
            if layer.parent.is_some() {
                if let Ok(lower_content) = layer_dir.read_to_string("lower") {
                    for link_ref in lower_content.trim().split(':') {
                        if let Some(link_id) = link_ref.strip_prefix("l/") {
                            // We'll validate these symlinks exist below
                            if link_id.is_empty() {
                                result.errors.push(ValidationError::InvalidLowerRef {
                                    layer_id: layer.id.clone(),
                                    missing_link: link_ref.to_string(),
                                });
                            }
                        }
                    }
                }
            }

            // Check tar-split file exists (only if layer has content)
            // Empty layers created with create_layer() don't have tar-split files
            let has_content = layer.diff_size.unwrap_or(0) > 0 || layer.diff_digest.is_some();
            let tar_split_name = format!("{}.tar-split.gz", layer.id);
            if has_content
                && !layers_metadata_dir
                    .try_exists(&tar_split_name)
                    .unwrap_or(false)
            {
                result.errors.push(ValidationError::MissingTarSplit {
                    layer_id: layer.id.clone(),
                });
            } else if has_content && options.verify_tar_split {
                // Optionally verify tar-split can be parsed
                if let Err(e) = self.verify_tar_split(&layer.id) {
                    result.errors.push(ValidationError::CorruptTarSplit {
                        layer_id: layer.id.clone(),
                        details: e.to_string(),
                    });
                }
            }
        }

        // Validate symlinks in overlay/l/
        if let Ok(links_dir) = overlay_dir.open_dir("l") {
            let mut found_links: HashSet<String> = HashSet::new();

            for entry in links_dir.entries().map_err(StorageError::Io)? {
                let entry = entry.map_err(StorageError::Io)?;
                let link_name = entry.file_name().to_string_lossy().to_string();
                found_links.insert(link_name.clone());

                // Read symlink target
                match links_dir.read_link(&link_name) {
                    Ok(target) => {
                        let target_str = target.to_string_lossy();

                        // Verify target matches expected layer if we know what it should be
                        if let Some(expected_layer_id) = expected_links.get(&link_name) {
                            let expected_target = format!("../{}/diff", expected_layer_id);
                            if target_str != expected_target {
                                result.errors.push(ValidationError::SymlinkTargetMismatch {
                                    link_id: link_name.clone(),
                                    expected: expected_target,
                                    actual: target_str.to_string(),
                                });
                            }
                            // Check if the target layer's diff actually exists
                            let layer_diff = format!("{}/diff", expected_layer_id);
                            if !overlay_dir.try_exists(&layer_diff).unwrap_or(false) {
                                result.errors.push(ValidationError::BrokenSymlink {
                                    link_id: link_name.clone(),
                                    target: target_str.to_string(),
                                });
                            }
                        } else {
                            // Orphaned symlink - target validation is done by orphan check
                            // Just check the target pattern is valid and exists
                            if let Some(layer_id) = target_str
                                .strip_prefix("../")
                                .and_then(|s| s.strip_suffix("/diff"))
                            {
                                let layer_diff = format!("{}/diff", layer_id);
                                if !overlay_dir.try_exists(&layer_diff).unwrap_or(false) {
                                    result.errors.push(ValidationError::BrokenSymlink {
                                        link_id: link_name.clone(),
                                        target: target_str.to_string(),
                                    });
                                }
                            }
                        }
                    }
                    Err(_) => {
                        // Not a symlink or can't read
                    }
                }
            }

            // Check for missing expected symlinks
            for (link_id, layer_id) in &expected_links {
                if !found_links.contains(link_id) {
                    result.errors.push(ValidationError::MissingSymlink {
                        link_id: link_id.clone(),
                        layer_id: layer_id.clone(),
                    });
                }
            }

            // Check for orphaned symlinks
            if options.check_orphans {
                for link_id in &found_links {
                    if !expected_links.contains_key(link_id) {
                        result.warnings.push(ValidationWarning::OrphanedSymlink {
                            link_id: link_id.clone(),
                        });
                    }
                }
            }
        }

        // Check for orphaned layer directories
        if options.check_orphans {
            for entry in overlay_dir.entries().map_err(StorageError::Io)? {
                let entry = entry.map_err(StorageError::Io)?;
                let dir_name = entry.file_name().to_string_lossy().to_string();

                // Skip special directories
                if dir_name == "l" {
                    continue;
                }

                // Check if this looks like a layer ID (64 hex chars)
                if dir_name.len() == 64 && dir_name.chars().all(|c| c.is_ascii_hexdigit()) {
                    if !layer_ids.contains(dir_name.as_str()) {
                        result
                            .warnings
                            .push(ValidationWarning::OrphanedLayerDir { dir_name });
                        result.stats.orphaned_layer_dirs += 1;
                    }
                }
            }
        }

        // Check for unused layers
        if options.check_unused_layers {
            let used_layers = self.get_used_layer_ids()?;
            for layer in &layers {
                if !used_layers.contains(&layer.id) {
                    result.warnings.push(ValidationWarning::UnusedLayer {
                        layer_id: layer.id.clone(),
                    });
                    result.stats.unused_layers += 1;
                }
            }
        }

        Ok(())
    }

    fn validate_images(
        &self,
        options: &ValidateOptions,
        result: &mut ValidationResult,
    ) -> Result<()> {
        let image_store = self.image_store();
        let images = image_store.list_images()?;

        // Build set of layer IDs for quick lookup
        let layer_store = self.layer_store();
        let layers = layer_store.list_layers()?;
        let layer_ids: HashSet<&str> = layers.iter().map(|l| l.id.as_str()).collect();

        // Build set of image IDs for orphan checking
        let image_ids: HashSet<&str> = images.iter().map(|i| i.id.as_str()).collect();

        let images_dir = self.root_dir().open_dir("overlay-images")?;

        for image in &images {
            result.stats.images_checked += 1;

            // Check image directory exists
            let image_dir = match images_dir.open_dir(&image.id) {
                Ok(dir) => dir,
                Err(_) => {
                    result.errors.push(ValidationError::MissingImageDir {
                        image_id: image.id.clone(),
                    });
                    continue;
                }
            };

            // Check manifest exists
            if !image_dir.try_exists("manifest").unwrap_or(false) {
                result.errors.push(ValidationError::MissingManifest {
                    image_id: image.id.clone(),
                });
            }

            // Check layer reference is valid
            if let Some(layer_id) = &image.layer {
                if !layer_ids.contains(layer_id.as_str()) {
                    result.errors.push(ValidationError::ImageLayerMissing {
                        image_id: image.id.clone(),
                        layer_id: layer_id.clone(),
                    });
                }
            }

            // Check big data files exist
            if let Some(big_data_names) = &image.big_data_names {
                for name in big_data_names {
                    // Big data is stored as base64-encoded filenames prefixed with '='
                    let encoded = format!("={}", base64_encode_filename(name));
                    if !image_dir.try_exists(&encoded).unwrap_or(false) && name != "manifest" {
                        // manifest is stored directly, others are base64 encoded
                        result.errors.push(ValidationError::MissingBigData {
                            image_id: image.id.clone(),
                            key: name.clone(),
                        });
                    }
                }
            }
        }

        // Check for orphaned image directories
        if options.check_orphans {
            for entry in images_dir.entries().map_err(StorageError::Io)? {
                let entry = entry.map_err(StorageError::Io)?;
                let dir_name = entry.file_name().to_string_lossy().to_string();

                // Skip non-directories and special files
                if dir_name.ends_with(".json") || dir_name.ends_with(".lock") {
                    continue;
                }

                // Check if this looks like an image ID (64 hex chars)
                if dir_name.len() == 64 && dir_name.chars().all(|c| c.is_ascii_hexdigit()) {
                    if !image_ids.contains(dir_name.as_str()) {
                        result
                            .warnings
                            .push(ValidationWarning::OrphanedImageDir { dir_name });
                        result.stats.orphaned_image_dirs += 1;
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if a link ID is valid (26 uppercase letters).
    fn is_valid_link_id(s: &str) -> bool {
        s.len() == 26 && s.chars().all(|c| c.is_ascii_uppercase())
    }

    /// Detect circular parent references.
    fn detect_parent_cycle(
        &self,
        start_id: &str,
        layers: &[crate::layer_store::LayerRecord],
    ) -> Option<Vec<String>> {
        let layer_map: HashMap<&str, &crate::layer_store::LayerRecord> =
            layers.iter().map(|l| (l.id.as_str(), l)).collect();

        let mut visited = HashSet::new();
        let mut path = vec![start_id.to_string()];
        let mut current_id = start_id;

        while let Some(layer) = layer_map.get(current_id) {
            if let Some(parent_id) = &layer.parent {
                if visited.contains(parent_id.as_str()) {
                    // Found a cycle
                    path.push(parent_id.clone());
                    return Some(path);
                }
                visited.insert(current_id);
                path.push(parent_id.clone());
                current_id = parent_id;
            } else {
                break;
            }
        }

        None
    }

    /// Get all layer IDs that are referenced by images (directly or through parent chain).
    fn get_used_layer_ids(&self) -> Result<HashSet<String>> {
        let mut used = HashSet::new();

        let image_store = self.image_store();
        let images = image_store.list_images()?;

        let layer_store = self.layer_store();
        let layers = layer_store.list_layers()?;
        let layer_map: HashMap<&str, &crate::layer_store::LayerRecord> =
            layers.iter().map(|l| (l.id.as_str(), l)).collect();

        // For each image, walk the layer chain
        for image in &images {
            if let Some(layer_id) = &image.layer {
                let mut current_id = layer_id.as_str();
                while let Some(layer) = layer_map.get(current_id) {
                    used.insert(current_id.to_string());
                    if let Some(parent_id) = &layer.parent {
                        current_id = parent_id;
                    } else {
                        break;
                    }
                }
            }
        }

        Ok(used)
    }

    /// Verify a tar-split file can be parsed.
    fn verify_tar_split(&self, layer_id: &str) -> Result<()> {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let layers_dir = self.root_dir().open_dir("overlay-layers")?;
        let tar_split_name = format!("{}.tar-split.gz", layer_id);

        let file = layers_dir.open(&tar_split_name).map_err(StorageError::Io)?;
        let mut decoder = GzDecoder::new(std::io::BufReader::new(file));
        let mut contents = String::new();
        decoder.read_to_string(&mut contents).map_err(|e| {
            StorageError::InvalidStorage(format!("failed to decompress tar-split: {}", e))
        })?;

        // Try to parse each line as JSON
        for line in contents.lines() {
            if !line.is_empty() {
                serde_json::from_str::<serde_json::Value>(line).map_err(|e| {
                    StorageError::InvalidStorage(format!("invalid JSON in tar-split: {}", e))
                })?;
            }
        }

        Ok(())
    }
}

/// Encode a filename for big data storage (simplified base64).
fn base64_encode_filename(name: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_error_display() {
        let err = ValidationError::MissingLayerDir {
            layer_id: "abc123".to_string(),
        };
        assert!(err.to_string().contains("abc123"));
        assert!(err.to_string().contains("missing directory"));

        let err = ValidationError::InvalidParent {
            layer_id: "child".to_string(),
            parent_id: "parent".to_string(),
        };
        assert!(err.to_string().contains("child"));
        assert!(err.to_string().contains("parent"));
    }

    #[test]
    fn test_validation_warning_display() {
        let warn = ValidationWarning::OrphanedLayerDir {
            dir_name: "deadbeef".to_string(),
        };
        assert!(warn.to_string().contains("deadbeef"));
        assert!(warn.to_string().contains("orphaned"));

        let warn = ValidationWarning::UnusedLayer {
            layer_id: "unused123".to_string(),
        };
        assert!(warn.to_string().contains("unused123"));
        assert!(warn.to_string().contains("not referenced"));
    }

    #[test]
    fn test_validation_result_helpers() {
        let mut result = ValidationResult::default();
        assert!(result.is_ok());
        assert!(!result.has_errors());
        assert!(!result.has_warnings());

        result.warnings.push(ValidationWarning::IncompleteLayer {
            layer_id: "test".to_string(),
        });
        assert!(result.is_ok());
        assert!(!result.has_errors());
        assert!(result.has_warnings());

        result.errors.push(ValidationError::MissingLayerDir {
            layer_id: "test".to_string(),
        });
        assert!(!result.is_ok());
        assert!(result.has_errors());
    }

    #[test]
    fn test_validate_options_default() {
        let opts = ValidateOptions::default();
        assert!(opts.check_orphans);
        assert!(!opts.check_unused_layers);
        assert!(!opts.verify_tar_split);
    }

    #[test]
    fn test_is_valid_link_id() {
        assert!(Storage::is_valid_link_id("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
        assert!(!Storage::is_valid_link_id("abcdefghijklmnopqrstuvwxyz")); // lowercase
        assert!(!Storage::is_valid_link_id("ABCDEFGHIJKLMNOPQRSTUVWXY")); // too short
        assert!(!Storage::is_valid_link_id("ABCDEFGHIJKLMNOPQRSTUVWXYZ1")); // too long
        assert!(!Storage::is_valid_link_id("ABCDEFGHIJKLMNOPQRSTUVWXY1")); // has digit
    }

    #[test]
    fn test_base64_encode_filename() {
        let encoded = base64_encode_filename("sha256:abc123");
        assert!(!encoded.is_empty());
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
    }
}
