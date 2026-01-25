//! Output formatting utilities for the CLI.
//!
//! This module provides consistent output formatting for CLI commands,
//! supporting both human-readable table output and machine-parseable JSON.
//!
//! # Usage
//!
//! ```ignore
//! use output::{OutputFormat, format_size, format_time_ago};
//!
//! // Parse format from CLI args
//! #[derive(clap::Parser)]
//! struct Args {
//!     #[arg(long, default_value = "table")]
//!     format: OutputFormat,
//! }
//!
//! // Format sizes for display
//! assert_eq!(format_size(1_500_000_000), "1.4 GB");
//! ```

use chrono::{DateTime, Utc};
use clap::ValueEnum;
use comfy_table::{presets::UTF8_FULL_CONDENSED, ContentArrangement, Table};
use facet::Facet;
use serde::Serialize;

/// Output format for CLI commands.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable table format.
    #[default]
    Table,
    /// Machine-parseable JSON format.
    Json,
}

/// Image list entry for CLI output.
///
/// This type implements both `Serialize` for JSON output and `Facet` for
/// reflection-based table generation.
#[derive(Debug, Serialize, Facet)]
pub struct ImageListEntry {
    /// Repository name (e.g., "docker.io/library/alpine").
    pub repository: String,
    /// Image tag (e.g., "latest").
    pub tag: String,
    /// Truncated image ID (12 characters).
    pub id: String,
    /// Full image ID (SHA256 digest).
    /// This field is automatically skipped in table output (starts with "full_").
    pub full_id: String,
    /// Pre-formatted creation time for table display (e.g., "2 hours ago").
    pub created: String,
    /// Total image size in bytes.
    /// Automatically formatted as human-readable size in table output.
    pub size: u64,
    /// Number of layers.
    pub layers: usize,
}

/// Layer information for CLI output.
///
/// This type implements both `Serialize` for JSON output and `Facet` for
/// reflection-based table generation.
#[derive(Debug, Serialize, Facet)]
pub struct LayerInfo {
    /// Layer index (0-based, from bottom).
    pub index: usize,
    /// Truncated layer ID (12 characters).
    pub id: String,
    /// Full layer ID (auto-skipped in table output due to "full_" prefix).
    pub full_id: String,
    /// Short link ID used for overlay mounts.
    pub link_id: String,
    /// Number of parent layers.
    pub parent_count: usize,
    /// Diff size in bytes (if available).
    /// Automatically formatted as human-readable size in table output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_size: Option<u64>,
}

/// Image inspection output.
#[derive(Debug, Serialize, Facet)]
pub struct ImageInspectOutput {
    /// Full image ID.
    pub id: String,
    /// Repository tags as comma-separated string for display.
    pub repo_tags: String,
    /// Pre-formatted creation time for display (e.g., "2 hours ago").
    pub created: String,
    /// Total image size in bytes.
    pub size: u64,
    /// OCI manifest schema version.
    pub schema_version: u32,
    /// Media type of the manifest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// Config blob digest.
    pub config_digest: String,
    /// Number of layers (computed from layers Vec).
    pub layer_count: usize,
}

/// Layer inspection output.
#[derive(Debug, Serialize, Facet)]
pub struct LayerInspectOutput {
    /// Full layer ID.
    pub id: String,
    /// Short link ID used for overlay mounts.
    pub link_id: String,
    /// Number of parent layers.
    pub parent_count: usize,
    /// Uncompressed diff size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_size: Option<u64>,
    /// Compressed size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compressed_size: Option<u64>,
    /// Parent layer IDs as newline-separated string (only when --chain is specified).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_chain: Option<String>,
}

/// Format a byte count as human-readable size.
///
/// Uses SI units (GB, MB, KB) with one decimal place.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(format_size(0), "0 B");
/// assert_eq!(format_size(512), "512 B");
/// assert_eq!(format_size(1024), "1.0 KB");
/// assert_eq!(format_size(1_500_000), "1.4 MB");
/// assert_eq!(format_size(2_500_000_000), "2.3 GB");
/// ```
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format a datetime as a human-readable relative time.
///
/// Returns strings like "2 hours ago", "3 days ago", "5 months ago".
///
/// # Examples
///
/// ```ignore
/// use chrono::Utc;
///
/// let now = Utc::now();
/// assert_eq!(format_time_ago(now), "just now");
/// ```
pub fn format_time_ago(dt: DateTime<Utc>) -> String {
    let now = Utc::now();
    let duration = now.signed_duration_since(dt);

    let seconds = duration.num_seconds();
    if seconds < 0 {
        return "in the future".to_string();
    }

    let minutes = duration.num_minutes();
    let hours = duration.num_hours();
    let days = duration.num_days();
    let weeks = days / 7;
    let months = days / 30;
    let years = days / 365;

    if seconds < 60 {
        "just now".to_string()
    } else if minutes == 1 {
        "1 minute ago".to_string()
    } else if minutes < 60 {
        format!("{} minutes ago", minutes)
    } else if hours == 1 {
        "1 hour ago".to_string()
    } else if hours < 24 {
        format!("{} hours ago", hours)
    } else if days == 1 {
        "1 day ago".to_string()
    } else if days < 7 {
        format!("{} days ago", days)
    } else if weeks == 1 {
        "1 week ago".to_string()
    } else if weeks < 4 {
        format!("{} weeks ago", weeks)
    } else if months == 1 {
        "1 month ago".to_string()
    } else if months < 12 {
        format!("{} months ago", months)
    } else if years == 1 {
        "1 year ago".to_string()
    } else {
        format!("{} years ago", years)
    }
}

/// Truncate an ID to 12 characters for display.
///
/// Container IDs are typically 64-character hex strings; this provides
/// a shorter form suitable for display while remaining unique enough
/// for most purposes.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(truncate_id("abc123def456789"), "abc123def456");
/// assert_eq!(truncate_id("short"), "short");
/// ```
pub fn truncate_id(id: &str) -> String {
    if id.len() <= 12 {
        id.to_string()
    } else {
        id[..12].to_string()
    }
}

/// Create a styled table with consistent formatting.
///
/// The table uses UTF-8 borders and is configured for terminal output
/// with dynamic content arrangement.
pub fn create_styled_table() -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic);
    table
}

/// Output a single item in the specified format.
///
/// For JSON output, uses serde serialization.
/// For table output, uses facet-based reflection to build a key-value table.
pub fn output_item<'a, T>(item: &T, format: OutputFormat) -> Result<(), serde_json::Error>
where
    T: Serialize + Facet<'a>,
{
    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string(item)?;
            println!("{}", json);
            Ok(())
        }
        OutputFormat::Table => {
            println!("{}", super::table::table_from_item(item));
            Ok(())
        }
    }
}

/// Output a slice of items in the specified format.
///
/// For JSON output, uses serde serialization.
/// For table output, uses facet-based reflection to build a columnar table.
pub fn output_slice<'a, T>(items: &[T], format: OutputFormat) -> Result<(), serde_json::Error>
where
    T: Serialize + Facet<'a>,
{
    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string(items)?;
            println!("{}", json);
            Ok(())
        }
        OutputFormat::Table => {
            println!("{}", super::table::table_from_slice(items));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(1_500_000), "1.4 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(format_size(2_500_000_000), "2.3 GB");
    }

    #[test]
    fn test_truncate_id() {
        assert_eq!(truncate_id("abc"), "abc");
        assert_eq!(truncate_id("123456789012"), "123456789012");
        assert_eq!(truncate_id("1234567890123"), "123456789012");
        assert_eq!(truncate_id("sha256:abc123def456789abcdef"), "sha256:abc12");
    }

    #[test]
    fn test_format_time_ago_just_now() {
        let now = Utc::now();
        assert_eq!(format_time_ago(now), "just now");
    }

    #[test]
    fn test_image_list_entry_serializes() {
        let entry = ImageListEntry {
            repository: "docker.io/library/alpine".to_string(),
            tag: "latest".to_string(),
            id: "abc123def456".to_string(),
            full_id: "abc123def456789".to_string(),
            created: "2 hours ago".to_string(),
            size: 5_000_000,
            layers: 3,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("docker.io/library/alpine"));
        assert!(json.contains("abc123def456"));
    }

    #[test]
    fn test_create_styled_table() {
        let table = create_styled_table();
        // Table should be created without panicking
        let _ = table.to_string();
    }
}
