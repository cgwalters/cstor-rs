//! Facet-based table generation for CLI output.
//!
//! This module provides a generic way to build `comfy_table::Table` from any type
//! implementing `facet::Facet`. It uses runtime reflection to extract field names
//! and values without requiring manual table-building code.
//!
//! # Automatic Formatting
//!
//! - Fields named `size`, `diff_size`, `compressed_size` → formatted as human-readable bytes
//! - Fields with prefix `full_` → automatically skipped (internal IDs)
//! - Fields with `#[facet(skip)]` → excluded from table output
//! - All other fields → converted to title-case headers

use comfy_table::{Cell, Table};
use facet::{Facet, Field, Peek, PeekStruct, ScalarType, Type, UserType};

use super::output::{create_styled_table, format_size};

/// Metadata for a single column in table output.
#[derive(Debug, Clone)]
struct ColumnMeta {
    /// The display header for this column.
    header: String,
    /// Field index in the struct.
    field_index: usize,
    /// Whether to format as human-readable size.
    format_size: bool,
}

/// Check if a field should be formatted as a size (bytes).
fn is_size_field(field: &Field) -> bool {
    let name = field.name;
    matches!(name, "size" | "diff_size" | "compressed_size")
}

/// Check if a field should be skipped.
fn is_skipped(field: &Field) -> bool {
    // Check flags for skip
    field.should_skip_deserializing()
}

/// Get the display name for a field.
fn get_field_display_name(field: &Field) -> String {
    let name = field.name;

    // Convert to title case for display
    name.split('_')
        .map(|s: &str| {
            let mut c = s.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Extract column metadata from struct fields.
fn extract_columns(fields: &[Field]) -> Vec<ColumnMeta> {
    let mut columns = Vec::new();

    for (idx, field) in fields.iter().enumerate() {
        let skip = is_skipped(field);

        // Skip fields that are explicitly marked or have "full_" prefix (internal IDs)
        let field_name = field.name;
        let auto_skip = field_name.starts_with("full_")
            || field_name == "internal"
            || field_name.starts_with('_');

        if skip || auto_skip {
            continue;
        }

        let header = get_field_display_name(field).to_uppercase();

        columns.push(ColumnMeta {
            header,
            field_index: idx,
            format_size: is_size_field(field),
        });
    }

    columns
}

/// Format a Peek value as a string for table display.
fn format_peek_value(peek: Peek<'_, '_>, meta: &ColumnMeta) -> String {
    // Handle Option by peeking inside
    if let Ok(opt_peek) = peek.into_option() {
        if let Some(inner) = opt_peek.value() {
            return format_peek_value(inner, meta);
        } else {
            return "N/A".to_string();
        }
    }

    // Get the shape for scalar type detection
    let shape = peek.shape();

    // Try scalar types
    if let Some(scalar) = shape.scalar_type() {
        return format_scalar_peek(peek, scalar, meta);
    }

    // Try Display trait if available
    if shape.is_display() {
        return peek.to_string();
    }

    // Fall back to Debug
    if shape.is_debug() {
        return format!("{:?}", peek);
    }

    "?".to_string()
}

/// Format a scalar value from a Peek.
fn format_scalar_peek(peek: Peek<'_, '_>, scalar: ScalarType, meta: &ColumnMeta) -> String {
    match scalar {
        ScalarType::U64 => {
            // Try to get the u64 value
            if let Ok(value) = peek.get::<u64>() {
                if meta.format_size {
                    format_size(*value)
                } else {
                    value.to_string()
                }
            } else {
                "?".to_string()
            }
        }
        ScalarType::U32 => {
            if let Ok(value) = peek.get::<u32>() {
                if meta.format_size {
                    format_size(*value as u64)
                } else {
                    value.to_string()
                }
            } else {
                "?".to_string()
            }
        }
        ScalarType::I64 => {
            if let Ok(value) = peek.get::<i64>() {
                value.to_string()
            } else {
                "?".to_string()
            }
        }
        ScalarType::I32 => {
            if let Ok(value) = peek.get::<i32>() {
                value.to_string()
            } else {
                "?".to_string()
            }
        }
        ScalarType::String => peek.to_string(),
        ScalarType::Str => peek.to_string(),
        ScalarType::Bool => {
            if let Ok(value) = peek.get::<bool>() {
                value.to_string()
            } else {
                "?".to_string()
            }
        }
        _ => {
            // For other scalars (including usize), try Display
            if peek.shape().is_display() {
                peek.to_string()
            } else {
                "?".to_string()
            }
        }
    }
}

/// Get struct fields from a shape's type.
fn get_struct_fields(shape: &'static facet::Shape) -> Option<&'static [Field]> {
    match &shape.ty {
        Type::User(UserType::Struct(struct_type)) => Some(struct_type.fields),
        _ => None,
    }
}

/// Build a table from a slice of items implementing Facet.
///
/// This function inspects the type's shape at runtime to extract field
/// information and builds a formatted table.
pub fn table_from_slice<'a, T: Facet<'a>>(items: &[T]) -> Table {
    let shape = T::SHAPE;
    let mut table = create_styled_table();

    // Extract struct fields
    let fields = match get_struct_fields(shape) {
        Some(f) => f,
        None => {
            // Not a struct - return empty table
            return table;
        }
    };

    // Build column metadata from fields
    let columns = extract_columns(fields);

    // Set headers
    let headers: Vec<&str> = columns.iter().map(|c| c.header.as_str()).collect();
    table.set_header(headers);

    // Add rows
    for item in items {
        let peek = Peek::new(item);
        let struct_peek: PeekStruct<'_, '_> = match peek.into_struct() {
            Ok(s) => s,
            Err(_) => continue,
        };

        let mut cells: Vec<Cell> = Vec::new();

        for col in &columns {
            let value = match struct_peek.field(col.field_index) {
                Ok(fp) => format_peek_value(fp, col),
                Err(_) => "?".to_string(),
            };
            cells.push(Cell::new(value));
        }

        table.add_row(cells);
    }

    table
}

/// Build a key-value table from a single item implementing Facet.
///
/// This creates a two-column table with "Field" and "Value" headers,
/// suitable for detailed inspection of a single item.
pub fn table_from_item<'a, T: Facet<'a>>(item: &T) -> Table {
    let shape = T::SHAPE;
    let mut table = create_styled_table();
    table.set_header(vec!["Field", "Value"]);

    // Extract struct fields
    let fields = match get_struct_fields(shape) {
        Some(f) => f,
        None => {
            return table;
        }
    };

    // Build column metadata from fields
    let columns = extract_columns(fields);

    let peek = Peek::new(item);
    let struct_peek: PeekStruct<'_, '_> = match peek.into_struct() {
        Ok(s) => s,
        Err(_) => return table,
    };

    // Add rows
    for col in &columns {
        let value = match struct_peek.field(col.field_index) {
            Ok(fp) => format_peek_value(fp, col),
            Err(_) => "?".to_string(),
        };

        // Use title-case field name for display
        let display_name = get_field_display_name(&fields[col.field_index]);
        table.add_row(vec![Cell::new(display_name), Cell::new(value)]);
    }

    table
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{ImageListEntry, LayerInfo};

    #[derive(Debug, facet::Facet)]
    struct TestEntry {
        name: String,
        size: u64,
        #[facet(skip)]
        internal: String,
    }

    #[test]
    fn test_table_from_slice() {
        let entries = vec![
            TestEntry {
                name: "test1".to_string(),
                size: 1024,
                internal: "hidden".to_string(),
            },
            TestEntry {
                name: "test2".to_string(),
                size: 2048,
                internal: "also hidden".to_string(),
            },
        ];

        let table = table_from_slice(&entries);
        let output = table.to_string();

        // Verify headers are present
        assert!(output.contains("NAME"));
        assert!(output.contains("SIZE"));
        // Verify internal field is not shown (it's skipped)
        assert!(!output.contains("INTERNAL"));
    }

    #[test]
    fn test_table_from_item() {
        let entry = TestEntry {
            name: "single".to_string(),
            size: 4096,
            internal: "secret".to_string(),
        };

        let table = table_from_item(&entry);
        let output = table.to_string();

        // Verify field names are present
        assert!(output.contains("Name"));
        assert!(output.contains("Size"));
        // Verify values are present
        assert!(output.contains("single"));
        // Size should be formatted as bytes
        assert!(output.contains("4.0 KB"));
    }

    #[test]
    fn test_image_list_entry_facet_table() {
        // Test that the migrated ImageListEntry works with facet-based tables
        let entries = vec![
            ImageListEntry {
                repository: "docker.io/library/alpine".to_string(),
                tag: "latest".to_string(),
                id: "abc123def456".to_string(),
                full_id: "sha256:abc123def456789...".to_string(),
                created: "2 hours ago".to_string(),
                size: 5_500_000,
                layers: 3,
            },
            ImageListEntry {
                repository: "docker.io/library/nginx".to_string(),
                tag: "1.25".to_string(),
                id: "def789abc012".to_string(),
                full_id: "sha256:def789abc012345...".to_string(),
                created: "3 days ago".to_string(),
                size: 150_000_000,
                layers: 7,
            },
        ];

        let table = table_from_slice(&entries);
        let output = table.to_string();

        // Verify headers are present (auto-generated from field names)
        assert!(output.contains("REPOSITORY"));
        assert!(output.contains("TAG"));
        assert!(output.contains("ID"));
        assert!(output.contains("CREATED"));
        assert!(output.contains("SIZE"));
        assert!(output.contains("LAYERS"));

        // Verify full_id is NOT shown (auto-skipped due to "full_" prefix)
        assert!(!output.contains("FULL ID"));

        // Verify values are present
        assert!(output.contains("docker.io/library/alpine"));
        assert!(output.contains("latest"));
        assert!(output.contains("abc123def456"));
        assert!(output.contains("2 hours ago"));

        // Verify size formatting (150MB)
        assert!(output.contains("143.1 MB"));
    }

    #[test]
    fn test_layer_info_facet_table() {
        let layers = vec![
            LayerInfo {
                index: 0,
                id: "abc123def456".to_string(),
                full_id: "sha256:abc123def456789...".to_string(),
                link_id: "ABCD1234".to_string(),
                parent_count: 0,
                diff_size: Some(10_000_000),
            },
            LayerInfo {
                index: 1,
                id: "def789abc012".to_string(),
                full_id: "sha256:def789abc012345...".to_string(),
                link_id: "EFGH5678".to_string(),
                parent_count: 1,
                diff_size: Some(5_000_000),
            },
        ];

        let table = table_from_slice(&layers);
        let output = table.to_string();

        // Verify headers are present
        assert!(output.contains("INDEX"));
        assert!(output.contains("ID"));
        assert!(output.contains("LINK ID"));
        assert!(output.contains("PARENT COUNT"));
        assert!(output.contains("DIFF SIZE"));

        // Verify full_id is NOT shown (auto-skipped due to "full_" prefix)
        assert!(!output.contains("FULL ID"));

        // Verify values are present
        assert!(output.contains("abc123def456"));
        assert!(output.contains("ABCD1234"));

        // Verify size formatting
        assert!(output.contains("9.5 MB"));
        assert!(output.contains("4.8 MB"));
    }
}
