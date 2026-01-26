//! cstor-rs: Command-line tool for reading containers-storage
//!
//! This binary exposes all functionality of the cstor-rs library
//! and serves as an integration test for comparing with skopeo.
//!
//! # Rootless Mode
//!
//! When running as a non-root user with rootless Podman, container images
//! may contain files with UIDs/GIDs that are mapped via user namespaces.
//! Commands that access file content (`export-layer`, `copy-to-oci`) will
//! automatically re-execute themselves via `podman unshare` to enter the
//! user namespace with the correct UID/GID mappings.
//!
//! This is necessary because container layers often contain files owned by
//! UIDs like 0 (root) or other system users, which in rootless mode are
//! mapped to high UIDs in the host namespace via `/etc/subuid` and
//! `/etc/subgid`. Without entering the user namespace, these files would
//! be inaccessible or have incorrect ownership in the reconstructed tar.
//!
//! The automatic re-exec behavior:
//! - Detects when running as a non-root user (via `getuid()`)
//! - Re-executes via `podman unshare /proc/self/exe <args>`
//! - Sets `CSTOR_IN_USERNS=1` environment variable to prevent infinite loops
//! - Is transparent to the user - no manual intervention required
//!
//! To disable this behavior (e.g., for debugging), set `CSTOR_IN_USERNS=1`
//! before running the command.

mod output;
mod table;

use anyhow::{Context, Result, anyhow};
use cap_std::ambient_authority;
use cap_std::fs::Dir;
use clap::{Parser, Subcommand};
use cstor_rs::*;
use output::{
    ImageInspectOutput, ImageListEntry, LayerInfo, LayerInspectOutput, OutputFormat,
    format_time_ago, output_item, output_slice, truncate_id,
};
use sha2::Digest;
use std::fs::File;
use std::io::{self, Write};

use std::path::PathBuf;

/// Environment variable set when we've re-execed into a user namespace
const USERNS_ENV: &str = "CSTOR_IN_USERNS";

#[derive(Parser)]
#[command(name = "cstor-rs")]
#[command(about = "Read-only access to containers-storage (overlay driver)", long_about = None)]
struct Cli {
    /// Path to storage root (default: auto-discover)
    #[arg(short, long, global = true)]
    root: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage images
    #[command(visible_alias = "images")]
    Image {
        #[command(subcommand)]
        command: ImageCommands,
    },

    /// Manage layers
    #[command(visible_alias = "layers")]
    Layer {
        #[command(subcommand)]
        command: LayerCommands,
    },

    /// Resolve a link ID to layer ID
    ResolveLink {
        /// Short link ID (26 chars)
        link_id: String,
    },
}

/// Image subcommands
#[derive(Subcommand)]
enum ImageCommands {
    /// List images in storage
    #[command(visible_alias = "ls")]
    List {
        /// Output format (table or json)
        #[arg(long, value_enum, default_value = "table")]
        format: OutputFormat,
        /// Don't truncate image IDs
        #[arg(long)]
        no_trunc: bool,
    },

    /// Display detailed information on an image
    Inspect {
        /// Image ID or name
        image: String,
        /// Output format (table or json)
        #[arg(long, value_enum, default_value = "table")]
        format: OutputFormat,
    },

    /// List layers for an image
    Layers {
        /// Image ID or name
        image: String,
        /// Output format (table or json)
        #[arg(long, value_enum, default_value = "table")]
        format: OutputFormat,
    },

    /// Output Table of Contents (TOC) for an image
    ///
    /// The TOC contains metadata for all files across all layers,
    /// in a format compatible with eStargz.
    Toc {
        /// Image ID or name
        image: String,
        /// Pretty-print the JSON output
        #[arg(long)]
        pretty: bool,
    },

    /// Copy image to OCI directory layout
    #[command(visible_alias = "copy")]
    CopyToOci {
        /// Image ID or name
        image: String,
        /// Output OCI directory
        output: PathBuf,
    },

    /// Extract image to directory using reflinks
    ///
    /// Flattens all layers and extracts to the destination directory.
    /// Files are reflinked from the source storage when possible,
    /// avoiding data duplication on filesystems that support it (btrfs, XFS).
    ///
    /// Uses ProxiedStorage for transparent access even when running
    /// as an unprivileged user with rootless Podman.
    Extract {
        /// Image ID or name
        image: String,
        /// Destination directory (must not exist)
        output: PathBuf,
        /// Link mode for file extraction
        #[arg(long, value_enum, default_value = "reflink")]
        link_mode: CliLinkMode,
        /// Fall back to copying if reflink/hardlink fails (e.g., cross-filesystem)
        ///
        /// By default, extraction will fail if the requested link mode is not
        /// supported. Use this flag to silently fall back to copying instead.
        #[arg(long)]
        fallback_to_copy: bool,
        /// Preserve file ownership (UID/GID) - requires privileges
        #[arg(long)]
        preserve_ownership: bool,
        /// Disable preserving file permissions
        #[arg(long)]
        no_permissions: bool,
    },
}

/// Link mode for file extraction (CLI enum).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum CliLinkMode {
    /// Use reflinks (copy-on-write) - best for btrfs/XFS
    #[default]
    Reflink,
    /// Use hardlinks to source files - works on ext4
    Hardlink,
    /// Always copy file data
    Copy,
}

impl From<CliLinkMode> for cstor_rs::extract::LinkMode {
    fn from(mode: CliLinkMode) -> Self {
        match mode {
            CliLinkMode::Reflink => cstor_rs::extract::LinkMode::Reflink,
            CliLinkMode::Hardlink => cstor_rs::extract::LinkMode::Hardlink,
            CliLinkMode::Copy => cstor_rs::extract::LinkMode::Copy,
        }
    }
}

/// Layer subcommands
#[derive(Subcommand)]
enum LayerCommands {
    /// Display detailed information on a layer
    Inspect {
        /// Layer ID
        layer: String,
        /// Show parent chain
        #[arg(short, long)]
        chain: bool,
        /// Output format (table or json)
        #[arg(long, value_enum, default_value = "table")]
        format: OutputFormat,
    },

    /// Export layer as tar stream
    Export {
        /// Layer ID
        layer: String,
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Export layer as tar stream via IPC protocol (experimental)
    ///
    /// Demonstrates the JSON-RPC fd-passing protocol by streaming
    /// tar-split data through a socketpair internally.
    ExportIpc {
        /// Layer ID
        layer: String,
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Extract layer to directory using reflinks
    ///
    /// Extracts all files from the layer to the destination directory.
    /// Files are reflinked from the source storage when possible,
    /// avoiding data duplication on filesystems that support it (btrfs, XFS).
    ///
    /// Uses ProxiedStorage for transparent access even when running
    /// as an unprivileged user with rootless Podman.
    Extract {
        /// Layer ID
        layer: String,
        /// Destination directory (must not exist)
        output: PathBuf,
        /// Link mode for file extraction
        #[arg(long, value_enum, default_value = "reflink")]
        link_mode: CliLinkMode,
        /// Fall back to copying if reflink/hardlink fails (e.g., cross-filesystem)
        ///
        /// By default, extraction will fail if the requested link mode is not
        /// supported. Use this flag to silently fall back to copying instead.
        #[arg(long)]
        fallback_to_copy: bool,
        /// Preserve file ownership (UID/GID) - requires privileges
        #[arg(long)]
        preserve_ownership: bool,
        /// Disable preserving file permissions
        #[arg(long)]
        no_permissions: bool,
    },
}

fn main() -> Result<()> {
    // Check if this process was spawned as a userns helper and run the helper loop if so.
    // This must be called early, before any other processing.
    cstor_rs::userns_helper::init_if_helper();

    let cli = Cli::parse();

    // Re-exec via podman unshare if needed for proper UID/GID mapping
    if cstor_rs::userns::should_enter_userns(USERNS_ENV) {
        cstor_rs::userns::reexec_via_podman(USERNS_ENV)
            .map_err(|e| anyhow!("Failed to enter user namespace: {}", e))?;
    }

    // Open storage
    let storage = if let Some(ref root) = cli.root {
        Storage::open(root).context("Failed to open storage")?
    } else {
        Storage::discover().context("Failed to discover storage")?
    };

    match cli.command {
        Commands::Image { command } => match command {
            ImageCommands::List { format, no_trunc } => list_images(&storage, format, no_trunc)?,
            ImageCommands::Inspect { image, format } => inspect_image(&storage, &image, format)?,
            ImageCommands::Layers { image, format } => list_layers(&storage, &image, format)?,
            ImageCommands::Toc { image, pretty } => output_toc(&storage, &image, pretty)?,
            ImageCommands::CopyToOci { image, output } => copy_to_oci(&storage, &image, output)?,
            ImageCommands::Extract {
                image,
                output,
                link_mode,
                fallback_to_copy,
                preserve_ownership,
                no_permissions,
            } => extract_image_cmd(
                &cli.root,
                &image,
                output,
                link_mode,
                fallback_to_copy,
                preserve_ownership,
                no_permissions,
            )?,
        },
        Commands::Layer { command } => match command {
            LayerCommands::Inspect {
                layer,
                chain,
                format,
            } => inspect_layer(&storage, &layer, chain, format)?,
            LayerCommands::Export { layer, output } => export_layer(&storage, &layer, output)?,
            LayerCommands::ExportIpc { layer, output } => {
                export_layer_ipc(&storage, &layer, output)?
            }
            LayerCommands::Extract {
                layer,
                output,
                link_mode,
                fallback_to_copy,
                preserve_ownership,
                no_permissions,
            } => extract_layer_cmd(
                &cli.root,
                &layer,
                output,
                link_mode,
                fallback_to_copy,
                preserve_ownership,
                no_permissions,
            )?,
        },
        Commands::ResolveLink { link_id } => resolve_link(&storage, &link_id)?,
    }

    Ok(())
}

/// Parse a full image name into (repository, tag).
///
/// Splits on the last `:` to handle names like `docker.io/library/alpine:latest`.
/// If no `:` is found, returns the full name as repository with tag "<none>".
fn parse_repo_tag(name: &str) -> (String, String) {
    // Find the last colon, but be careful about ports in registry URLs
    // e.g., "localhost:5000/image:tag" should split as ("localhost:5000/image", "tag")
    // A tag can only appear after the last `/` segment
    if let Some(last_slash) = name.rfind('/') {
        let after_slash = &name[last_slash + 1..];
        if let Some(colon_offset) = after_slash.rfind(':') {
            let colon_pos = last_slash + 1 + colon_offset;
            return (
                name[..colon_pos].to_string(),
                name[colon_pos + 1..].to_string(),
            );
        }
    } else if let Some(colon_pos) = name.rfind(':') {
        // No slash, simple case like "alpine:latest"
        return (
            name[..colon_pos].to_string(),
            name[colon_pos + 1..].to_string(),
        );
    }
    // No tag found
    (name.to_string(), "<none>".to_string())
}

fn list_images(storage: &Storage, format: OutputFormat, no_trunc: bool) -> Result<()> {
    let images = storage.list_images().context("Failed to list images")?;

    let mut entries: Vec<ImageListEntry> = Vec::with_capacity(images.len());

    for image in &images {
        let names = image.names(storage).unwrap_or_default();
        let size = storage.calculate_image_size(image).unwrap_or(0);
        let created = image.created().ok().flatten();
        let manifest = image.manifest().context("Failed to read manifest")?;
        let layer_count = manifest.layers().len();

        let full_id = image.id().to_string();
        let id = if no_trunc {
            full_id.clone()
        } else {
            truncate_id(&full_id)
        };

        // Pre-format the creation time for display
        let created_display = created
            .map(format_time_ago)
            .unwrap_or_else(|| "N/A".to_string());

        if names.is_empty() {
            // No names - show as <none>:<none>
            entries.push(ImageListEntry {
                repository: "<none>".to_string(),
                tag: "<none>".to_string(),
                id: id.clone(),
                full_id: full_id.clone(),
                created: created_display.clone(),
                size,
                layers: layer_count,
            });
        } else {
            // Create an entry for each name
            for name in &names {
                let (repository, tag) = parse_repo_tag(name);
                entries.push(ImageListEntry {
                    repository,
                    tag,
                    id: id.clone(),
                    full_id: full_id.clone(),
                    created: created_display.clone(),
                    size,
                    layers: layer_count,
                });
            }
        }
    }

    output_slice(&entries, format).context("Failed to output images")?;

    Ok(())
}

/// Helper to open an image by ID (full or prefix) or name.
fn open_image_by_id_or_name(storage: &Storage, image_ref: &str) -> Result<Image> {
    // First try direct ID lookup (full ID)
    if let Ok(image) = Image::open(storage, image_ref) {
        return Ok(image);
    }

    // Try prefix matching on image IDs
    if image_ref.len() >= 3 {
        let images = storage.list_images().context("Failed to list images")?;
        let matches: Vec<_> = images
            .into_iter()
            .filter(|img| img.id().starts_with(image_ref))
            .collect();

        match matches.len() {
            1 => return Ok(matches.into_iter().next().unwrap()),
            n if n > 1 => {
                anyhow::bail!(
                    "ambiguous image ID prefix '{}' matches {} images",
                    image_ref,
                    n
                );
            }
            _ => {}
        }
    }

    // Fall back to name lookup
    storage
        .find_image_by_name(image_ref)
        .with_context(|| format!("image not found: {}", image_ref))
}

/// Helper to open a layer by ID (full or prefix) or link ID.
fn open_layer_by_id_or_link(storage: &Storage, layer_ref: &str) -> Result<Layer> {
    // First try direct ID lookup (full ID)
    if let Ok(layer) = Layer::open(storage, layer_ref) {
        return Ok(layer);
    }

    // Try resolving as a link ID (base32, 26 chars)
    if layer_ref.len() == 26
        && layer_ref.chars().all(|c| c.is_ascii_alphanumeric())
        && let Ok(layer_id) = storage.resolve_link(layer_ref)
        && let Ok(layer) = Layer::open(storage, &layer_id)
    {
        return Ok(layer);
    }

    // Try prefix matching on layer IDs
    if layer_ref.len() >= 3 {
        let overlay_dir = storage
            .root_dir()
            .open_dir("overlay")
            .context("Failed to open overlay directory")?;

        let mut matches: Vec<String> = Vec::new();
        for entry in overlay_dir
            .entries()
            .context("Failed to read overlay directory")?
        {
            let entry = entry.context("Failed to read directory entry")?;
            if entry.file_type()?.is_dir() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                // Skip the 'l' directory (link directory)
                if name_str != "l" && name_str.starts_with(layer_ref) {
                    matches.push(name_str.to_string());
                }
            }
        }

        match matches.len() {
            1 => return Layer::open(storage, &matches[0]).context("Failed to open layer"),
            n if n > 1 => {
                anyhow::bail!(
                    "ambiguous layer ID prefix '{}' matches {} layers",
                    layer_ref,
                    n
                );
            }
            _ => {}
        }
    }

    anyhow::bail!("layer not found: {}", layer_ref)
}

fn inspect_image(storage: &Storage, image_id: &str, format: OutputFormat) -> Result<()> {
    let image = open_image_by_id_or_name(storage, image_id)?;

    let manifest = image.manifest().context("Failed to read manifest")?;
    let names = image.names(storage).unwrap_or_default();
    let size = storage.calculate_image_size(&image).unwrap_or(0);
    let created = image.created().ok().flatten();

    // Build layer info
    let storage_layers = storage
        .get_image_layers(&image)
        .context("Failed to get image layers")?;

    let layer_count = storage_layers.len();

    // Pre-format for display
    let created_display = created
        .map(format_time_ago)
        .unwrap_or_else(|| "N/A".to_string());

    let output = ImageInspectOutput {
        id: image.id().to_string(),
        repo_tags: names.join(", "),
        created: created_display,
        size,
        schema_version: manifest.schema_version(),
        media_type: manifest.media_type().as_ref().map(|s| s.to_string()),
        config_digest: manifest.config().digest().to_string(),
        layer_count,
    };

    output_item(&output, format).context("Failed to output image")?;

    Ok(())
}

fn list_layers(storage: &Storage, image_id: &str, format: OutputFormat) -> Result<()> {
    let image = open_image_by_id_or_name(storage, image_id)?;

    let storage_layers = storage
        .get_image_layers(&image)
        .context("Failed to get image layers")?;

    let layers: Vec<LayerInfo> = storage_layers
        .iter()
        .enumerate()
        .map(|(i, layer)| {
            let diff_size = storage
                .get_layer_metadata(&layer.id)
                .ok()
                .and_then(|m| m.diff_size);
            LayerInfo {
                index: i,
                id: truncate_id(&layer.id),
                full_id: layer.id.clone(),
                link_id: layer.link_id().to_string(),
                parent_count: layer.parent_links().len(),
                diff_size,
            }
        })
        .collect();

    output_slice(&layers, format).context("Failed to output layers")?;

    Ok(())
}

fn inspect_layer(
    storage: &Storage,
    layer_ref: &str,
    show_chain: bool,
    format: OutputFormat,
) -> Result<()> {
    let layer = open_layer_by_id_or_link(storage, layer_ref)?;

    let metadata = storage.get_layer_metadata(&layer.id).ok();
    let parent_links = layer.parent_links();

    // Build parent chain if requested (as newline-separated string for display)
    let parent_chain: Option<String> = if show_chain {
        let chain: Vec<String> = parent_links
            .iter()
            .filter_map(|link_id| storage.resolve_link(link_id).ok())
            .collect();
        if chain.is_empty() {
            None
        } else {
            Some(chain.join("\n"))
        }
    } else {
        None
    };

    let info = LayerInspectOutput {
        id: layer.id.clone(),
        link_id: layer.link_id().to_string(),
        parent_count: parent_links.len(),
        diff_size: metadata.as_ref().and_then(|m| m.diff_size),
        compressed_size: metadata.as_ref().and_then(|m| m.compressed_size),
        parent_chain,
    };

    output_item(&info, format).context("Failed to output layer info")?;

    Ok(())
}

fn export_layer(storage: &Storage, layer_ref: &str, output: Option<PathBuf>) -> Result<()> {
    let layer = open_layer_by_id_or_link(storage, layer_ref)?;

    let mut stream =
        TarSplitFdStream::new(storage, &layer).context("Failed to create tar-split stream")?;

    let mut writer: Box<dyn Write> = if let Some(path) = output {
        Box::new(File::create(path).context("Failed to create output file")?)
    } else {
        Box::new(io::stdout())
    };

    use cstor_rs::TarSplitItem;
    use std::io::Read;

    let mut count = 0;
    while let Some(item) = stream.next()? {
        match item {
            TarSplitItem::Segment(bytes) => {
                // Write raw segment bytes (TAR headers and padding) directly
                writer
                    .write_all(&bytes)
                    .context("Failed to write segment")?;
            }
            TarSplitItem::FileContent { fd, size, .. } => {
                // Write file content WITHOUT padding - padding is in the next Segment
                let mut file = std::fs::File::from(fd);
                let mut remaining = size;
                let mut buffer = [0u8; 8192];

                while remaining > 0 {
                    let to_read = (remaining as usize).min(buffer.len());
                    let n = file
                        .read(&mut buffer[..to_read])
                        .context("Failed to read file data")?;
                    if n == 0 {
                        anyhow::bail!("Unexpected EOF while reading file data");
                    }
                    writer
                        .write_all(&buffer[..n])
                        .context("Failed to write file data")?;
                    remaining -= n as u64;
                }

                count += 1;
            }
        }
    }

    eprintln!("Exported {} file entries from layer {}", count, layer.id);

    Ok(())
}

fn copy_to_oci(storage: &Storage, image_id: &str, output: PathBuf) -> Result<()> {
    let image = open_image_by_id_or_name(storage, image_id)?;

    // Get storage layer IDs (resolved from diff_ids via layers.json)
    let layer_ids = image
        .storage_layer_ids(storage)
        .context("Failed to get layer IDs")?;

    // Create output directory structure
    std::fs::create_dir_all(&output).context("Failed to create output directory")?;

    let blobs_dir = output.join("blobs").join("sha256");
    std::fs::create_dir_all(&blobs_dir).context("Failed to create blobs directory")?;

    println!("Copying image {} to {}", image.id(), output.display());
    println!("Layers: {}", layer_ids.len());

    // Export each layer
    for (i, layer_id) in layer_ids.iter().enumerate() {
        println!("\n[{}/{}] Layer: {}", i + 1, layer_ids.len(), layer_id);

        let layer = Layer::open(storage, layer_id)
            .with_context(|| format!("Failed to open layer {}", layer_id))?;

        // Write compressed tar to a buffer first so we can compute its digest
        let mut tar_buf = Vec::new();
        let mut gz = flate2::write::GzEncoder::new(&mut tar_buf, flate2::Compression::default());

        let mut stream =
            TarSplitFdStream::new(storage, &layer).context("Failed to create tar-split stream")?;

        use cstor_rs::TarSplitItem;
        use std::io::Read;

        let mut entry_count = 0;
        while let Some(item) = stream.next()? {
            match item {
                TarSplitItem::Segment(bytes) => {
                    // Write raw segment bytes directly
                    gz.write_all(&bytes)?;
                }
                TarSplitItem::FileContent { fd, size, .. } => {
                    // Write file content WITHOUT padding - padding is in the next Segment
                    let mut file = std::fs::File::from(fd);
                    let mut remaining = size;
                    let mut buffer = [0u8; 8192];

                    while remaining > 0 {
                        let to_read = (remaining as usize).min(buffer.len());
                        let n = file.read(&mut buffer[..to_read])?;
                        if n == 0 {
                            anyhow::bail!("Unexpected EOF while reading file data");
                        }
                        gz.write_all(&buffer[..n])?;
                        remaining -= n as u64;
                    }

                    entry_count += 1;
                }
            }
        }

        gz.finish()?;

        // Compute digest of compressed tar
        let compressed_digest = format!("{:x}", sha2::Sha256::digest(&tar_buf));

        // Write compressed blob
        let blob_path = blobs_dir.join(&compressed_digest);
        std::fs::write(&blob_path, &tar_buf)
            .with_context(|| format!("Failed to write blob file {}", blob_path.display()))?;

        println!(
            "  Wrote {} entries ({} bytes compressed, digest: {})",
            entry_count,
            tar_buf.len(),
            compressed_digest
        );
    }

    // Write config blob (copy the original to preserve digest)
    use base64::{Engine, engine::general_purpose::STANDARD};
    let config_key = format!("sha256:{}", image.id());
    let encoded_key = STANDARD.encode(config_key.as_bytes());
    let config_json = image
        .read_metadata(&encoded_key)
        .context("Failed to read config")?;

    // The config blob should be named after the image ID
    let config_path = blobs_dir.join(image.id());
    std::fs::write(&config_path, &config_json).context("Failed to write config blob")?;
    println!("\nWrote config blob: {}", image.id());

    // Write manifest blob (read the original manifest file to preserve digest)
    let manifest_bytes = {
        let mut file = image.image_dir().open("manifest")?;
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut buf)?;
        buf
    };
    let manifest_digest = format!("{:x}", sha2::Sha256::digest(&manifest_bytes));
    let manifest_path = blobs_dir.join(&manifest_digest);
    std::fs::write(&manifest_path, &manifest_bytes).context("Failed to write manifest blob")?;
    println!("Wrote manifest blob: {}", manifest_digest);

    // Write index.json
    let index = serde_json::json!({
        "schemaVersion": 2,
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": format!("sha256:{}", manifest_digest),
            "size": manifest_bytes.len()
        }]
    });
    std::fs::write(
        output.join("index.json"),
        serde_json::to_string_pretty(&index)?,
    )
    .context("Failed to write index.json")?;

    // Write OCI layout file
    let oci_layout = r#"{"imageLayoutVersion":"1.0.0"}"#;
    std::fs::write(output.join("oci-layout"), oci_layout).context("Failed to write OCI layout")?;

    println!("\nSuccessfully copied image to {}", output.display());

    Ok(())
}

fn resolve_link(storage: &Storage, link_id: &str) -> Result<()> {
    let layer_id = storage
        .resolve_link(link_id)
        .context("Failed to resolve link")?;

    println!("{} -> {}", link_id, layer_id);

    Ok(())
}

fn output_toc(storage: &Storage, image_id: &str, pretty: bool) -> Result<()> {
    use cstor_rs::Toc;

    let image = open_image_by_id_or_name(storage, image_id)?;
    let toc = Toc::from_image(storage, &image).context("Failed to build TOC")?;

    let json = if pretty {
        serde_json::to_string_pretty(&toc).context("Failed to serialize TOC")?
    } else {
        serde_json::to_string(&toc).context("Failed to serialize TOC")?
    };

    println!("{}", json);
    Ok(())
}

/// Resolve a layer reference to a full layer ID.
///
/// This handles short IDs, link IDs, and full IDs.
fn resolve_layer_id(storage: &Storage, layer_ref: &str) -> Result<String> {
    // First try direct ID lookup (full ID)
    if Layer::open(storage, layer_ref).is_ok() {
        return Ok(layer_ref.to_string());
    }

    // Try resolving as a link ID (base32, 26 chars)
    if layer_ref.len() == 26
        && layer_ref.chars().all(|c| c.is_ascii_alphanumeric())
        && let Ok(layer_id) = storage.resolve_link(layer_ref)
        && Layer::open(storage, &layer_id).is_ok()
    {
        return Ok(layer_id);
    }

    // Try prefix matching on layer IDs
    if layer_ref.len() >= 3 {
        let overlay_dir = storage
            .root_dir()
            .open_dir("overlay")
            .context("Failed to open overlay directory")?;

        let mut matches: Vec<String> = Vec::new();
        for entry in overlay_dir
            .entries()
            .context("Failed to read overlay directory")?
        {
            let entry = entry.context("Failed to read directory entry")?;
            if entry.file_type()?.is_dir() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                // Skip the 'l' directory (link directory)
                if name_str != "l" && name_str.starts_with(layer_ref) {
                    matches.push(name_str.to_string());
                }
            }
        }

        match matches.len() {
            1 => return Ok(matches.into_iter().next().unwrap()),
            n if n > 1 => {
                anyhow::bail!(
                    "ambiguous layer ID prefix '{}' matches {} layers",
                    layer_ref,
                    n
                );
            }
            _ => {}
        }
    }

    anyhow::bail!("layer not found: {}", layer_ref)
}

/// Extract a layer to a directory using ProxiedStorage.
///
/// Uses the ProxiedStorage API for transparent access in both privileged
/// and unprivileged modes.
fn extract_layer_cmd(
    storage_root: &Option<PathBuf>,
    layer_ref: &str,
    dest: PathBuf,
    link_mode: CliLinkMode,
    fallback_to_copy: bool,
    preserve_ownership: bool,
    no_permissions: bool,
) -> Result<()> {
    use cstor_rs::ProxiedStorage;
    use cstor_rs::extract::ExtractionOptions;
    use std::time::Instant;

    // Validate destination doesn't exist
    if dest.exists() {
        anyhow::bail!("Destination directory already exists: {}", dest.display());
    }
    let parent = dest.parent().context("Destination path has no parent")?;
    if !parent.exists() {
        anyhow::bail!("Parent directory does not exist: {}", parent.display());
    }

    // Create destination directory
    std::fs::create_dir(&dest).context("Failed to create destination directory")?;
    let dest_dir = Dir::open_ambient_dir(&dest, ambient_authority())
        .context("Failed to open destination directory")?;

    // Build extraction options with appropriate hardlink filter
    let hardlink_filter = match link_mode {
        CliLinkMode::Hardlink => Some(std::sync::Arc::new(
            cstor_rs::extract::DefaultHardlinkFilter,
        ) as std::sync::Arc<dyn cstor_rs::extract::HardlinkFilter>),
        _ => None,
    };
    let options = ExtractionOptions {
        link_mode: link_mode.into(),
        fallback_to_copy,
        hardlink_filter,
        preserve_ownership,
        preserve_permissions: !no_permissions,
        process_whiteouts: true,
    };

    // Determine storage path
    let storage_path = match storage_root {
        Some(root) => root.clone(),
        None => discover_storage_path()?,
    };

    // First resolve the layer reference to a full ID using read-only storage access
    // This allows short IDs and link IDs to work
    let layer_id = {
        let storage = Storage::open(&storage_path).context("Failed to open storage for lookup")?;
        resolve_layer_id(&storage, layer_ref)?
    };

    // Create tokio runtime for async ProxiedStorage operations
    let rt = tokio::runtime::Runtime::new().context("Failed to create tokio runtime")?;

    rt.block_on(async {
        let start = Instant::now();

        // Open storage with proxy support if needed
        let mut storage = ProxiedStorage::open_with_proxy(&storage_path)
            .await
            .map_err(|e| anyhow!("Failed to open storage: {}", e))?;

        if storage.is_proxied() {
            eprintln!("Using proxied storage via userns helper");
        }

        eprintln!("Extracting layer {} to {}", layer_id, dest.display());

        // Extract the layer
        let stats = storage
            .extract_layer(&layer_id, &dest_dir, &options)
            .await
            .map_err(|e| anyhow!("Extraction failed: {}", e))?;

        let elapsed = start.elapsed();

        // Print stats
        eprintln!();
        eprintln!("Extraction completed in {:.2}s", elapsed.as_secs_f64());
        eprintln!("  Files:      {}", stats.files_extracted);
        eprintln!("  Directories: {}", stats.directories_created);
        eprintln!("  Symlinks:   {}", stats.symlinks_created);
        eprintln!("  Hardlinks:  {}", stats.hardlinks_created);
        if stats.whiteouts_processed > 0 {
            eprintln!("  Whiteouts:  {}", stats.whiteouts_processed);
        }
        if stats.entries_skipped > 0 {
            eprintln!(
                "  Skipped:    {} (device files, etc.)",
                stats.entries_skipped
            );
        }
        eprintln!();
        if stats.bytes_reflinked > 0 {
            eprintln!(
                "  Bytes reflinked:  {} ({:.2} MB)",
                stats.bytes_reflinked,
                stats.bytes_reflinked as f64 / (1024.0 * 1024.0)
            );
        }
        if stats.bytes_hardlinked > 0 {
            eprintln!(
                "  Bytes hardlinked: {} ({:.2} MB)",
                stats.bytes_hardlinked,
                stats.bytes_hardlinked as f64 / (1024.0 * 1024.0)
            );
        }
        if stats.bytes_copied > 0 {
            eprintln!(
                "  Bytes copied:     {} ({:.2} MB)",
                stats.bytes_copied,
                stats.bytes_copied as f64 / (1024.0 * 1024.0)
            );
        }

        // Shutdown proxy if used
        storage
            .shutdown()
            .await
            .map_err(|e| anyhow!("Failed to shutdown proxy: {}", e))?;

        Ok(())
    })
}

/// Extract an image to a directory using ProxiedStorage.
///
/// Flattens all layers and extracts to the destination directory using
/// the ProxiedStorage API for transparent access in both privileged
/// and unprivileged modes.
fn extract_image_cmd(
    storage_root: &Option<PathBuf>,
    image_ref: &str,
    dest: PathBuf,
    link_mode: CliLinkMode,
    fallback_to_copy: bool,
    preserve_ownership: bool,
    no_permissions: bool,
) -> Result<()> {
    use cstor_rs::ProxiedStorage;
    use cstor_rs::extract::ExtractionOptions;
    use std::time::Instant;

    // Validate destination doesn't exist
    if dest.exists() {
        anyhow::bail!("Destination directory already exists: {}", dest.display());
    }
    let parent = dest.parent().context("Destination path has no parent")?;
    if !parent.exists() {
        anyhow::bail!("Parent directory does not exist: {}", parent.display());
    }

    // Create destination directory
    std::fs::create_dir(&dest).context("Failed to create destination directory")?;
    let dest_dir = Dir::open_ambient_dir(&dest, ambient_authority())
        .context("Failed to open destination directory")?;

    // Build extraction options with appropriate hardlink filter
    let hardlink_filter = match link_mode {
        CliLinkMode::Hardlink => Some(std::sync::Arc::new(
            cstor_rs::extract::DefaultHardlinkFilter,
        ) as std::sync::Arc<dyn cstor_rs::extract::HardlinkFilter>),
        _ => None,
    };
    let options = ExtractionOptions {
        link_mode: link_mode.into(),
        fallback_to_copy,
        hardlink_filter,
        preserve_ownership,
        preserve_permissions: !no_permissions,
        process_whiteouts: true,
    };

    // Determine storage path
    let storage_path = match storage_root {
        Some(root) => root.clone(),
        None => discover_storage_path()?,
    };

    // Create tokio runtime for async ProxiedStorage operations
    let rt = tokio::runtime::Runtime::new().context("Failed to create tokio runtime")?;

    rt.block_on(async {
        let start = Instant::now();

        // Open storage with proxy support if needed
        let mut storage = ProxiedStorage::open_with_proxy(&storage_path)
            .await
            .map_err(|e| anyhow!("Failed to open storage: {}", e))?;

        if storage.is_proxied() {
            eprintln!("Using proxied storage via userns helper");
        }

        eprintln!("Extracting image {} to {}", image_ref, dest.display());

        // Extract the image (all layers merged)
        let stats = storage
            .extract_image(image_ref, &dest_dir, &options)
            .await
            .map_err(|e| anyhow!("Extraction failed: {}", e))?;

        let elapsed = start.elapsed();

        // Print stats
        eprintln!();
        eprintln!("Extraction completed in {:.2}s", elapsed.as_secs_f64());
        eprintln!("  Files:      {}", stats.files_extracted);
        eprintln!("  Directories: {}", stats.directories_created);
        eprintln!("  Symlinks:   {}", stats.symlinks_created);
        eprintln!("  Hardlinks:  {}", stats.hardlinks_created);
        if stats.whiteouts_processed > 0 {
            eprintln!("  Whiteouts:  {}", stats.whiteouts_processed);
        }
        if stats.entries_skipped > 0 {
            eprintln!(
                "  Skipped:    {} (device files, etc.)",
                stats.entries_skipped
            );
        }
        eprintln!();
        if stats.bytes_reflinked > 0 {
            eprintln!(
                "  Bytes reflinked:  {} ({:.2} MB)",
                stats.bytes_reflinked,
                stats.bytes_reflinked as f64 / (1024.0 * 1024.0)
            );
        }
        if stats.bytes_hardlinked > 0 {
            eprintln!(
                "  Bytes hardlinked: {} ({:.2} MB)",
                stats.bytes_hardlinked,
                stats.bytes_hardlinked as f64 / (1024.0 * 1024.0)
            );
        }
        if stats.bytes_copied > 0 {
            eprintln!(
                "  Bytes copied:     {} ({:.2} MB)",
                stats.bytes_copied,
                stats.bytes_copied as f64 / (1024.0 * 1024.0)
            );
        }

        // Shutdown proxy if used
        storage
            .shutdown()
            .await
            .map_err(|e| anyhow!("Failed to shutdown proxy: {}", e))?;

        Ok(())
    })
}

/// Discover the default storage path.
///
/// This mirrors the logic in Storage::discover() but returns the path
/// rather than opening the storage.
fn discover_storage_path() -> Result<PathBuf> {
    use std::env;

    // 1. Check CONTAINERS_STORAGE_ROOT environment variable
    if let Ok(root) = env::var("CONTAINERS_STORAGE_ROOT") {
        let path = PathBuf::from(&root);
        if path.exists() {
            return Ok(path);
        }
    }

    // 2. Check rootless locations
    if let Ok(home) = env::var("HOME") {
        let home_path = PathBuf::from(&home);

        // Try XDG_DATA_HOME first
        if let Ok(xdg_data) = env::var("XDG_DATA_HOME") {
            let path = PathBuf::from(xdg_data).join("containers/storage");
            if path.exists() {
                return Ok(path);
            }
        }

        // Fallback to ~/.local/share/containers/storage
        let path = home_path.join(".local/share/containers/storage");
        if path.exists() {
            return Ok(path);
        }
    }

    // 3. Check root location
    let path = PathBuf::from("/var/lib/containers/storage");
    if path.exists() {
        return Ok(path);
    }

    anyhow::bail!("No valid storage location found. Searched default locations.")
}

/// Export a layer via the IPC protocol (PoC demonstration).
///
/// This function demonstrates the JSON-RPC fd-passing protocol by:
/// 1. Creating a socketpair
/// 2. Spawning a tokio task to run the RpcServer
/// 3. Acting as the client sending GetLayerSplitfdstream request
/// 4. Receiving the response with file descriptors
/// 5. Reconstructing the tar from splitfdstream + fds
///
/// This validates that the wire format works correctly over Unix sockets.
fn export_layer_ipc(storage: &Storage, layer_ref: &str, output: Option<PathBuf>) -> Result<()> {
    use cstor_rs::protocol::GetLayerSplitfdstreamParams;
    use cstor_rs::server::RpcServer;
    use cstor_rs::splitfdstream::reconstruct_tar_seekable;
    use jsonrpc_fdpass::transport::UnixSocketTransport;
    use jsonrpc_fdpass::{JsonRpcMessage, JsonRpcRequest, MessageWithFds};
    use std::io::Read;
    use tokio::net::UnixStream;

    // Validate the layer exists and resolve to full ID before setting up IPC
    let layer = open_layer_by_id_or_link(storage, layer_ref)?;
    let layer_id = layer.id.clone();

    // For the server task, we need to re-discover storage since Storage is not Clone.
    // This is acceptable for a PoC - in production, the server would be a separate process.
    let _ = storage; // We've validated the layer, now drop reference

    // Create tokio runtime for async operations
    let rt = tokio::runtime::Runtime::new().context("Failed to create tokio runtime")?;

    rt.block_on(async {
        // Create a socketpair for IPC
        let (server_sock, client_sock) =
            UnixStream::pair().context("Failed to create socket pair")?;

        // Spawn the server in a blocking task since Storage contains rusqlite which is not Send
        let layer_id_clone = layer_id.to_string();
        let server_handle = tokio::task::spawn_blocking(move || {
            // Create a new runtime for the server since we're in spawn_blocking
            let rt = tokio::runtime::Runtime::new().expect("Failed to create server runtime");
            rt.block_on(async move {
                let server_storage =
                    Storage::discover().expect("Failed to discover storage in server task");
                let mut server = RpcServer::new(server_sock, server_storage);
                server.run().await.expect("Server failed");
            });
        });

        // Client side: create transport and send request
        let transport = UnixSocketTransport::new(client_sock);
        let (mut sender, mut receiver) = transport.split();

        // Send GetLayerSplitfdstream request
        let params = GetLayerSplitfdstreamParams {
            layer: layer_id_clone,
            compressed: false,
        };
        let request = JsonRpcRequest::new(
            "GetLayerSplitfdstream".to_string(),
            Some(serde_json::to_value(&params).context("Failed to serialize params")?),
            serde_json::Value::Number(1.into()),
        );
        let message = MessageWithFds::new(JsonRpcMessage::Request(request), vec![]);
        sender
            .send(message)
            .await
            .map_err(|e| anyhow!("Failed to send request: {}", e))?;

        // Receive response with fds
        let response = receiver
            .receive()
            .await
            .map_err(|e| anyhow!("Failed to receive response: {}", e))?;

        // Check for errors in response
        let resp = match response.message {
            JsonRpcMessage::Response(r) => r,
            other => anyhow::bail!("Expected Response, got {:?}", other),
        };

        if let Some(error) = resp.error {
            anyhow::bail!(
                "Server returned error {}: {}",
                error.code(),
                error.message()
            );
        }

        // Extract fds: fd[0] = splitfdstream, fd[1..n] = content fds
        let mut fds = response.file_descriptors;
        if fds.is_empty() {
            anyhow::bail!("No file descriptors received in response");
        }

        // fd[0] is the splitfdstream data
        let stream_fd = fds.remove(0);
        let content_fds = fds; // remaining fds are content

        // Read the splitfdstream from the memfd
        let mut stream_file = std::fs::File::from(stream_fd);
        let mut stream_data = Vec::new();
        stream_file
            .read_to_end(&mut stream_data)
            .context("Failed to read splitfdstream from fd")?;

        // Reconstruct the tar to output
        let mut output_writer: Box<dyn Write> = match &output {
            Some(path) => Box::new(
                File::create(path)
                    .with_context(|| format!("Failed to create output file: {}", path.display()))?,
            ),
            None => Box::new(io::stdout().lock()),
        };

        // Convert OwnedFds to Files for read_at
        let content_files: Vec<std::fs::File> =
            content_fds.into_iter().map(std::fs::File::from).collect();

        let bytes_written =
            reconstruct_tar_seekable(stream_data.as_slice(), &content_files, &mut output_writer)
                .context("Failed to reconstruct tar from splitfdstream")?;

        // Drop sender to close the connection, allowing server to exit
        drop(sender);
        drop(receiver);

        // Wait for server to finish (with timeout)
        tokio::select! {
            result = server_handle => {
                result.context("Server task panicked")?;
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                // Server didn't exit cleanly, but that's OK for this PoC
            }
        }

        if output.is_some() {
            eprintln!("Wrote {} bytes via IPC protocol", bytes_written);
        }

        Ok(())
    })
}
