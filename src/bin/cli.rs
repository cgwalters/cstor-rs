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

use anyhow::{Context, Result, anyhow};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, Permissions};
use clap::{Parser, Subcommand};
use cstor_rs::*;
use sha2::Digest;
use std::fs::File;
use std::io::{self, Write};
use std::ops::Deref;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

/// Environment variable set when we've re-execed into a user namespace
const USERNS_ENV: &str = "CSTOR_IN_USERNS";

#[derive(Parser)]
#[command(name = "cstor-rs")]
#[command(about = "Read and manipulate containers-storage (overlay driver)", long_about = None)]
struct Cli {
    /// Path to storage root (default: auto-discover)
    #[arg(short, long, global = true)]
    root: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all images in storage
    ListImages {
        /// Show detailed information
        #[arg(short, long)]
        verbose: bool,
    },

    /// Show information about a specific image
    InspectImage {
        /// Image ID or name
        image_id: String,

        /// Show layers
        #[arg(short, long)]
        layers: bool,
    },

    /// List layers for an image
    ListLayers {
        /// Image ID
        image_id: String,
    },

    /// Inspect a specific layer
    InspectLayer {
        /// Layer ID
        layer_id: String,

        /// Show parent chain
        #[arg(short, long)]
        chain: bool,
    },

    /// Export layer as tar stream
    ExportLayer {
        /// Layer ID
        layer_id: String,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Copy image to OCI directory layout
    ///
    /// This command reassembles tar streams from file descriptors,
    /// demonstrating zero-copy access to layer content.
    CopyToOci {
        /// Image ID
        image_id: String,

        /// Output OCI directory
        output: PathBuf,
    },

    /// Resolve a link ID to layer ID
    ResolveLink {
        /// Short link ID (26 chars)
        link_id: String,
    },

    /// Extract image to directory using reflinks
    ///
    /// Flattens all layers and extracts to the destination directory.
    /// Files are reflinked from the source storage when possible,
    /// avoiding data duplication on filesystems that support it (btrfs, XFS).
    ReflinkToDir {
        /// Image ID
        image_id: String,

        /// Destination directory (must not exist)
        output: PathBuf,

        /// Fall back to copying if reflinks are not supported
        #[arg(long)]
        force_copy: bool,

        /// Use splitfdstream path for extraction (experimental)
        ///
        /// Instead of using the TOC-based approach, this uses splitfdstream
        /// to get file descriptors for layer content. The splitfdstream
        /// encodes tar metadata inline and references file content via fds.
        #[arg(long)]
        use_splitfdstream: bool,
    },

    /// Output Table of Contents (TOC) for an image as JSON
    ///
    /// The TOC contains metadata for all files across all layers,
    /// in a format compatible with eStargz.
    Toc {
        /// Image ID
        image_id: String,

        /// Pretty-print the JSON output
        #[arg(long)]
        pretty: bool,
    },

    /// Export layer as tar stream via IPC protocol (PoC)
    ///
    /// This command demonstrates the JSON-RPC fd-passing protocol
    /// by streaming tar-split data through a socketpair internally.
    /// The server sends NDJSON messages with fds, and the client
    /// reconstructs the tar archive.
    ExportLayerIpc {
        /// Layer ID
        layer_id: String,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

/// Check if we need to enter a user namespace for file access.
///
/// Returns `true` if we're running as a non-root user and haven't already
/// re-execed into a user namespace via `podman unshare`.
fn needs_userns() -> bool {
    // Already in userns from our re-exec
    if std::env::var(USERNS_ENV).is_ok() {
        return false;
    }

    // Running as real root doesn't need userns
    if rustix::process::getuid().is_root() {
        return false;
    }

    // Non-root user needs userns for proper UID/GID mapping
    true
}

/// Re-execute this binary via `podman unshare` to enter a user namespace.
///
/// This function does not return on success - it replaces the current process.
fn reexec_in_userns() -> Result<std::convert::Infallible> {
    let exe = std::fs::read_link("/proc/self/exe").context("Failed to read /proc/self/exe")?;

    let args: Vec<String> = std::env::args().collect();

    // Use exec() to replace the current process
    let err = Command::new("podman")
        .arg("unshare")
        .arg(&exe)
        .args(&args[1..])
        .env(USERNS_ENV, "1")
        .exec();

    // exec() only returns on error
    Err(err).context("Failed to exec podman unshare")
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Check if this command needs user namespace access for file content
    let needs_file_access = matches!(
        cli.command,
        Commands::ExportLayer { .. }
            | Commands::CopyToOci { .. }
            | Commands::ReflinkToDir { .. }
            | Commands::ExportLayerIpc { .. }
    );

    // Re-exec via podman unshare if needed
    if needs_file_access && needs_userns() {
        reexec_in_userns()?;
    }

    // Open storage
    let storage = if let Some(ref root) = cli.root {
        Storage::open(root).context("Failed to open storage")?
    } else {
        Storage::discover().context("Failed to discover storage")?
    };

    match cli.command {
        Commands::ListImages { verbose } => list_images(&storage, verbose)?,
        Commands::InspectImage { image_id, layers } => inspect_image(&storage, &image_id, layers)?,
        Commands::ListLayers { image_id } => list_layers(&storage, &image_id)?,
        Commands::InspectLayer { layer_id, chain } => inspect_layer(&storage, &layer_id, chain)?,
        Commands::ExportLayer { layer_id, output } => export_layer(&storage, &layer_id, output)?,
        Commands::CopyToOci { image_id, output } => copy_to_oci(&storage, &image_id, output)?,
        Commands::ResolveLink { link_id } => resolve_link(&storage, &link_id)?,
        Commands::ReflinkToDir {
            image_id,
            output,
            force_copy,
            use_splitfdstream,
        } => reflink_to_dir(&storage, &image_id, output, force_copy, use_splitfdstream)?,
        Commands::Toc { image_id, pretty } => output_toc(&storage, &image_id, pretty)?,
        Commands::ExportLayerIpc { layer_id, output } => {
            export_layer_ipc(&storage, &layer_id, output)?
        }
    }

    Ok(())
}

fn list_images(storage: &Storage, verbose: bool) -> Result<()> {
    let images = storage.list_images().context("Failed to list images")?;

    println!("Found {} images", images.len());

    for image in &images {
        println!("\n{}", image.id());

        if verbose {
            let manifest = image.manifest().context("Failed to read manifest")?;
            println!("  Schema: {}", manifest.schema_version());
            if let Some(media_type) = manifest.media_type() {
                println!("  Media type: {}", media_type);
            }
            let layers = manifest.layers();
            println!("  Layers: {}", layers.len());
            for (i, layer) in layers.iter().take(3).enumerate() {
                println!("    {}: {} ({} bytes)", i + 1, layer.digest(), layer.size());
            }
            if layers.len() > 3 {
                println!("    ... and {} more layers", layers.len() - 3);
            }
        }
    }

    Ok(())
}

/// Helper to open an image by ID or name.
fn open_image_by_id_or_name(storage: &Storage, image_ref: &str) -> Result<Image> {
    // First try direct ID lookup
    if let Ok(image) = Image::open(storage, image_ref) {
        return Ok(image);
    }

    // Fall back to name lookup
    storage
        .find_image_by_name(image_ref)
        .with_context(|| format!("image not found: {}", image_ref))
}

fn inspect_image(storage: &Storage, image_id: &str, show_layers: bool) -> Result<()> {
    let image = open_image_by_id_or_name(storage, image_id)?;

    println!("Image: {}", image.id());

    let manifest = image.manifest().context("Failed to read manifest")?;
    println!("Schema version: {}", manifest.schema_version());
    if let Some(media_type) = manifest.media_type() {
        println!("Media type: {}", media_type);
    }
    println!("Config: {}", manifest.config().digest());
    println!("\nLayers: {}", manifest.layers().len());

    if show_layers {
        for (i, layer) in manifest.layers().iter().enumerate() {
            println!("  {}: {} ({} bytes)", i + 1, layer.digest(), layer.size());
        }
    }

    Ok(())
}

fn list_layers(storage: &Storage, image_id: &str) -> Result<()> {
    let image = open_image_by_id_or_name(storage, image_id)?;

    let layers = storage
        .get_image_layers(&image)
        .context("Failed to get image layers")?;

    println!("Image {} has {} layers:", image.id(), layers.len());

    for (i, layer) in layers.iter().enumerate() {
        println!("\n  Layer {}: {}", i + 1, layer.id);
        println!("    Link ID: {}", layer.link_id());
        let parent_links = layer.parent_links();
        if !parent_links.is_empty() {
            println!("    Parents: {}", parent_links.len());
        }
    }

    Ok(())
}

fn inspect_layer(storage: &Storage, layer_id: &str, show_chain: bool) -> Result<()> {
    let layer = Layer::open(storage, layer_id).context("Failed to open layer")?;

    println!("Layer: {}", layer.id);
    println!("Link ID: {}", layer.link_id());

    let parent_links = layer.parent_links();
    println!("Parents: {}", parent_links.len());

    if show_chain && !parent_links.is_empty() {
        println!("\nParent chain:");
        for (i, link_id) in parent_links.iter().enumerate() {
            match storage.resolve_link(link_id) {
                Ok(parent_id) => println!("  {}: {}", i + 1, parent_id),
                Err(e) => println!("  {}: {} (error: {})", i + 1, link_id, e),
            }
        }
    }

    Ok(())
}

fn export_layer(storage: &Storage, layer_id: &str, output: Option<PathBuf>) -> Result<()> {
    let layer = Layer::open(storage, layer_id).context("Failed to open layer")?;

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

    eprintln!("Exported {} file entries from layer {}", count, layer_id);

    Ok(())
}

fn copy_to_oci(storage: &Storage, image_id: &str, output: PathBuf) -> Result<()> {
    let image = open_image_by_id_or_name(storage, image_id)?;

    // Get layer IDs from the image config (diff_ids)
    let layer_ids = image.layers().context("Failed to get layer IDs")?;

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

fn reflink_to_dir(
    storage: &Storage,
    image_id: &str,
    dest: PathBuf,
    force_copy: bool,
    use_splitfdstream: bool,
) -> Result<()> {
    let image = open_image_by_id_or_name(storage, image_id)?;

    // Require parent directory to exist, but destination must not exist
    if dest.exists() {
        anyhow::bail!("Destination directory already exists: {}", dest.display());
    }
    let parent = dest.parent().context("Destination path has no parent")?;
    if !parent.exists() {
        anyhow::bail!("Parent directory does not exist: {}", parent.display());
    }

    // Create destination directory and open as Dir
    std::fs::create_dir(&dest).context("Failed to create destination directory")?;
    let dest_dir = Dir::open_ambient_dir(&dest, ambient_authority())
        .context("Failed to open destination directory")?;

    if use_splitfdstream {
        reflink_to_dir_splitfdstream(storage, &image, &dest_dir, &dest, force_copy)
    } else {
        reflink_to_dir_toc(storage, &image, &dest_dir, &dest, force_copy)
    }
}

/// Extract image using TOC-based approach (original implementation).
fn reflink_to_dir_toc(
    storage: &Storage,
    image: &cstor_rs::Image,
    dest_dir: &Dir,
    dest: &std::path::Path,
    force_copy: bool,
) -> Result<()> {
    use cstor_rs::Toc;
    use std::collections::HashMap;

    // Build merged TOC with layer mapping
    // This properly handles whiteouts - files deleted in upper layers won't appear
    let (toc, layer_map) =
        Toc::from_image_with_layers(storage, image).context("Failed to build merged TOC")?;

    eprintln!(
        "Extracting {} entries to {}",
        toc.entries.len(),
        dest.display()
    );

    // Cache opened layers to avoid reopening
    let mut layer_cache: HashMap<String, Layer> = HashMap::new();

    // Extract each entry from its source layer
    for entry in &toc.entries {
        let layer_id = layer_map
            .get(&entry.name)
            .with_context(|| format!("No layer mapping for entry: {}", entry.name.display()))?;

        // Get or open the layer (using entry API for efficiency)
        if !layer_cache.contains_key(layer_id) {
            let layer = Layer::open(storage, layer_id)
                .with_context(|| format!("Failed to open layer {}", layer_id))?;
            layer_cache.insert(layer_id.clone(), layer);
        }
        let layer = layer_cache.get(layer_id).unwrap();

        extract_toc_entry(dest_dir, layer, entry, force_copy)?;
    }

    eprintln!("Successfully extracted image to {}", dest.display());
    Ok(())
}

/// Extract image using splitfdstream approach.
fn reflink_to_dir_splitfdstream(
    storage: &Storage,
    image: &cstor_rs::Image,
    dest_dir: &Dir,
    dest: &std::path::Path,
    force_copy: bool,
) -> Result<()> {
    use cstor_rs::splitfdstream::extract_to_dir;
    use cstor_rs::{DEFAULT_INLINE_THRESHOLD, layer_to_splitfdstream};

    let layer_ids = image.layers().context("Failed to get layer IDs")?;

    eprintln!(
        "Extracting {} layers to {} (using splitfdstream)",
        layer_ids.len(),
        dest.display()
    );

    let mut total_stats = cstor_rs::splitfdstream::ExtractionStats::default();

    // Process each layer in order (base to top)
    // Process each layer in order (base to top), with later layers overwriting
    // earlier ones. Whiteout files are processed for proper overlay semantics:
    // - Regular whiteouts (.wh.<name>) remove the target file/directory
    // - Opaque whiteouts (.wh..wh..opq) clear all contents from the directory
    for (i, layer_id) in layer_ids.iter().enumerate() {
        eprintln!(
            "[{}/{}] Processing layer: {}",
            i + 1,
            layer_ids.len(),
            layer_id
        );

        let layer = Layer::open(storage, layer_id)
            .with_context(|| format!("Failed to open layer {}", layer_id))?;

        // Convert layer to splitfdstream
        let splitfd = layer_to_splitfdstream(storage, &layer, DEFAULT_INLINE_THRESHOLD)
            .with_context(|| format!("Failed to convert layer {} to splitfdstream", layer_id))?;

        // Extract from splitfdstream
        let stats = extract_to_dir(
            splitfd.stream.as_slice(),
            &splitfd.files,
            dest_dir,
            force_copy,
        )
        .with_context(|| format!("Failed to extract layer {}", layer_id))?;

        eprintln!(
            "  {} files, {} dirs, {} symlinks, {} whiteouts, {} bytes reflinked, {} bytes copied, {} bytes inline",
            stats.files_extracted,
            stats.directories_created,
            stats.symlinks_created,
            stats.whiteouts_processed,
            stats.bytes_reflinked,
            stats.bytes_copied,
            stats.bytes_inline
        );

        // Accumulate stats
        total_stats.files_extracted += stats.files_extracted;
        total_stats.directories_created += stats.directories_created;
        total_stats.symlinks_created += stats.symlinks_created;
        total_stats.hardlinks_created += stats.hardlinks_created;
        total_stats.whiteouts_processed += stats.whiteouts_processed;
        total_stats.bytes_reflinked += stats.bytes_reflinked;
        total_stats.bytes_copied += stats.bytes_copied;
        total_stats.bytes_inline += stats.bytes_inline;
    }

    eprintln!(
        "Successfully extracted image to {} ({} files, {} dirs, {} bytes reflinked, {} bytes copied)",
        dest.display(),
        total_stats.files_extracted,
        total_stats.directories_created,
        total_stats.bytes_reflinked,
        total_stats.bytes_copied
    );

    Ok(())
}

enum ParentDir<'a> {
    Owned(Dir),
    Ref(&'a Dir),
}

impl<'a> Deref for ParentDir<'a> {
    type Target = Dir;

    fn deref(&self) -> &Self::Target {
        match self {
            ParentDir::Owned(dir) => dir,
            ParentDir::Ref(dir) => dir,
        }
    }
}

/// Extract a single TOC entry to the destination directory.
fn extract_toc_entry(
    dest: &Dir,
    layer: &Layer,
    entry: &cstor_rs::TocEntry,
    force_copy: bool,
) -> Result<()> {
    use cstor_rs::TocEntryType;
    use rustix::fs::ioctl_ficlone;

    let path = &entry.name;

    // Skip empty paths
    if path.as_os_str().is_empty() {
        return Ok(());
    }

    // Create parent directories if needed
    let parent = if let Some(parent_path) = path.parent().filter(|v| !v.as_os_str().is_empty()) {
        dest.create_dir_all(parent_path)
            .with_context(|| format!("Failed to create parent directory {:?}", parent_path))?;
        ParentDir::Owned(
            dest.open_dir(parent_path)
                .with_context(|| format!("Failed to open parent directory {:?}", parent_path))?,
        )
    } else {
        ParentDir::Ref(dest)
    };

    let Some(filename) = path.file_name() else {
        return Ok(()); // Skip entries with no filename component
    };

    match entry.entry_type {
        TocEntryType::Dir => {
            match parent.create_dir(filename) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("Failed to create directory {:?}", path))?;
                }
            }
            let std_perms = std::fs::Permissions::from_mode(entry.mode);
            let perms = Permissions::from_std(std_perms);
            parent
                .set_permissions(filename, perms)
                .with_context(|| format!("Failed to set permissions for {:?}", path))?;
        }
        TocEntryType::Symlink => {
            let link_target = entry.link_name.as_deref().unwrap_or("");
            let _ = parent.remove_file(filename);
            parent
                .symlink(link_target, filename)
                .with_context(|| format!("Failed to create symlink {:?}", path))?;
        }
        TocEntryType::Reg => {
            let _ = parent.remove_file(filename);
            let dst_file = parent
                .create(filename)
                .with_context(|| format!("Failed to create file {:?}", path))?;

            // Only copy content if file has size > 0
            if entry.size.unwrap_or(0) > 0 {
                let mut src_file = layer
                    .open_file_std(&entry.name)
                    .with_context(|| format!("Failed to open source file {:?}", entry.name))?;

                match ioctl_ficlone(&dst_file, &src_file) {
                    Ok(_) => {}
                    Err(e) => {
                        if force_copy {
                            let mut dst = dst_file.into_std();
                            std::io::copy(&mut src_file, &mut dst)
                                .with_context(|| format!("Failed to copy file {:?}", path))?;
                        } else {
                            return Err(anyhow!("Reflink failed for {:?}: {}", path, e));
                        }
                    }
                }
            }

            let std_perms = std::fs::Permissions::from_mode(entry.mode);
            let perms = Permissions::from_std(std_perms);
            parent
                .set_permissions(filename, perms)
                .with_context(|| format!("Failed to set permissions for {:?}", path))?;
        }
        TocEntryType::Hardlink => {
            let link_target = entry.link_name.as_deref().unwrap_or("");
            let _ = parent.remove_file(filename);
            dest.hard_link(link_target, &parent, filename)
                .with_context(|| {
                    format!("Failed to create hard link {:?} -> {:?}", path, link_target)
                })?;
        }
        TocEntryType::Char | TocEntryType::Block | TocEntryType::Fifo => {
            // Skip device files and FIFOs - can't create as unprivileged user
        }
    }

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
fn export_layer_ipc(storage: &Storage, layer_id: &str, output: Option<PathBuf>) -> Result<()> {
    use cstor_rs::protocol::GetLayerSplitfdstreamParams;
    use cstor_rs::server::RpcServer;
    use cstor_rs::splitfdstream::reconstruct_tar_seekable;
    use jsonrpc_fdpass::transport::UnixSocketTransport;
    use jsonrpc_fdpass::{JsonRpcMessage, JsonRpcRequest, MessageWithFds};
    use std::io::Read;
    use tokio::net::UnixStream;

    // Validate the layer exists before setting up IPC
    let _layer = Layer::open(storage, layer_id).context("Failed to open layer")?;

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
                let mut server = RpcServer::new(server_sock, server_storage)
                    .expect("Failed to create RpcServer");
                server.run().await.expect("Server failed");
            });
        });

        // Client side: create transport and send request
        let transport = UnixSocketTransport::new(client_sock)
            .map_err(|e| anyhow!("Failed to create client transport: {}", e))?;
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
