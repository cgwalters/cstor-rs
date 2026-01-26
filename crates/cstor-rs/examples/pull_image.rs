//! Example: Pull an OCI image from a registry and store it in containers-storage
//!
//! This example demonstrates:
//! 1. Parsing an image reference (e.g., "docker.io/library/alpine:latest")
//! 2. Connecting to a registry with anonymous auth
//! 3. Pulling the manifest (handling manifest lists by selecting linux/amd64)
//! 4. Downloading and decompressing layers
//! 5. Computing diff digests and creating layers
//! 6. Creating the image in containers-storage
//!
//! Run with:
//!   cargo run --example pull_image -p cstor-rs -- docker.io/library/alpine:latest
//!
//! Or with a different platform:
//!   cargo run --example pull_image -p cstor-rs -- --arch arm64 docker.io/library/alpine:latest

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use cstor_rs::{LayerRecord, Storage, generate_layer_id};
use flate2::read::GzDecoder;
use oci_client::Reference;
use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::manifest::{OciDescriptor, OciImageManifest, OciManifest};
use oci_client::secrets::RegistryAuth;
use oci_spec::image::ImageConfiguration;
use sha2::{Digest, Sha256};
use zstd::stream::read::Decoder as ZstdDecoder;

/// Default platform to select for multi-arch images
const DEFAULT_OS: &str = "linux";
const DEFAULT_ARCH: &str = "amd64";

#[derive(Debug)]
struct PullOptions {
    /// Image reference (e.g., "docker.io/library/alpine:latest")
    image_ref: String,
    /// Target OS
    os: String,
    /// Target architecture
    arch: String,
    /// Storage path (auto-discover if not set)
    storage_path: Option<PathBuf>,
}

impl PullOptions {
    fn from_args() -> Result<Self> {
        let args: Vec<String> = std::env::args().collect();

        let mut os = DEFAULT_OS.to_string();
        let mut arch = DEFAULT_ARCH.to_string();
        let mut storage_path = None;
        let mut image_ref = None;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--os" => {
                    i += 1;
                    os = args.get(i).cloned().context("--os requires a value")?;
                }
                "--arch" => {
                    i += 1;
                    arch = args.get(i).cloned().context("--arch requires a value")?;
                }
                "--storage" => {
                    i += 1;
                    storage_path = Some(PathBuf::from(
                        args.get(i).context("--storage requires a value")?,
                    ));
                }
                arg if arg.starts_with('-') => {
                    bail!("Unknown option: {}", arg);
                }
                arg => {
                    image_ref = Some(arg.to_string());
                }
            }
            i += 1;
        }

        let image_ref = image_ref.ok_or_else(|| {
            anyhow::anyhow!(
                "Usage: {} [--os OS] [--arch ARCH] [--storage PATH] IMAGE\n\n\
                 Example:\n  {} docker.io/library/alpine:latest\n\n\
                 Options:\n\
                   --os OS        Target OS (default: linux)\n\
                   --arch ARCH    Target architecture (default: amd64)\n\
                   --storage PATH Storage path (auto-discover if not set)",
                args[0],
                args[0]
            )
        })?;

        Ok(Self {
            image_ref,
            os,
            arch,
            storage_path,
        })
    }
}

/// Layer info after download
#[derive(Debug)]
struct DownloadedLayer {
    /// Compressed digest (from manifest)
    compressed_digest: String,
    /// Compressed size
    compressed_size: u64,
    /// Diff digest (sha256 of uncompressed tar)
    diff_digest: String,
    /// Uncompressed size
    diff_size: u64,
    /// Uncompressed tar data
    tar_data: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = PullOptions::from_args()?;

    println!("Pulling image: {}", opts.image_ref);
    println!("Platform: {}/{}", opts.os, opts.arch);

    // Parse image reference
    let reference: Reference = opts
        .image_ref
        .parse()
        .context("Failed to parse image reference")?;

    println!(
        "Registry: {}, Repository: {}, Tag: {}",
        reference.registry(),
        reference.repository(),
        reference.tag().unwrap_or("latest")
    );

    // Create OCI client
    let client_config = ClientConfig {
        protocol: ClientProtocol::Https,
        ..Default::default()
    };
    let client = oci_client::Client::new(client_config);

    // Pull manifest
    println!("\nFetching manifest...");
    let (manifest, manifest_digest, config_str) =
        pull_manifest(&client, &reference, &opts.os, &opts.arch).await?;

    println!("Manifest digest: {}", manifest_digest);
    println!("Layers: {}", manifest.layers.len());

    // Parse config
    let config: ImageConfiguration =
        serde_json::from_str(&config_str).context("Failed to parse image configuration")?;
    let config_bytes = config_str.as_bytes();
    let manifest_bytes = serde_json::to_vec(&manifest)?;

    println!("Architecture: {}", config.architecture());
    println!("OS: {}", config.os());

    let rootfs = config.rootfs();
    let config_diff_ids = rootfs.diff_ids();
    println!("Diff IDs: {}", config_diff_ids.len());

    // Pull layers
    println!("\nDownloading layers...");
    let mut downloaded_layers = Vec::new();

    for (i, layer_desc) in manifest.layers.iter().enumerate() {
        println!(
            "  Layer {}/{}: {} ({} bytes)",
            i + 1,
            manifest.layers.len(),
            &layer_desc.digest[7..19], // Show abbreviated digest
            layer_desc.size
        );

        let layer = download_layer(&client, &reference, layer_desc).await?;
        println!(
            "    Uncompressed: {} bytes, diff_id: sha256:{}...",
            layer.diff_size,
            &layer.diff_digest[..12]
        );
        downloaded_layers.push(layer);
    }

    // Verify diff_ids match config
    if config_diff_ids.len() != downloaded_layers.len() {
        bail!(
            "Mismatch: config has {} diff_ids but manifest has {} layers",
            config_diff_ids.len(),
            downloaded_layers.len()
        );
    }

    for (i, (layer, expected_diff_id)) in downloaded_layers
        .iter()
        .zip(config_diff_ids.iter())
        .enumerate()
    {
        let computed = format!("sha256:{}", layer.diff_digest);
        let expected = expected_diff_id.to_string();
        if computed != expected {
            bail!(
                "Layer {} diff_id mismatch: computed {} but config has {}",
                i,
                computed,
                expected
            );
        }
    }
    println!("\nAll diff_ids verified!");

    // Open storage
    println!("\nOpening containers-storage...");
    let storage = if let Some(ref path) = opts.storage_path {
        Storage::open_writable(path).context("Failed to open storage")?
    } else {
        Storage::discover_writable().context("Failed to discover storage")?
    };

    let layer_store = storage.layer_store();
    let image_store = storage.image_store();

    // Create layers
    println!("\nCreating layers in storage...");
    let mut parent_id: Option<String> = None;
    let mut layer_ids = Vec::new();

    for (i, layer) in downloaded_layers.iter().enumerate() {
        println!(
            "  Creating layer {}/{}: sha256:{}...",
            i + 1,
            downloaded_layers.len(),
            &layer.diff_digest[..12]
        );

        let layer_record = create_layer_from_tar(
            &layer_store,
            &layer.tar_data,
            parent_id.as_deref(),
            &layer.diff_digest,
            layer.diff_size,
            &layer.compressed_digest,
            layer.compressed_size,
        )?;

        println!("    Layer ID: {}", layer_record.id);
        parent_id = Some(layer_record.id.clone());
        layer_ids.push(layer_record.id);
    }

    // Create image
    let top_layer_id = layer_ids
        .last()
        .ok_or_else(|| anyhow::anyhow!("No layers created"))?;

    // Build the full image name
    let image_name = format!(
        "{}/{}:{}",
        reference.registry(),
        reference.repository(),
        reference.tag().unwrap_or("latest")
    );

    println!("\nCreating image: {}", image_name);

    let image_record = image_store
        .create_image(
            None, // Auto-generate ID from config digest
            top_layer_id,
            &manifest_bytes,
            config_bytes,
            &[&image_name],
        )
        .context("Failed to create image")?;

    println!("\nImage created successfully!");
    println!("  Image ID: {}", image_record.id);
    println!("  Digest: {:?}", image_record.digest);
    println!("  Names: {:?}", image_record.names);
    println!("  Layers: {}", layer_ids.len());

    println!("\nYou can now use the image with:");
    println!("  podman run --rm {} echo hello", image_name);

    Ok(())
}

/// Pull manifest, handling manifest lists by selecting the appropriate platform
async fn pull_manifest(
    client: &oci_client::Client,
    reference: &Reference,
    os: &str,
    arch: &str,
) -> Result<(OciImageManifest, String, String)> {
    // Pull the manifest (auth is already stored in client)
    let (manifest, digest) = client
        .pull_manifest(reference, &RegistryAuth::Anonymous)
        .await
        .context("Failed to pull manifest")?;

    match manifest {
        OciManifest::Image(image_manifest) => {
            // Direct image manifest - need to pull config separately
            let config_str = pull_config(client, reference, &image_manifest.config).await?;
            Ok((image_manifest, digest, config_str))
        }
        OciManifest::ImageIndex(index) => {
            // Manifest list - find matching platform
            println!("  Image is multi-arch, selecting {}/{}", os, arch);

            let matching = index.manifests.iter().find(|m| {
                if let Some(platform) = &m.platform {
                    platform.os == os && platform.architecture == arch
                } else {
                    false
                }
            });

            let descriptor =
                matching.ok_or_else(|| anyhow::anyhow!("No manifest found for {}/{}", os, arch))?;

            println!(
                "  Selected manifest: {} ({} bytes)",
                descriptor.digest, descriptor.size
            );

            // Pull the specific manifest
            let manifest_ref = reference.clone_with_digest(descriptor.digest.clone());
            let (inner_manifest, inner_digest) = client
                .pull_manifest(&manifest_ref, &RegistryAuth::Anonymous)
                .await
                .context("Failed to pull platform-specific manifest")?;

            match inner_manifest {
                OciManifest::Image(image_manifest) => {
                    // Pull config for this manifest
                    let config_str =
                        pull_config(client, &manifest_ref, &image_manifest.config).await?;
                    Ok((image_manifest, inner_digest, config_str))
                }
                OciManifest::ImageIndex(_) => {
                    bail!("Nested manifest index not supported");
                }
            }
        }
    }
}

/// Pull config blob and return as string
async fn pull_config(
    client: &oci_client::Client,
    reference: &Reference,
    config_desc: &OciDescriptor,
) -> Result<String> {
    let mut config_bytes = Vec::new();
    client
        .pull_blob(reference, config_desc, &mut config_bytes)
        .await
        .context("Failed to pull config")?;

    String::from_utf8(config_bytes).context("Config is not valid UTF-8")
}

/// Download and decompress a layer
async fn download_layer(
    client: &oci_client::Client,
    reference: &Reference,
    layer_desc: &OciDescriptor,
) -> Result<DownloadedLayer> {
    // Download compressed blob
    let mut compressed_data = Vec::new();
    client
        .pull_blob(reference, layer_desc, &mut compressed_data)
        .await
        .with_context(|| format!("Failed to pull layer {}", layer_desc.digest))?;

    let compressed_size = compressed_data.len() as u64;
    let media_type = &layer_desc.media_type;

    // Decompress based on media type
    let tar_data = decompress_layer(&compressed_data, media_type)?;
    let diff_size = tar_data.len() as u64;

    // Compute diff digest (sha256 of uncompressed tar)
    let diff_digest = compute_sha256(&tar_data);

    // Extract compressed digest (remove "sha256:" prefix)
    let compressed_digest = layer_desc
        .digest
        .strip_prefix("sha256:")
        .unwrap_or(&layer_desc.digest)
        .to_string();

    Ok(DownloadedLayer {
        compressed_digest,
        compressed_size,
        diff_digest,
        diff_size,
        tar_data,
    })
}

/// Decompress layer based on media type
fn decompress_layer(data: &[u8], media_type: &str) -> Result<Vec<u8>> {
    if media_type.contains("gzip") || media_type.ends_with("+gzip") {
        // Gzip compressed
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .context("Failed to decompress gzip layer")?;
        Ok(decompressed)
    } else if media_type.contains("zstd") || media_type.ends_with("+zstd") {
        // Zstd compressed
        let mut decoder = ZstdDecoder::new(data).context("Failed to create zstd decoder")?;
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .context("Failed to decompress zstd layer")?;
        Ok(decompressed)
    } else if media_type.contains("tar") && !media_type.contains('+') {
        // Uncompressed tar
        Ok(data.to_vec())
    } else {
        // Try gzip first (most common), then zstd, fall back to uncompressed
        if let Ok(mut decoder) = ZstdDecoder::new(data) {
            let mut decompressed = Vec::new();
            if decoder.read_to_end(&mut decompressed).is_ok() {
                return Ok(decompressed);
            }
        }
        // Try gzip
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        match decoder.read_to_end(&mut decompressed) {
            Ok(_) if !decompressed.is_empty() => Ok(decompressed),
            _ => Ok(data.to_vec()), // Fall back to raw data
        }
    }
}

/// Compute SHA256 hash and return as hex string
fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Create a layer from uncompressed tar data
fn create_layer_from_tar(
    layer_store: &cstor_rs::LayerStore,
    tar_data: &[u8],
    parent_id: Option<&str>,
    diff_digest: &str,
    diff_size: u64,
    compressed_digest: &str,
    compressed_size: u64,
) -> Result<LayerRecord> {
    use tar::Archive;

    // Generate layer ID
    let layer_id = generate_layer_id();

    // First, create the basic layer record
    let mut record = layer_store
        .create_layer(Some(&layer_id), parent_id, &[], None::<std::io::Empty>)
        .context("Failed to create layer")?;

    // Discover storage path
    let storage_root = discover_storage_path()?;
    let overlay_path = storage_root.join("overlay").join(&layer_id).join("diff");

    // Extract tar to diff directory
    let mut archive = Archive::new(tar_data);

    for entry_result in archive.entries().context("Failed to read tar entries")? {
        let mut entry = entry_result.context("Failed to read tar entry")?;

        // Get path (convert to owned to avoid borrow issues)
        let path = entry
            .path()
            .context("Failed to get entry path")?
            .into_owned();
        let dest_path = overlay_path.join(&path);

        // Create parent directories
        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        // Handle entry type
        match entry.header().entry_type() {
            tar::EntryType::Directory => {
                std::fs::create_dir_all(&dest_path).ok();
                // Set permissions
                if let Ok(mode) = entry.header().mode() {
                    let perms = std::fs::Permissions::from_mode(mode);
                    std::fs::set_permissions(&dest_path, perms).ok();
                }
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                // Unpack file
                entry
                    .unpack(&dest_path)
                    .with_context(|| format!("Failed to unpack {}", path.display()))?;
            }
            tar::EntryType::Symlink => {
                if let Ok(Some(target)) = entry.header().link_name() {
                    // Remove existing file if any
                    std::fs::remove_file(&dest_path).ok();
                    std::os::unix::fs::symlink(&*target, &dest_path).ok();
                }
            }
            tar::EntryType::Link => {
                if let Ok(Some(target)) = entry.header().link_name() {
                    let target_path = overlay_path.join(&*target);
                    // Remove existing file if any
                    std::fs::remove_file(&dest_path).ok();
                    std::fs::hard_link(&target_path, &dest_path).ok();
                }
            }
            _ => {
                // Skip other types (device nodes, etc.)
            }
        }
    }

    // Update the layer record with digest info
    record.diff_digest = Some(format!("sha256:{}", diff_digest));
    record.diff_size = Some(diff_size as i64);
    record.compressed_diff_digest = Some(format!("sha256:{}", compressed_digest));
    record.compressed_size = Some(compressed_size as i64);

    // Update layers.json with the digest info
    update_layer_record(&storage_root, &record)?;

    Ok(record)
}

/// Discover storage path from environment or defaults
fn discover_storage_path() -> Result<PathBuf> {
    // Check environment variable first
    if let Ok(path) = std::env::var("CONTAINERS_STORAGE_ROOT") {
        return Ok(PathBuf::from(path));
    }

    // Check rootless location
    if let Ok(home) = std::env::var("HOME") {
        let rootless_path = PathBuf::from(&home).join(".local/share/containers/storage");
        if rootless_path.exists() {
            return Ok(rootless_path);
        }
    }

    // Default to root location
    let root_path = PathBuf::from("/var/lib/containers/storage");
    if root_path.exists() {
        return Ok(root_path);
    }

    // Fallback to rootless
    if let Ok(home) = std::env::var("HOME") {
        return Ok(PathBuf::from(home).join(".local/share/containers/storage"));
    }

    bail!("Could not determine storage path")
}

/// Update a layer record in layers.json
fn update_layer_record(storage_root: &std::path::Path, record: &LayerRecord) -> Result<()> {
    let layers_json_path = storage_root.join("overlay-layers").join("layers.json");

    // Read existing layers.json
    let content = std::fs::read_to_string(&layers_json_path).unwrap_or_else(|_| "[]".to_string());

    let mut layers: Vec<serde_json::Value> =
        serde_json::from_str(&content).unwrap_or_else(|_| Vec::new());

    // Find and update our layer
    let mut found = false;
    for layer in &mut layers {
        if layer.get("id").and_then(|v| v.as_str()) == Some(&record.id) {
            // Update fields
            if let Some(diff_digest) = &record.diff_digest {
                layer["diff-digest"] = serde_json::Value::String(diff_digest.clone());
            }
            if let Some(diff_size) = record.diff_size {
                layer["diff-size"] = serde_json::Value::Number(diff_size.into());
            }
            if let Some(compressed_digest) = &record.compressed_diff_digest {
                layer["compressed-diff-digest"] =
                    serde_json::Value::String(compressed_digest.clone());
            }
            if let Some(compressed_size) = record.compressed_size {
                layer["compressed-size"] = serde_json::Value::Number(compressed_size.into());
            }
            found = true;
            break;
        }
    }

    if !found {
        bail!("Layer {} not found in layers.json", record.id);
    }

    // Write back atomically
    let temp_path = layers_json_path.with_extension("tmp");
    let json = serde_json::to_string_pretty(&layers)?;
    std::fs::write(&temp_path, &json)?;
    std::fs::rename(&temp_path, &layers_json_path)?;

    Ok(())
}
