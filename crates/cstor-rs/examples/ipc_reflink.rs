//! Example: IPC-based reflink extraction of a container image
//!
//! This example demonstrates the full flow:
//! 1. Open containers-storage and find an image
//! 2. Create a socketpair for IPC
//! 3. Server task streams tar-split with fd passing
//! 4. Client task receives fds and reflinks files to destination
//!
//! Run with:
//!   cargo run --example ipc_reflink <image-id> <dest-dir> [--force-copy]
//!
//! Example:
//!   cargo run --example ipc_reflink busybox ~/tmp/extracted

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::prelude::*;
use cstor_rs::client::{ReceivedItem, TarSplitClient};
use cstor_rs::tar_split::{TarSplitFdStream, TarSplitItem};
use cstor_rs::{Image, Layer, Storage};
use jsonrpc_fdpass::transport::UnixSocketTransport;
use jsonrpc_fdpass::{JsonRpcMessage, JsonRpcNotification, MessageWithFds};
use rustix::fs::ioctl_ficlone;
use tokio::net::UnixStream;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let force_copy = args.iter().any(|a| a == "--force-copy");
    let positional: Vec<&String> = args
        .iter()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();

    if positional.len() != 2 {
        anyhow::bail!(
            "Usage: {} <image-id> <dest-dir> [--force-copy]\n\n\
             Example:\n  {} busybox ~/tmp/extracted\n\n\
             Options:\n  --force-copy  Fall back to copying if reflinks fail",
            args[0],
            args[0]
        );
    }

    let image_id = positional[0];
    let dest_dir = PathBuf::from(positional[1]);

    // Ensure destination doesn't exist
    if dest_dir.exists() {
        anyhow::bail!("Destination already exists: {}", dest_dir.display());
    }

    // Open storage
    let storage = Storage::discover().context("Failed to discover containers-storage")?;
    println!("Opened containers-storage");

    // Find image
    let image = Image::open(&storage, image_id).context("Failed to open image")?;
    println!("Found image: {}", image.id());

    // Get storage layer IDs (resolved from diff_ids via layers.json)
    let layer_ids = image
        .storage_layer_ids(&storage)
        .context("Failed to get layers")?;
    println!("Image has {} layer(s)", layer_ids.len());

    // Create destination directory
    std::fs::create_dir_all(&dest_dir).context("Failed to create destination directory")?;

    // Process each layer
    let mut total_files = 0;
    let mut total_reflinked = 0;
    let mut total_copied = 0;

    for (i, layer_id) in layer_ids.iter().enumerate() {
        println!(
            "\nProcessing layer {}/{}: {}",
            i + 1,
            layer_ids.len(),
            layer_id
        );

        let layer = Layer::open(&storage, layer_id).context("Failed to open layer")?;
        let (reflinked, copied) =
            extract_layer_via_ipc(&storage, &layer, &dest_dir, force_copy).await?;
        total_reflinked += reflinked;
        total_copied += copied;
        total_files += reflinked + copied;
    }

    println!("\nExtraction complete!");
    println!("  Total files: {}", total_files);
    println!("  Reflinked:   {} (zero-copy)", total_reflinked);
    if total_copied > 0 {
        println!("  Copied:      {} (fallback)", total_copied);
    }
    println!("  Destination: {}", dest_dir.display());

    Ok(())
}

/// Extract a single layer via IPC with reflink support
async fn extract_layer_via_ipc(
    storage: &Storage,
    layer: &Layer,
    dest_dir: &Path,
    force_copy: bool,
) -> Result<(usize, usize)> {
    // Collect tar-split items synchronously (Storage is not Send)
    let mut stream =
        TarSplitFdStream::new(storage, layer).context("Failed to create tar-split stream")?;

    let mut items = Vec::new();
    while let Some(item) = stream.next()? {
        items.push(item);
    }

    // Create socketpair
    let (server_sock, client_sock) = UnixStream::pair().context("Failed to create socketpair")?;

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let transport = UnixSocketTransport::new(server_sock)
            .map_err(|e| anyhow::anyhow!("Failed to create transport: {}", e))?;
        let (mut sender, _receiver) = transport.split();

        // Send start message
        let notification =
            JsonRpcNotification::new("stream.start".to_string(), Some(serde_json::json!({})));
        sender
            .send(MessageWithFds::new(
                JsonRpcMessage::Notification(notification),
                vec![],
            ))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send start: {}", e))?;

        // Send all items
        for item in items {
            match item {
                TarSplitItem::Segment(bytes) => {
                    let data = BASE64_STANDARD.encode(&bytes);
                    let notification = JsonRpcNotification::new(
                        "stream.seg".to_string(),
                        Some(serde_json::json!({ "data": data })),
                    );
                    sender
                        .send(MessageWithFds::new(
                            JsonRpcMessage::Notification(notification),
                            vec![],
                        ))
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to send seg: {}", e))?;
                }
                TarSplitItem::FileContent { fd, size, name } => {
                    // File descriptors are passed positionally via SCM_RIGHTS
                    let notification = JsonRpcNotification::new(
                        "stream.file".to_string(),
                        Some(serde_json::json!({
                            "name": name,
                            "size": size,
                        })),
                    );
                    sender
                        .send(MessageWithFds::new(
                            JsonRpcMessage::Notification(notification),
                            vec![fd],
                        ))
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to send file: {}", e))?;
                }
            }
        }

        // Send end message
        let notification =
            JsonRpcNotification::new("stream.end".to_string(), Some(serde_json::json!({})));
        sender
            .send(MessageWithFds::new(
                JsonRpcMessage::Notification(notification),
                vec![],
            ))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send end: {}", e))?;

        Ok::<(), anyhow::Error>(())
    });

    // Client side: receive and reflink
    let mut client = TarSplitClient::new(client_sock).context("Failed to create TarSplitClient")?;

    let mut reflinked = 0;
    let mut copied = 0;

    loop {
        match client.next_item().await? {
            Some(ReceivedItem::Segment(_)) => {
                // Skip segments - we only care about files for reflink
            }
            Some(ReceivedItem::File { name, size, fd }) => {
                // Skip empty files
                if size == 0 {
                    continue;
                }

                // Create destination path
                let dest_path = dest_dir.join(&name);

                // Create parent directories
                if let Some(parent) = dest_path.parent() {
                    std::fs::create_dir_all(parent).with_context(|| {
                        format!("Failed to create parent directory for {}", name)
                    })?;
                }

                // Skip if it's a directory path or already exists
                if dest_path.exists() {
                    continue;
                }

                // Create destination file
                let dest_file = std::fs::File::create(&dest_path)
                    .with_context(|| format!("Failed to create file {}", name))?;

                // Convert OwnedFd to File for reflink
                let src_file = std::fs::File::from(fd);

                // Try reflink - require it by default
                match ioctl_ficlone(&dest_file, &src_file) {
                    Ok(_) => {
                        reflinked += 1;
                    }
                    Err(e) => {
                        if force_copy {
                            // Fall back to copy only if explicitly requested
                            let mut src = src_file;
                            let mut dst = dest_file;
                            std::io::copy(&mut src, &mut dst)
                                .with_context(|| format!("Failed to copy file {}", name))?;
                            copied += 1;
                        } else {
                            // Clean up the created file before returning error
                            let _ = std::fs::remove_file(&dest_path);
                            return Err(e).with_context(|| {
                                format!(
                                    "Reflink failed for {}. Use --force-copy to fall back to copying",
                                    name
                                )
                            });
                        }
                    }
                }

                // Set permissions (approximate - tar has more metadata)
                let _ =
                    std::fs::set_permissions(&dest_path, std::fs::Permissions::from_mode(0o644));
            }
            Some(ReceivedItem::End) => break,
            None => break,
        }
    }

    // Wait for server task
    server_task
        .await
        .map_err(|e| anyhow::anyhow!("Server task panicked: {}", e))?
        .context("Server task error")?;

    println!(
        "  Extracted {} files ({} reflinked, {} copied)",
        reflinked + copied,
        reflinked,
        copied
    );

    Ok((reflinked, copied))
}
