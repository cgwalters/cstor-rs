//! User namespace helper process for privileged storage access.
//!
//! This module provides a mechanism for unprivileged processes to access
//! containers-storage content that has restrictive permissions. It works by
//! spawning a helper process inside a user namespace (via `podman unshare`)
//! that can read any file, and communicating with it via JSON-RPC over a
//! Unix socket with fd-passing.
//!
//! # Why This Is Needed
//!
//! Container images contain files with various permission bits (e.g., `/etc/shadow`
//! with mode 0600). When stored in rootless containers-storage, these files are
//! owned by remapped UIDs that the unprivileged user cannot access. Even though
//! we have tar-split metadata telling us the file structure, we still need to
//! read the actual file content.
//!
//! # Architecture
//!
//! The helper uses stdin (fd 0) for IPC, avoiding the need for unsafe code:
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │         Parent Process              │
//! │   (unprivileged, library user)      │
//! │                                     │
//! │  StorageProxy::spawn()              │
//! │       │                             │
//! │       ├─► Create socketpair         │
//! │       ├─► Spawn: podman unshare     │
//! │       │      /proc/self/exe         │
//! │       │      (child's stdin=socket) │
//! │       │                             │
//! │  proxy.open_file(path) ───────────► │
//! │       │                             │
//! │  ◄─── receives OwnedFd via SCM_RIGHTS│
//! └─────────────────────────────────────┘
//! ```
//!
//! # Higher-Level API
//!
//! For most use cases, prefer [`ProxiedStorage`] which provides transparent
//! access to storage with automatic userns helper spawning when needed:
//!
//! ```no_run
//! use cstor_rs::userns_helper::{ProxiedStorage, ProxiedTarSplitItem};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Opens storage with automatic helper if unprivileged
//! let mut storage = ProxiedStorage::open_with_proxy("/path/to/storage").await?;
//!
//! // List images works transparently (async for proxied mode)
//! for image in storage.list_images_async().await? {
//!     println!("Image: {} - {:?}", image.id, image.names);
//! }
//!
//! // Get image metadata
//! let image = storage.get_image("alpine:latest").await?;
//! println!("Image has {} layers", image.layer_diff_ids.len());
//!
//! // Stream layer content with fd-passing when needed
//! let mut stream = storage.stream_layer("layer-id").await?;
//! while let Some(item) = stream.next().await? {
//!     match item {
//!         ProxiedTarSplitItem::Segment(bytes) => {
//!             println!("Segment: {} bytes", bytes.len());
//!         }
//!         ProxiedTarSplitItem::FileContent { name, size, fd } => {
//!             println!("File: {} ({} bytes)", name, size);
//!             // fd is an OwnedFd you can read from
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Usage
//!
//! Library users must call [`init_if_helper`] early in their `main()` function:
//!
//! ```no_run
//! // This must be called before any other cstor-rs operations.
//! // If this process was spawned as a userns helper, it will
//! // serve requests and exit, never returning.
//! cstor_rs::userns_helper::init_if_helper();
//!
//! // Normal application code continues here...
//! ```

use std::os::fd::AsFd;
use std::os::unix::io::OwnedFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use base64::prelude::*;
use jsonrpc_fdpass::transport::UnixSocketTransport;
use jsonrpc_fdpass::{JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, MessageWithFds};
use rustix::io::dup;
use serde::{Deserialize, Serialize};
use tokio::net::UnixStream as TokioUnixStream;

use crate::error::{Result as CstorResult, StorageError};
use crate::layer::Layer;
use crate::storage::{LayerMetadata, Storage};
use crate::tar_split::{TarSplitFdStream, TarSplitItem};
use crate::toc::Toc;
use crate::userns::can_bypass_file_permissions;

/// Environment variable that indicates this process is a userns helper.
const HELPER_ENV: &str = "__CSTOR_USERNS_HELPER";

/// JSON-RPC 2.0 error codes.
///
/// These codes follow the JSON-RPC 2.0 specification:
/// - Standard errors: -32700 to -32600
/// - Server errors: -32099 to -32000 (implementation-defined)
mod error_codes {
    /// Invalid params - the params passed to a method are invalid.
    pub const INVALID_PARAMS: i32 = -32602;

    /// Method not found - the requested method does not exist.
    pub const METHOD_NOT_FOUND: i32 = -32601;

    /// Resource not found - the requested resource (image, layer, etc.) was not found.
    pub const RESOURCE_NOT_FOUND: i32 = -32000;

    /// Internal error - a server-side error occurred (I/O, storage access, etc.).
    pub const INTERNAL_ERROR: i32 = -32003;
}

/// JSON-RPC method names.
mod methods {
    /// Open a file and return its fd.
    pub const OPEN_FILE: &str = "userns.openFile";
    /// Shutdown the helper process.
    pub const SHUTDOWN: &str = "userns.shutdown";
    /// List images in storage.
    pub const LIST_IMAGES: &str = "userns.listImages";
    /// Get image metadata.
    pub const GET_IMAGE: &str = "userns.getImage";
    /// Get layer metadata.
    pub const GET_LAYER_METADATA: &str = "userns.getLayerMetadata";
    /// Stream layer as tar-split entries with fds.
    pub const STREAM_LAYER: &str = "userns.streamLayer";
    /// Get TOC for a layer.
    pub const GET_LAYER_TOC: &str = "userns.getLayerToc";
    /// Get merged TOC for an image.
    pub const GET_IMAGE_TOC: &str = "userns.getImageToc";
}

/// Parameters for the open_file method.
#[derive(Debug, Serialize, Deserialize)]
pub struct OpenFileParams {
    /// Path to open.
    pub path: String,
}

/// Result for the open_file method.
#[derive(Debug, Serialize, Deserialize)]
pub struct OpenFileResult {
    /// True if successful (fd is passed out-of-band).
    pub success: bool,
}

/// Parameters for list_images method.
#[derive(Debug, Serialize, Deserialize)]
pub struct ListImagesParams {
    /// Storage root path.
    pub storage_path: String,
}

/// Image info returned by list_images.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    /// Image ID.
    pub id: String,
    /// Image names/tags.
    pub names: Vec<String>,
}

/// Result for list_images method.
#[derive(Debug, Serialize, Deserialize)]
pub struct ListImagesResult {
    /// List of images.
    pub images: Vec<ImageInfo>,
}

/// Parameters for get_image method.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetImageParams {
    /// Storage root path.
    pub storage_path: String,
    /// Image ID or name.
    pub image_ref: String,
}

/// Result for get_image method.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetImageResult {
    /// Image ID.
    pub id: String,
    /// Image names.
    pub names: Vec<String>,
    /// Layer diff IDs (sha256:...).
    pub layer_diff_ids: Vec<String>,
}

/// Parameters for get_layer_metadata method.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetLayerMetadataParams {
    /// Storage root path.
    pub storage_path: String,
    /// Layer ID.
    pub layer_id: String,
}

/// Result for get_layer_metadata method.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetLayerMetadataResult {
    /// Layer ID.
    pub id: String,
    /// Parent layer ID.
    pub parent: Option<String>,
    /// Uncompressed size.
    pub diff_size: Option<u64>,
    /// Compressed size.
    pub compressed_size: Option<u64>,
}

/// Parameters for stream_layer method.
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamLayerParams {
    /// Storage root path.
    pub storage_path: String,
    /// Layer ID.
    pub layer_id: String,
}

/// Streaming notification for a segment.
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamSegmentNotification {
    /// Base64-encoded segment data.
    pub data: String,
}

/// Streaming notification for a file (fd is passed out-of-band).
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamFileNotification {
    /// File path in the tar.
    pub name: String,
    /// File size.
    pub size: u64,
}

/// Result for stream_layer method (sent after all notifications).
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamLayerResult {
    /// Number of items streamed.
    pub items_sent: usize,
}

/// Parameters for get_layer_toc method.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetLayerTocParams {
    /// Storage root path.
    pub storage_path: String,
    /// Layer ID.
    pub layer_id: String,
}

/// Parameters for get_image_toc method.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetImageTocParams {
    /// Storage root path.
    pub storage_path: String,
    /// Image ID.
    pub image_id: String,
}

/// Result for TOC methods.
#[derive(Debug, Serialize, Deserialize)]
pub struct TocResult {
    /// The TOC as JSON.
    pub toc: Toc,
}

/// Error type for userns helper operations.
#[derive(Debug, thiserror::Error)]
pub enum HelperError {
    /// Failed to create socket.
    #[error("failed to create socket: {0}")]
    Socket(#[source] std::io::Error),

    /// Failed to spawn helper process.
    #[error("failed to spawn helper process: {0}")]
    Spawn(#[source] std::io::Error),

    /// IPC error.
    #[error("IPC error: {0}")]
    Ipc(String),

    /// Helper returned an error.
    #[error("helper error: {0}")]
    HelperError(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON-RPC error from the helper.
    #[error("RPC error: code={code}, message={message}")]
    RpcError {
        /// JSON-RPC error code.
        code: i32,
        /// Error message.
        message: String,
    },
}

/// Check if this process was spawned as a userns helper and run the helper loop if so.
///
/// This function **must** be called early in `main()`, before any other cstor-rs
/// operations. If this process was spawned as a helper, this function will:
///
/// 1. Read from stdin (which is a Unix socket from the parent)
/// 2. Serve JSON-RPC requests for file operations  
/// 3. Exit when the parent closes the connection
///
/// If this is not a helper process, this function returns immediately.
///
/// # Example
///
/// ```no_run
/// // Must be first in your main()!
/// cstor_rs::userns_helper::init_if_helper();
///
/// // Rest of your application...
/// ```
pub fn init_if_helper() {
    // Check if we're a helper via environment variable
    if std::env::var(HELPER_ENV).is_err() {
        return; // Not a helper, continue normal execution
    }

    // We're a helper - stdin is our IPC socket.
    // Use dup() to get a new owned fd from stdin (fd 0).
    // This is safe because:
    // 1. We were spawned with stdin set to a socket
    // 2. dup() gives us a new fd that we own
    // 3. We use std::io::stdin().as_fd() which is the safe way to get the fd
    let stdin_fd = match dup(std::io::stdin().as_fd()) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("cstor-rs helper: failed to dup stdin: {}", e);
            std::process::exit(1);
        }
    };
    let std_socket = StdUnixStream::from(stdin_fd);

    // Run the helper loop (never returns on success)
    if let Err(e) = run_helper_loop_blocking(std_socket) {
        eprintln!("cstor-rs helper: error in helper loop: {}", e);
        std::process::exit(1);
    }
    std::process::exit(0);
}

/// Run the helper loop synchronously by creating a tokio runtime.
fn run_helper_loop_blocking(std_socket: StdUnixStream) -> std::result::Result<(), HelperError> {
    // Set non-blocking for tokio
    std_socket.set_nonblocking(true)?;

    // Create a tokio runtime for the helper
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| HelperError::Ipc(format!("failed to create tokio runtime: {}", e)))?;

    rt.block_on(run_helper_loop_async(std_socket))
}

/// Run the helper loop, serving requests from the parent.
async fn run_helper_loop_async(std_socket: StdUnixStream) -> std::result::Result<(), HelperError> {
    // Convert std socket to tokio socket
    let tokio_socket = TokioUnixStream::from_std(std_socket)
        .map_err(|e| HelperError::Ipc(format!("failed to convert socket: {}", e)))?;

    let transport = UnixSocketTransport::new(tokio_socket)
        .map_err(|e| HelperError::Ipc(format!("failed to create transport: {}", e)))?;
    let (mut sender, mut receiver) = transport.split();

    tracing::debug!("userns helper: starting request loop");

    loop {
        let msg_with_fds = match receiver.receive().await {
            Ok(m) => m,
            Err(jsonrpc_fdpass::Error::ConnectionClosed) => {
                tracing::debug!("userns helper: connection closed");
                return Ok(());
            }
            Err(e) => {
                return Err(HelperError::Ipc(format!(
                    "failed to receive message: {}",
                    e
                )));
            }
        };

        match msg_with_fds.message {
            JsonRpcMessage::Request(request) => {
                let id = request.id.clone();

                // Handle stream_layer specially since it needs to send multiple messages
                if request.method == methods::STREAM_LAYER {
                    if let Err((code, msg)) = handle_stream_layer(&request, &mut sender).await {
                        let error = jsonrpc_fdpass::JsonRpcError::owned(code, msg, None::<()>);
                        let response = JsonRpcResponse::error(error, id);
                        let message =
                            MessageWithFds::new(JsonRpcMessage::Response(response), vec![]);
                        sender.send(message).await.map_err(|e| {
                            HelperError::Ipc(format!("failed to send error response: {}", e))
                        })?;
                    } else {
                        // Success response is sent by handle_stream_layer
                    }
                    continue;
                }

                let (result, fds) = handle_request(&request);

                match result {
                    Ok(response_value) => {
                        let response = JsonRpcResponse::success(response_value, id);
                        let message = MessageWithFds::new(JsonRpcMessage::Response(response), fds);
                        sender.send(message).await.map_err(|e| {
                            HelperError::Ipc(format!("failed to send response: {}", e))
                        })?;
                    }
                    Err((code, message_str)) => {
                        let error =
                            jsonrpc_fdpass::JsonRpcError::owned(code, message_str, None::<()>);
                        let response = JsonRpcResponse::error(error, id);
                        let message =
                            MessageWithFds::new(JsonRpcMessage::Response(response), vec![]);
                        sender.send(message).await.map_err(|e| {
                            HelperError::Ipc(format!("failed to send error response: {}", e))
                        })?;
                    }
                }

                // Check for shutdown request (handle after sending response)
                if request.method == methods::SHUTDOWN {
                    tracing::debug!("userns helper: received shutdown request");
                    return Ok(());
                }
            }
            JsonRpcMessage::Notification(notif) => {
                if notif.method == methods::SHUTDOWN {
                    tracing::debug!("userns helper: received shutdown notification");
                    return Ok(());
                }
                // Ignore other notifications
            }
            JsonRpcMessage::Response(_) => {
                // Unexpected response - ignore
            }
        }
    }
}

/// Handle stream_layer request - sends multiple notifications with fds.
async fn handle_stream_layer(
    request: &JsonRpcRequest,
    sender: &mut jsonrpc_fdpass::transport::Sender,
) -> std::result::Result<(), (i32, String)> {
    let params: StreamLayerParams = request
        .params
        .as_ref()
        .and_then(|p| serde_json::from_value(p.clone()).ok())
        .ok_or((
            error_codes::INVALID_PARAMS,
            "invalid params for streamLayer".to_string(),
        ))?;

    let storage = Storage::open(&params.storage_path).map_err(|e| {
        (
            error_codes::INTERNAL_ERROR,
            format!("failed to open storage: {}", e),
        )
    })?;

    let layer = Layer::open(&storage, &params.layer_id).map_err(|e| {
        (
            error_codes::RESOURCE_NOT_FOUND,
            format!("layer not found: {}", e),
        )
    })?;

    let mut stream = TarSplitFdStream::new(&storage, &layer).map_err(|e| {
        (
            error_codes::INTERNAL_ERROR,
            format!("failed to create tar-split stream: {}", e),
        )
    })?;

    let mut items_sent = 0usize;

    // Stream all items as notifications
    while let Some(item) = stream
        .next()
        .map_err(|e| (error_codes::INTERNAL_ERROR, format!("stream error: {}", e)))?
    {
        match item {
            TarSplitItem::Segment(bytes) => {
                // Send segment as base64-encoded notification
                let params = StreamSegmentNotification {
                    data: BASE64_STANDARD.encode(&bytes),
                };
                let notif = jsonrpc_fdpass::JsonRpcNotification::new(
                    "stream.segment".to_string(),
                    Some(serde_json::to_value(&params).unwrap()),
                );
                let message = MessageWithFds::new(JsonRpcMessage::Notification(notif), vec![]);
                sender.send(message).await.map_err(|e| {
                    (
                        error_codes::INTERNAL_ERROR,
                        format!("failed to send segment: {}", e),
                    )
                })?;
                items_sent += 1;
            }
            TarSplitItem::FileContent { fd, size, name } => {
                // Send file notification with fd
                let params = StreamFileNotification { name, size };
                let notif = jsonrpc_fdpass::JsonRpcNotification::new(
                    "stream.file".to_string(),
                    Some(serde_json::to_value(&params).unwrap()),
                );
                let message = MessageWithFds::new(JsonRpcMessage::Notification(notif), vec![fd]);
                sender.send(message).await.map_err(|e| {
                    (
                        error_codes::INTERNAL_ERROR,
                        format!("failed to send file: {}", e),
                    )
                })?;
                items_sent += 1;
            }
        }
    }

    // Send success response
    let result = StreamLayerResult { items_sent };
    let response =
        JsonRpcResponse::success(serde_json::to_value(result).unwrap(), request.id.clone());
    let message = MessageWithFds::new(JsonRpcMessage::Response(response), vec![]);
    sender.send(message).await.map_err(|e| {
        (
            error_codes::INTERNAL_ERROR,
            format!("failed to send response: {}", e),
        )
    })?;

    Ok(())
}

/// Handle a JSON-RPC request.
fn handle_request(
    request: &JsonRpcRequest,
) -> (
    std::result::Result<serde_json::Value, (i32, String)>,
    Vec<OwnedFd>,
) {
    match request.method.as_str() {
        methods::OPEN_FILE => {
            let params: OpenFileParams = match request
                .params
                .as_ref()
                .and_then(|p| serde_json::from_value(p.clone()).ok())
            {
                Some(p) => p,
                None => {
                    return (
                        Err((
                            error_codes::INVALID_PARAMS,
                            "invalid params: missing 'path' field".to_string(),
                        )),
                        vec![],
                    );
                }
            };

            match std::fs::File::open(&params.path) {
                Ok(file) => {
                    let fd: OwnedFd = file.into();
                    let result = OpenFileResult { success: true };
                    (Ok(serde_json::to_value(result).unwrap()), vec![fd])
                }
                Err(e) => (
                    Err((
                        error_codes::INTERNAL_ERROR,
                        format!("failed to open file: {}", e),
                    )),
                    vec![],
                ),
            }
        }
        methods::LIST_IMAGES => handle_list_images(request),
        methods::GET_IMAGE => handle_get_image(request),
        methods::GET_LAYER_METADATA => handle_get_layer_metadata(request),
        methods::GET_LAYER_TOC => handle_get_layer_toc(request),
        methods::GET_IMAGE_TOC => handle_get_image_toc(request),
        methods::SHUTDOWN => {
            // Just return success - the loop will exit after sending the response
            (Ok(serde_json::json!({"success": true})), vec![])
        }
        _ => (
            Err((
                error_codes::METHOD_NOT_FOUND,
                format!("method not found: {}", request.method),
            )),
            vec![],
        ),
    }
}

/// Handle list_images request.
fn handle_list_images(
    request: &JsonRpcRequest,
) -> (
    std::result::Result<serde_json::Value, (i32, String)>,
    Vec<OwnedFd>,
) {
    let params: ListImagesParams = match request
        .params
        .as_ref()
        .and_then(|p| serde_json::from_value(p.clone()).ok())
    {
        Some(p) => p,
        None => {
            return (
                Err((
                    error_codes::INVALID_PARAMS,
                    "invalid params for listImages".to_string(),
                )),
                vec![],
            );
        }
    };

    let storage = match Storage::open(&params.storage_path) {
        Ok(s) => s,
        Err(e) => {
            return (
                Err((
                    error_codes::INTERNAL_ERROR,
                    format!("failed to open storage: {}", e),
                )),
                vec![],
            );
        }
    };

    let images = match storage.list_images() {
        Ok(imgs) => imgs,
        Err(e) => {
            return (
                Err((
                    error_codes::INTERNAL_ERROR,
                    format!("failed to list images: {}", e),
                )),
                vec![],
            );
        }
    };

    let image_infos: Vec<ImageInfo> = images
        .iter()
        .map(|img| ImageInfo {
            id: img.id().to_string(),
            names: img.names(&storage).unwrap_or_default(),
        })
        .collect();

    let result = ListImagesResult {
        images: image_infos,
    };
    (Ok(serde_json::to_value(result).unwrap()), vec![])
}

/// Handle get_image request.
fn handle_get_image(
    request: &JsonRpcRequest,
) -> (
    std::result::Result<serde_json::Value, (i32, String)>,
    Vec<OwnedFd>,
) {
    let params: GetImageParams = match request
        .params
        .as_ref()
        .and_then(|p| serde_json::from_value(p.clone()).ok())
    {
        Some(p) => p,
        None => {
            return (
                Err((
                    error_codes::INVALID_PARAMS,
                    "invalid params for getImage".to_string(),
                )),
                vec![],
            );
        }
    };

    let storage = match Storage::open(&params.storage_path) {
        Ok(s) => s,
        Err(e) => {
            return (
                Err((
                    error_codes::INTERNAL_ERROR,
                    format!("failed to open storage: {}", e),
                )),
                vec![],
            );
        }
    };

    // Try by ID first, then by name
    let image = match storage.get_image(&params.image_ref) {
        Ok(img) => img,
        Err(_) => match storage.find_image_by_name(&params.image_ref) {
            Ok(img) => img,
            Err(e) => {
                return (
                    Err((
                        error_codes::RESOURCE_NOT_FOUND,
                        format!("image not found: {}", e),
                    )),
                    vec![],
                );
            }
        },
    };

    let diff_ids = match image.layers() {
        Ok(ids) => ids,
        Err(e) => {
            return (
                Err((
                    error_codes::INTERNAL_ERROR,
                    format!("failed to get layers: {}", e),
                )),
                vec![],
            );
        }
    };

    let result = GetImageResult {
        id: image.id().to_string(),
        names: image.names(&storage).unwrap_or_default(),
        layer_diff_ids: diff_ids,
    };
    (Ok(serde_json::to_value(result).unwrap()), vec![])
}

/// Handle get_layer_metadata request.
fn handle_get_layer_metadata(
    request: &JsonRpcRequest,
) -> (
    std::result::Result<serde_json::Value, (i32, String)>,
    Vec<OwnedFd>,
) {
    let params: GetLayerMetadataParams = match request
        .params
        .as_ref()
        .and_then(|p| serde_json::from_value(p.clone()).ok())
    {
        Some(p) => p,
        None => {
            return (
                Err((
                    error_codes::INVALID_PARAMS,
                    "invalid params for getLayerMetadata".to_string(),
                )),
                vec![],
            );
        }
    };

    let storage = match Storage::open(&params.storage_path) {
        Ok(s) => s,
        Err(e) => {
            return (
                Err((
                    error_codes::INTERNAL_ERROR,
                    format!("failed to open storage: {}", e),
                )),
                vec![],
            );
        }
    };

    let metadata = match storage.get_layer_metadata(&params.layer_id) {
        Ok(m) => m,
        Err(e) => {
            return (
                Err((
                    error_codes::RESOURCE_NOT_FOUND,
                    format!("layer not found: {}", e),
                )),
                vec![],
            );
        }
    };

    let result = GetLayerMetadataResult {
        id: metadata.id,
        parent: metadata.parent,
        diff_size: metadata.diff_size,
        compressed_size: metadata.compressed_size,
    };
    (Ok(serde_json::to_value(result).unwrap()), vec![])
}

/// Handle get_layer_toc request.
fn handle_get_layer_toc(
    request: &JsonRpcRequest,
) -> (
    std::result::Result<serde_json::Value, (i32, String)>,
    Vec<OwnedFd>,
) {
    let params: GetLayerTocParams = match request
        .params
        .as_ref()
        .and_then(|p| serde_json::from_value(p.clone()).ok())
    {
        Some(p) => p,
        None => {
            return (
                Err((
                    error_codes::INVALID_PARAMS,
                    "invalid params for getLayerToc".to_string(),
                )),
                vec![],
            );
        }
    };

    let storage = match Storage::open(&params.storage_path) {
        Ok(s) => s,
        Err(e) => {
            return (
                Err((
                    error_codes::INTERNAL_ERROR,
                    format!("failed to open storage: {}", e),
                )),
                vec![],
            );
        }
    };

    let layer = match Layer::open(&storage, &params.layer_id) {
        Ok(l) => l,
        Err(e) => {
            return (
                Err((
                    error_codes::RESOURCE_NOT_FOUND,
                    format!("layer not found: {}", e),
                )),
                vec![],
            );
        }
    };

    let toc = match Toc::from_layer(&storage, &layer) {
        Ok(t) => t,
        Err(e) => {
            return (
                Err((
                    error_codes::INTERNAL_ERROR,
                    format!("failed to generate TOC: {}", e),
                )),
                vec![],
            );
        }
    };

    let result = TocResult { toc };
    (Ok(serde_json::to_value(result).unwrap()), vec![])
}

/// Handle get_image_toc request.
fn handle_get_image_toc(
    request: &JsonRpcRequest,
) -> (
    std::result::Result<serde_json::Value, (i32, String)>,
    Vec<OwnedFd>,
) {
    let params: GetImageTocParams = match request
        .params
        .as_ref()
        .and_then(|p| serde_json::from_value(p.clone()).ok())
    {
        Some(p) => p,
        None => {
            return (
                Err((
                    error_codes::INVALID_PARAMS,
                    "invalid params for getImageToc".to_string(),
                )),
                vec![],
            );
        }
    };

    let storage = match Storage::open(&params.storage_path) {
        Ok(s) => s,
        Err(e) => {
            return (
                Err((
                    error_codes::INTERNAL_ERROR,
                    format!("failed to open storage: {}", e),
                )),
                vec![],
            );
        }
    };

    let image = match storage.get_image(&params.image_id) {
        Ok(img) => img,
        Err(e) => {
            return (
                Err((
                    error_codes::RESOURCE_NOT_FOUND,
                    format!("image not found: {}", e),
                )),
                vec![],
            );
        }
    };

    let toc = match Toc::from_image(&storage, &image) {
        Ok(t) => t,
        Err(e) => {
            return (
                Err((
                    error_codes::INTERNAL_ERROR,
                    format!("failed to generate TOC: {}", e),
                )),
                vec![],
            );
        }
    };

    let result = TocResult { toc };
    (Ok(serde_json::to_value(result).unwrap()), vec![])
}

/// Proxy for accessing files via the userns helper process.
///
/// This spawns a helper process (via `podman unshare`) that runs inside a
/// user namespace and can read files with restrictive permissions. File
/// descriptors are passed back via SCM_RIGHTS.
pub struct StorageProxy {
    child: Child,
    sender: jsonrpc_fdpass::transport::Sender,
    receiver: jsonrpc_fdpass::transport::Receiver,
    next_id: u64,
}

impl std::fmt::Debug for StorageProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageProxy")
            .field("child_pid", &self.child.id())
            .finish_non_exhaustive()
    }
}

impl StorageProxy {
    /// Spawn a userns helper process.
    ///
    /// If the current process can already bypass file permissions (running as
    /// root or has CAP_DAC_OVERRIDE), this returns `Ok(None)` since no helper
    /// is needed.
    ///
    /// # Errors
    ///
    /// Returns an error if the helper process cannot be spawned.
    pub async fn spawn() -> std::result::Result<Option<Self>, HelperError> {
        // Check if we even need a helper
        if can_bypass_file_permissions() {
            return Ok(None);
        }

        Self::spawn_helper().await.map(Some)
    }

    /// Spawn the helper unconditionally.
    async fn spawn_helper() -> std::result::Result<Self, HelperError> {
        let exe = std::fs::read_link("/proc/self/exe").map_err(HelperError::Io)?;
        Self::spawn_helper_with_binary(exe).await
    }

    /// Spawn the helper with a specific binary path.
    ///
    /// This is used when the default /proc/self/exe is not suitable,
    /// such as when running from a test harness.
    async fn spawn_helper_with_binary(
        exe: std::path::PathBuf,
    ) -> std::result::Result<Self, HelperError> {
        // Create a socket pair - one end for us, one for the child's stdin
        let (parent_sock, child_sock) = StdUnixStream::pair().map_err(HelperError::Socket)?;

        // Spawn via podman unshare, with child_sock as the child's stdin.
        // We use `env` to set the HELPER_ENV because podman unshare doesn't
        // propagate the parent's environment to the inner command.
        let child = Command::new("podman")
            .arg("unshare")
            .arg("env")
            .arg(format!("{}=1", HELPER_ENV))
            .arg(&exe)
            .stdin(Stdio::from(OwnedFd::from(child_sock)))
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(HelperError::Spawn)?;

        // Convert our socket to async
        parent_sock.set_nonblocking(true)?;
        let tokio_socket = TokioUnixStream::from_std(parent_sock)
            .map_err(|e| HelperError::Ipc(format!("failed to convert socket: {}", e)))?;

        let transport = UnixSocketTransport::new(tokio_socket)
            .map_err(|e| HelperError::Ipc(format!("failed to create transport: {}", e)))?;
        let (sender, receiver) = transport.split();

        Ok(Self {
            child,
            sender,
            receiver,
            next_id: 1,
        })
    }

    /// Open a file via the helper, returning its fd.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to open (should be absolute)
    ///
    /// # Returns
    ///
    /// The opened file descriptor, which can be used for reading.
    pub async fn open_file(
        &mut self,
        path: impl AsRef<Path>,
    ) -> std::result::Result<OwnedFd, HelperError> {
        let params = OpenFileParams {
            path: path.as_ref().to_string_lossy().to_string(),
        };

        let id = self.next_id;
        self.next_id += 1;

        let request = JsonRpcRequest::new(
            methods::OPEN_FILE.to_string(),
            Some(serde_json::to_value(&params).unwrap()),
            serde_json::Value::Number(id.into()),
        );

        let message = MessageWithFds::new(JsonRpcMessage::Request(request), vec![]);
        self.sender
            .send(message)
            .await
            .map_err(|e| HelperError::Ipc(format!("failed to send request: {}", e)))?;

        // Receive response
        let response = self
            .receiver
            .receive()
            .await
            .map_err(|e| HelperError::Ipc(format!("failed to receive response: {}", e)))?;

        match response.message {
            JsonRpcMessage::Response(resp) => {
                if let Some(error) = resp.error {
                    return Err(HelperError::RpcError {
                        code: error.code(),
                        message: error.message().to_string(),
                    });
                }

                // The fd should be in the response
                if response.file_descriptors.is_empty() {
                    return Err(HelperError::Ipc(
                        "response missing file descriptor".to_string(),
                    ));
                }

                Ok(response.file_descriptors.into_iter().next().unwrap())
            }
            other => Err(HelperError::Ipc(format!(
                "unexpected message type: {:?}",
                other
            ))),
        }
    }

    /// Shutdown the helper process gracefully.
    pub async fn shutdown(mut self) -> std::result::Result<(), HelperError> {
        let id = self.next_id;

        let request = JsonRpcRequest::new(
            methods::SHUTDOWN.to_string(),
            None,
            serde_json::Value::Number(id.into()),
        );

        let message = MessageWithFds::new(JsonRpcMessage::Request(request), vec![]);
        // Ignore send errors - the child may have already exited
        let _ = self.sender.send(message).await;

        // Wait for the child to exit
        let _ = self.child.wait();

        Ok(())
    }

    /// List images in storage via the helper.
    pub async fn list_images(
        &mut self,
        storage_path: &str,
    ) -> std::result::Result<Vec<ImageInfo>, HelperError> {
        let params = ListImagesParams {
            storage_path: storage_path.to_string(),
        };
        let result: ListImagesResult = self.call(methods::LIST_IMAGES, &params).await?;
        Ok(result.images)
    }

    /// Get image information via the helper.
    pub async fn get_image(
        &mut self,
        storage_path: &str,
        image_ref: &str,
    ) -> std::result::Result<GetImageResult, HelperError> {
        let params = GetImageParams {
            storage_path: storage_path.to_string(),
            image_ref: image_ref.to_string(),
        };
        self.call(methods::GET_IMAGE, &params).await
    }

    /// Get layer metadata via the helper.
    pub async fn get_layer_metadata(
        &mut self,
        storage_path: &str,
        layer_id: &str,
    ) -> std::result::Result<GetLayerMetadataResult, HelperError> {
        let params = GetLayerMetadataParams {
            storage_path: storage_path.to_string(),
            layer_id: layer_id.to_string(),
        };
        self.call(methods::GET_LAYER_METADATA, &params).await
    }

    /// Get TOC for a layer via the helper.
    pub async fn get_layer_toc(
        &mut self,
        storage_path: &str,
        layer_id: &str,
    ) -> std::result::Result<Toc, HelperError> {
        let params = GetLayerTocParams {
            storage_path: storage_path.to_string(),
            layer_id: layer_id.to_string(),
        };
        let result: TocResult = self.call(methods::GET_LAYER_TOC, &params).await?;
        Ok(result.toc)
    }

    /// Get merged TOC for an image via the helper.
    pub async fn get_image_toc(
        &mut self,
        storage_path: &str,
        image_id: &str,
    ) -> std::result::Result<Toc, HelperError> {
        let params = GetImageTocParams {
            storage_path: storage_path.to_string(),
            image_id: image_id.to_string(),
        };
        let result: TocResult = self.call(methods::GET_IMAGE_TOC, &params).await?;
        Ok(result.toc)
    }

    /// Start streaming a layer's tar-split content.
    ///
    /// Returns a stream that yields `ProxiedTarSplitItem`s. The helper sends
    /// notifications with file descriptors for each file in the layer.
    pub async fn stream_layer(
        &mut self,
        storage_path: &str,
        layer_id: &str,
    ) -> std::result::Result<ProxiedLayerStream<'_>, HelperError> {
        let params = StreamLayerParams {
            storage_path: storage_path.to_string(),
            layer_id: layer_id.to_string(),
        };

        let id = self.next_id;
        self.next_id += 1;

        let request = JsonRpcRequest::new(
            methods::STREAM_LAYER.to_string(),
            Some(serde_json::to_value(&params).unwrap()),
            serde_json::Value::Number(id.into()),
        );

        let message = MessageWithFds::new(JsonRpcMessage::Request(request), vec![]);
        self.sender
            .send(message)
            .await
            .map_err(|e| HelperError::Ipc(format!("failed to send stream_layer request: {}", e)))?;

        Ok(ProxiedLayerStream {
            receiver: &mut self.receiver,
            request_id: id,
            finished: false,
        })
    }

    /// Make an RPC call and parse the response.
    async fn call<P: Serialize, R: for<'de> Deserialize<'de>>(
        &mut self,
        method: &str,
        params: &P,
    ) -> std::result::Result<R, HelperError> {
        let id = self.next_id;
        self.next_id += 1;

        let request = JsonRpcRequest::new(
            method.to_string(),
            Some(serde_json::to_value(params).unwrap()),
            serde_json::Value::Number(id.into()),
        );

        let message = MessageWithFds::new(JsonRpcMessage::Request(request), vec![]);
        self.sender
            .send(message)
            .await
            .map_err(|e| HelperError::Ipc(format!("failed to send request: {}", e)))?;

        // Receive response
        let response = self
            .receiver
            .receive()
            .await
            .map_err(|e| HelperError::Ipc(format!("failed to receive response: {}", e)))?;

        match response.message {
            JsonRpcMessage::Response(resp) => {
                if let Some(error) = resp.error {
                    return Err(HelperError::RpcError {
                        code: error.code(),
                        message: error.message().to_string(),
                    });
                }

                let result = resp
                    .result
                    .ok_or_else(|| HelperError::Ipc("response missing result".to_string()))?;

                serde_json::from_value(result)
                    .map_err(|e| HelperError::Ipc(format!("failed to parse result: {}", e)))
            }
            other => Err(HelperError::Ipc(format!(
                "unexpected message type: {:?}",
                other
            ))),
        }
    }
}

/// Item received from a proxied layer stream.
#[derive(Debug)]
pub enum ProxiedTarSplitItem {
    /// Raw segment bytes (tar header/padding).
    Segment(Vec<u8>),
    /// File content with metadata and fd.
    FileContent {
        /// File descriptor for the content.
        fd: OwnedFd,
        /// File size.
        size: u64,
        /// File name/path.
        name: String,
    },
}

/// Stream of tar-split items received via the helper proxy.
pub struct ProxiedLayerStream<'a> {
    receiver: &'a mut jsonrpc_fdpass::transport::Receiver,
    request_id: u64,
    finished: bool,
}

impl std::fmt::Debug for ProxiedLayerStream<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxiedLayerStream")
            .field("request_id", &self.request_id)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl<'a> ProxiedLayerStream<'a> {
    /// Get the next item from the stream.
    ///
    /// Returns `None` when the stream is complete.
    pub async fn next(&mut self) -> std::result::Result<Option<ProxiedTarSplitItem>, HelperError> {
        if self.finished {
            return Ok(None);
        }

        let msg_with_fds = match self.receiver.receive().await {
            Ok(m) => m,
            Err(jsonrpc_fdpass::Error::ConnectionClosed) => {
                self.finished = true;
                return Ok(None);
            }
            Err(e) => {
                return Err(HelperError::Ipc(format!("failed to receive: {}", e)));
            }
        };

        let mut fds = msg_with_fds.file_descriptors;

        match msg_with_fds.message {
            JsonRpcMessage::Notification(notif) => {
                let params = notif.params.unwrap_or(serde_json::Value::Null);

                match notif.method.as_str() {
                    "stream.segment" => {
                        let seg: StreamSegmentNotification = serde_json::from_value(params)
                            .map_err(|e| {
                                HelperError::Ipc(format!("invalid segment params: {}", e))
                            })?;

                        let bytes = BASE64_STANDARD.decode(&seg.data).map_err(|e| {
                            HelperError::Ipc(format!("failed to decode segment: {}", e))
                        })?;

                        Ok(Some(ProxiedTarSplitItem::Segment(bytes)))
                    }
                    "stream.file" => {
                        let file: StreamFileNotification = serde_json::from_value(params)
                            .map_err(|e| HelperError::Ipc(format!("invalid file params: {}", e)))?;

                        if fds.is_empty() {
                            return Err(HelperError::Ipc(
                                "file notification missing fd".to_string(),
                            ));
                        }

                        let fd = fds.remove(0);
                        Ok(Some(ProxiedTarSplitItem::FileContent {
                            fd,
                            size: file.size,
                            name: file.name,
                        }))
                    }
                    other => Err(HelperError::Ipc(format!(
                        "unknown notification method: {}",
                        other
                    ))),
                }
            }
            JsonRpcMessage::Response(resp) => {
                // Final response - stream is complete
                self.finished = true;

                if let Some(error) = resp.error {
                    return Err(HelperError::RpcError {
                        code: error.code(),
                        message: error.message().to_string(),
                    });
                }

                Ok(None)
            }
            JsonRpcMessage::Request(_) => Err(HelperError::Ipc(
                "unexpected request from helper".to_string(),
            )),
        }
    }
}

impl Drop for StorageProxy {
    fn drop(&mut self) {
        // Try to kill the child if it's still running
        let _ = self.child.kill();
    }
}

// ============================================================================
// ProxiedStorage - High-level API with transparent proxy support
// ============================================================================

/// Storage access mode for [`ProxiedStorage`].
#[derive(Debug)]
enum StorageMode {
    /// Direct access - we can read files directly.
    Direct(Storage),
    /// Proxied access via userns helper.
    Proxied {
        /// The proxy connection.
        proxy: StorageProxy,
        /// Storage path (for RPC calls).
        path: PathBuf,
    },
}

/// High-level storage access with automatic userns helper support.
///
/// This type provides transparent access to containers-storage. When running
/// as an unprivileged user who cannot directly read restrictive files, it
/// automatically spawns a userns helper process and proxies operations through it.
///
/// When the current process has sufficient privileges (root or CAP_DAC_OVERRIDE),
/// operations are performed directly without any IPC overhead.
///
/// # Example
///
/// ```no_run
/// use cstor_rs::userns_helper::ProxiedStorage;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Automatically uses proxy if needed
/// let mut storage = ProxiedStorage::open_with_proxy("/path/to/storage").await?;
///
/// // These work transparently regardless of access mode (async for proxied mode)
/// for image in storage.list_images_async().await? {
///     println!("Image: {} - {:?}", image.id, image.names);
/// }
///
/// // Streaming also works transparently
/// let layer_id = "...";
/// let mut stream = storage.stream_layer(layer_id).await?;
/// while let Some(item) = stream.next().await? {
///     // Process items...
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct ProxiedStorage {
    mode: StorageMode,
}

impl ProxiedStorage {
    /// Open storage with automatic proxy support if needed.
    ///
    /// If the current process can read arbitrary files (root or CAP_DAC_OVERRIDE),
    /// opens storage directly. Otherwise, spawns a userns helper process.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the storage root directory
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The storage path is invalid
    /// - The proxy cannot be spawned (if needed)
    pub async fn open_with_proxy<P: AsRef<Path>>(
        path: P,
    ) -> std::result::Result<Self, HelperError> {
        let path = path.as_ref().to_path_buf();

        // First, try to open storage directly to validate it exists
        let storage = Storage::open(&path).map_err(|e| {
            HelperError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("failed to open storage: {}", e),
            ))
        })?;

        // Check if we need a proxy
        if can_bypass_file_permissions() {
            Ok(Self {
                mode: StorageMode::Direct(storage),
            })
        } else {
            // Need proxy - spawn it
            let proxy = StorageProxy::spawn().await?.ok_or_else(|| {
                HelperError::Spawn(std::io::Error::other(
                    "failed to determine if proxy is needed",
                ))
            })?;

            Ok(Self {
                mode: StorageMode::Proxied { proxy, path },
            })
        }
    }

    /// Open storage directly without proxy.
    ///
    /// Use this when you know you have sufficient privileges or don't need
    /// to access restrictive files.
    pub fn open_direct<P: AsRef<Path>>(path: P) -> CstorResult<Self> {
        let storage = Storage::open(path)?;
        Ok(Self {
            mode: StorageMode::Direct(storage),
        })
    }

    /// Check if this storage is using a proxy.
    pub fn is_proxied(&self) -> bool {
        matches!(self.mode, StorageMode::Proxied { .. })
    }

    /// Get the storage path.
    pub fn path(&self) -> &Path {
        match &self.mode {
            StorageMode::Direct(_storage) => {
                // For direct mode, we don't have the original path stored
                // This is a limitation - we could store it if needed
                Path::new(".")
            }
            StorageMode::Proxied { path, .. } => path,
        }
    }

    /// List images in storage.
    pub fn list_images(&self) -> CstorResult<Vec<ImageInfo>> {
        match &self.mode {
            StorageMode::Direct(storage) => {
                let images = storage.list_images()?;
                Ok(images
                    .iter()
                    .map(|img| ImageInfo {
                        id: img.id().to_string(),
                        names: img.names(storage).unwrap_or_default(),
                    })
                    .collect())
            }
            StorageMode::Proxied { .. } => {
                // Proxied mode requires async - return error for sync call
                Err(StorageError::TarSplitError(
                    "list_images requires async for proxied storage - use list_images_async"
                        .to_string(),
                ))
            }
        }
    }

    /// List images asynchronously (works with both direct and proxied modes).
    pub async fn list_images_async(&mut self) -> std::result::Result<Vec<ImageInfo>, HelperError> {
        match &mut self.mode {
            StorageMode::Direct(storage) => {
                let images = storage.list_images().map_err(|e| {
                    HelperError::HelperError(format!("failed to list images: {}", e))
                })?;
                Ok(images
                    .iter()
                    .map(|img| ImageInfo {
                        id: img.id().to_string(),
                        names: img.names(storage).unwrap_or_default(),
                    })
                    .collect())
            }
            StorageMode::Proxied { proxy, path } => {
                proxy.list_images(path.to_str().unwrap_or(".")).await
            }
        }
    }

    /// Get image information.
    pub async fn get_image(
        &mut self,
        image_ref: &str,
    ) -> std::result::Result<GetImageResult, HelperError> {
        match &mut self.mode {
            StorageMode::Direct(storage) => {
                // Try by ID first, then by name
                let image = storage
                    .get_image(image_ref)
                    .or_else(|_| storage.find_image_by_name(image_ref))
                    .map_err(|e| HelperError::HelperError(format!("image not found: {}", e)))?;

                let diff_ids = image.layers().map_err(|e| {
                    HelperError::HelperError(format!("failed to get layers: {}", e))
                })?;

                Ok(GetImageResult {
                    id: image.id().to_string(),
                    names: image.names(storage).unwrap_or_default(),
                    layer_diff_ids: diff_ids,
                })
            }
            StorageMode::Proxied { proxy, path } => {
                proxy
                    .get_image(path.to_str().unwrap_or("."), image_ref)
                    .await
            }
        }
    }

    /// Get layer metadata.
    pub async fn get_layer_metadata(
        &mut self,
        layer_id: &str,
    ) -> std::result::Result<LayerMetadata, HelperError> {
        match &mut self.mode {
            StorageMode::Direct(storage) => storage
                .get_layer_metadata(layer_id)
                .map_err(|e| HelperError::HelperError(format!("layer not found: {}", e))),
            StorageMode::Proxied { proxy, path } => {
                let result = proxy
                    .get_layer_metadata(path.to_str().unwrap_or("."), layer_id)
                    .await?;
                Ok(LayerMetadata {
                    id: result.id,
                    parent: result.parent,
                    diff_size: result.diff_size,
                    compressed_size: result.compressed_size,
                })
            }
        }
    }

    /// Get TOC for a layer.
    pub async fn get_layer_toc(&mut self, layer_id: &str) -> std::result::Result<Toc, HelperError> {
        match &mut self.mode {
            StorageMode::Direct(storage) => {
                let layer = Layer::open(storage, layer_id)
                    .map_err(|e| HelperError::HelperError(format!("layer not found: {}", e)))?;
                Toc::from_layer(storage, &layer)
                    .map_err(|e| HelperError::HelperError(format!("failed to generate TOC: {}", e)))
            }
            StorageMode::Proxied { proxy, path } => {
                proxy
                    .get_layer_toc(path.to_str().unwrap_or("."), layer_id)
                    .await
            }
        }
    }

    /// Get merged TOC for an image.
    pub async fn get_image_toc(&mut self, image_id: &str) -> std::result::Result<Toc, HelperError> {
        match &mut self.mode {
            StorageMode::Direct(storage) => {
                let image = storage
                    .get_image(image_id)
                    .map_err(|e| HelperError::HelperError(format!("image not found: {}", e)))?;
                Toc::from_image(storage, &image)
                    .map_err(|e| HelperError::HelperError(format!("failed to generate TOC: {}", e)))
            }
            StorageMode::Proxied { proxy, path } => {
                proxy
                    .get_image_toc(path.to_str().unwrap_or("."), image_id)
                    .await
            }
        }
    }

    /// Stream layer content as tar-split items.
    ///
    /// Returns a stream that yields items with file descriptors for file content.
    /// For direct mode, file descriptors are opened locally. For proxied mode,
    /// file descriptors are passed via SCM_RIGHTS from the helper process.
    pub async fn stream_layer(
        &mut self,
        layer_id: &str,
    ) -> std::result::Result<LayerContentStream<'_>, HelperError> {
        match &mut self.mode {
            StorageMode::Direct(storage) => {
                let layer = Layer::open(storage, layer_id)
                    .map_err(|e| HelperError::HelperError(format!("layer not found: {}", e)))?;
                let stream = TarSplitFdStream::new(storage, &layer).map_err(|e| {
                    HelperError::HelperError(format!("failed to create stream: {}", e))
                })?;

                Ok(LayerContentStream::Direct(Box::new(DirectLayerStream {
                    stream,
                })))
            }
            StorageMode::Proxied { proxy, path } => {
                let stream = proxy
                    .stream_layer(path.to_str().unwrap_or("."), layer_id)
                    .await?;
                Ok(LayerContentStream::Proxied(stream))
            }
        }
    }

    /// Shutdown the proxy if one is running.
    pub async fn shutdown(self) -> std::result::Result<(), HelperError> {
        match self.mode {
            StorageMode::Direct(_) => Ok(()),
            StorageMode::Proxied { proxy, .. } => proxy.shutdown().await,
        }
    }

    /// Extract a layer to a directory.
    ///
    /// This extracts all files from the layer to the destination directory,
    /// using reflinks when possible for efficient zero-copy extraction.
    /// Works transparently in both direct and proxied modes.
    ///
    /// # Arguments
    ///
    /// * `layer_id` - Layer ID to extract
    /// * `dest` - Destination directory handle
    /// * `options` - Extraction options
    ///
    /// # Returns
    ///
    /// Statistics about the extraction.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cstor_rs::userns_helper::ProxiedStorage;
    /// use cstor_rs::extract::ExtractionOptions;
    /// use cap_std::fs::Dir;
    /// use cap_std::ambient_authority;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut storage = ProxiedStorage::open_with_proxy("/path/to/storage").await?;
    /// let dest = Dir::open_ambient_dir("/tmp/extract", ambient_authority())?;
    /// let options = ExtractionOptions::default();
    ///
    /// let stats = storage.extract_layer("layer-id", &dest, &options).await?;
    /// println!("Extracted {} files", stats.files_extracted);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn extract_layer(
        &mut self,
        layer_id: &str,
        dest: &cap_std::fs::Dir,
        options: &crate::extract::ExtractionOptions,
    ) -> std::result::Result<crate::extract::ExtractionStats, HelperError> {
        match &mut self.mode {
            StorageMode::Direct(storage) => {
                let layer = Layer::open(storage, layer_id)
                    .map_err(|e| HelperError::HelperError(format!("layer not found: {}", e)))?;
                crate::extract::extract_layer(storage, &layer, dest, options)
                    .map_err(|e| HelperError::HelperError(format!("extraction failed: {}", e)))
            }
            StorageMode::Proxied { proxy, path } => {
                // Stream layer content via IPC and extract
                let mut stream = proxy
                    .stream_layer(path.to_str().unwrap_or("."), layer_id)
                    .await?;

                // Use the extract_from_stream function with an async closure adapter
                // Since extract_from_stream expects a sync closure but we have an async stream,
                // we need to collect items first or use a different approach
                let mut items = Vec::new();
                while let Some(item) = stream.next().await? {
                    items.push(item);
                }

                let mut iter = items.into_iter();
                crate::extract::extract_from_stream(dest, options, || Ok(iter.next()))
                    .map_err(|e| HelperError::HelperError(format!("extraction failed: {}", e)))
            }
        }
    }

    /// Extract an image (all layers merged) to a directory.
    ///
    /// This extracts all layers in order, applying overlay semantics:
    /// - Upper layer files override lower layer files
    /// - Whiteouts remove files from lower layers
    ///
    /// # Arguments
    ///
    /// * `image_ref` - Image ID or name
    /// * `dest` - Destination directory handle
    /// * `options` - Extraction options
    ///
    /// # Returns
    ///
    /// Statistics about the extraction.
    pub async fn extract_image(
        &mut self,
        image_ref: &str,
        dest: &cap_std::fs::Dir,
        options: &crate::extract::ExtractionOptions,
    ) -> std::result::Result<crate::extract::ExtractionStats, HelperError> {
        // Get image info and layer IDs first
        let image_result = self.get_image(image_ref).await?;
        let layer_diff_ids = image_result.layer_diff_ids.clone();

        match &mut self.mode {
            StorageMode::Direct(storage) => {
                let image = storage
                    .get_image(image_ref)
                    .or_else(|_| storage.find_image_by_name(image_ref))
                    .map_err(|e| HelperError::HelperError(format!("image not found: {}", e)))?;
                crate::extract::extract_image(storage, &image, dest, options)
                    .map_err(|e| HelperError::HelperError(format!("extraction failed: {}", e)))
            }
            StorageMode::Proxied { .. } => {
                let mut total_stats = crate::extract::ExtractionStats::default();

                // Extract each layer in order
                for diff_id in &layer_diff_ids {
                    // Try to get layer metadata to find storage ID
                    let layer_id = match self.get_layer_metadata(diff_id).await {
                        Ok(metadata) => metadata.id,
                        Err(_) => {
                            // Try with diff_id directly (stripped of sha256: prefix)
                            diff_id
                                .strip_prefix("sha256:")
                                .unwrap_or(diff_id)
                                .to_string()
                        }
                    };

                    let layer_stats = self.extract_layer(&layer_id, dest, options).await?;

                    total_stats.files_extracted += layer_stats.files_extracted;
                    total_stats.directories_created += layer_stats.directories_created;
                    total_stats.symlinks_created += layer_stats.symlinks_created;
                    total_stats.hardlinks_created += layer_stats.hardlinks_created;
                    total_stats.bytes_reflinked += layer_stats.bytes_reflinked;
                    total_stats.bytes_copied += layer_stats.bytes_copied;
                    total_stats.whiteouts_processed += layer_stats.whiteouts_processed;
                    total_stats.entries_skipped += layer_stats.entries_skipped;
                    total_stats.permission_failures += layer_stats.permission_failures;
                    total_stats.ownership_failures += layer_stats.ownership_failures;
                }

                Ok(total_stats)
            }
        }
    }
}

/// Unified stream of layer content items.
///
/// This enum wraps both direct and proxied layer streams, providing a common
/// interface for iterating over layer content.
#[derive(Debug)]
pub enum LayerContentStream<'a> {
    /// Direct stream (no proxy).
    ///
    /// Boxed to reduce enum size variance between variants.
    Direct(Box<DirectLayerStream>),
    /// Proxied stream (via userns helper).
    Proxied(ProxiedLayerStream<'a>),
}

impl<'a> LayerContentStream<'a> {
    /// Get the next item from the stream.
    pub async fn next(&mut self) -> std::result::Result<Option<ProxiedTarSplitItem>, HelperError> {
        match self {
            LayerContentStream::Direct(stream) => stream.next(),
            LayerContentStream::Proxied(stream) => stream.next().await,
        }
    }
}

/// Direct layer stream wrapper.
#[derive(Debug)]
pub struct DirectLayerStream {
    stream: TarSplitFdStream,
}

impl DirectLayerStream {
    /// Get the next item from the stream.
    fn next(&mut self) -> std::result::Result<Option<ProxiedTarSplitItem>, HelperError> {
        match self.stream.next() {
            Ok(Some(TarSplitItem::Segment(bytes))) => Ok(Some(ProxiedTarSplitItem::Segment(bytes))),
            Ok(Some(TarSplitItem::FileContent { fd, size, name })) => {
                Ok(Some(ProxiedTarSplitItem::FileContent { fd, size, name }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(HelperError::HelperError(format!("stream error: {}", e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_helper_env_not_set() {
        // Should return immediately without doing anything
        init_if_helper();
    }

    #[test]
    fn test_can_bypass_skips_helper() {
        // If we can bypass, spawn should return None
        // Can't easily test without actually calling spawn
    }

    #[test]
    fn test_open_file_params_serialization() {
        let params = OpenFileParams {
            path: "/etc/hosts".to_string(),
        };
        let json = serde_json::to_string(&params).unwrap();
        assert!(json.contains("/etc/hosts"));

        let decoded: OpenFileParams = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.path, "/etc/hosts");
    }

    /// Test that spawns a helper and opens a file via IPC.
    ///
    /// This test is ignored by default because it requires `podman unshare`
    /// to work, which may not be available in all environments.
    #[tokio::test]
    #[ignore = "requires podman unshare"]
    async fn test_storage_proxy_open_file() {
        use std::io::Read;

        // Use the CLI binary, not the test harness.
        // This is needed because /proc/self/exe in tests is the test harness.
        let cli_binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("target/debug/cstor-rs");

        if !cli_binary.exists() {
            panic!(
                "CLI binary not found at {:?}. Run 'cargo build -p cstor-rs' first.",
                cli_binary
            );
        }

        // Spawn a helper with the CLI binary
        let mut proxy = StorageProxy::spawn_helper_with_binary(cli_binary)
            .await
            .expect("failed to spawn helper");

        // Give the helper a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Open a well-known file
        let fd = proxy
            .open_file("/etc/hosts")
            .await
            .expect("failed to open file");

        // Read from the fd
        let mut file = std::fs::File::from(fd);
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("failed to read");

        // /etc/hosts should contain localhost
        assert!(
            contents.contains("localhost"),
            "expected /etc/hosts to contain 'localhost', got: {}",
            contents
        );

        // Shutdown gracefully
        proxy.shutdown().await.expect("failed to shutdown");
    }

    #[test]
    fn test_image_info_serialization() {
        let info = ImageInfo {
            id: "abc123".to_string(),
            names: vec!["docker.io/library/alpine:latest".to_string()],
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("abc123"));
        assert!(json.contains("alpine"));

        let decoded: ImageInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, "abc123");
        assert_eq!(decoded.names.len(), 1);
    }

    #[test]
    fn test_stream_segment_notification_serialization() {
        let seg = StreamSegmentNotification {
            data: BASE64_STANDARD.encode(b"test data"),
        };
        let json = serde_json::to_string(&seg).unwrap();

        let decoded: StreamSegmentNotification = serde_json::from_str(&json).unwrap();
        let bytes = BASE64_STANDARD.decode(&decoded.data).unwrap();
        assert_eq!(bytes, b"test data");
    }

    #[test]
    fn test_stream_file_notification_serialization() {
        let file = StreamFileNotification {
            name: "etc/hosts".to_string(),
            size: 1234,
        };
        let json = serde_json::to_string(&file).unwrap();
        assert!(json.contains("etc/hosts"));
        assert!(json.contains("1234"));

        let decoded: StreamFileNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.name, "etc/hosts");
        assert_eq!(decoded.size, 1234);
    }

    #[test]
    fn test_get_image_result_serialization() {
        let result = GetImageResult {
            id: "sha256:abc123".to_string(),
            names: vec!["alpine:latest".to_string()],
            layer_diff_ids: vec!["sha256:layer1".to_string(), "sha256:layer2".to_string()],
        };
        let json = serde_json::to_string(&result).unwrap();

        let decoded: GetImageResult = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, "sha256:abc123");
        assert_eq!(decoded.layer_diff_ids.len(), 2);
    }

    #[test]
    fn test_toc_result_serialization() {
        let toc = Toc::new();
        let result = TocResult { toc };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("version"));

        let decoded: TocResult = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.toc.version, 1);
    }

    #[test]
    fn test_proxied_storage_is_proxied() {
        // Direct mode should not be proxied
        // We can't easily test proxied mode without podman
    }
}
