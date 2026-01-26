//! Client for the skopeo experimental-image-proxy v2 protocol.
//!
//! This module provides a client for communicating with skopeo's experimental-image-proxy
//! using the v2 protocol. The v2 protocol uses JSON-RPC 2.0 with file descriptor passing
//! to enable efficient layer extraction using tar-split metadata and zero-copy file access.
//!
//! # Protocol Overview
//!
//! The v2 protocol extends the original proxy with:
//! - Proper JSON-RPC 2.0 request/response semantics
//! - Version negotiation via `Initialize`
//! - Streaming layer data via `GetLayerTarSplit` with notifications
//! - File descriptor passing for zero-copy file extraction
//!
//! # Example
//!
//! ```no_run
//! use cstor_rs::proxy_v2::ProxyV2Client;
//! use tokio::net::UnixStream;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let stream = UnixStream::connect("/run/skopeo-proxy.sock").await?;
//! let mut client = ProxyV2Client::connect(stream);
//!
//! // Initialize and check capabilities
//! let init = client.initialize().await?;
//! println!("Proxy version: {}, capabilities: {:?}", init.version, init.capabilities);
//!
//! // Open an image
//! let image_id = client.open_image("containers-storage:fedora:latest").await?;
//!
//! // Get layer as tar-split stream
//! let mut stream = client.get_layer_tar_split(image_id, "sha256:abc123...").await?;
//! while let Some(item) = stream.next().await? {
//!     match item {
//!         cstor_rs::proxy_v2::LayerItem::File { name, fd, .. } => {
//!             println!("File: {} (fd received)", name);
//!         }
//!         _ => {}
//!     }
//! }
//!
//! client.close_image(image_id).await?;
//! client.shutdown().await?;
//! # Ok(())
//! # }
//! ```

use std::os::unix::io::OwnedFd;

use base64::prelude::*;
use jsonrpc_fdpass::transport::{Receiver, Sender, UnixSocketTransport};
use jsonrpc_fdpass::{
    Error as RpcError, JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, MessageWithFds,
};
use serde::{Deserialize, Serialize};
use tokio::net::UnixStream;

use crate::error::{Result, StorageError};

// ============================================================================
// Request/Response Message Types
// ============================================================================

/// Parameters for the `Initialize` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeParams {
    /// Protocol version requested by the client.
    pub version: u32,
}

/// Result of the `Initialize` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeResult {
    /// Server version string.
    pub version: String,
    /// List of capabilities supported by the server.
    pub capabilities: Vec<String>,
}

/// Parameters for the `OpenImage` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenImageParams {
    /// Image reference (e.g., "containers-storage:fedora:latest").
    pub image_ref: String,
}

/// Result of the `OpenImage` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenImageResult {
    /// Unique identifier for the opened image session.
    pub image_id: u64,
}

/// Parameters for the `CloseImage` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseImageParams {
    /// Image ID to close.
    pub image_id: u64,
}

/// Parameters for the `GetLayerTarSplit` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetLayerTarSplitParams {
    /// Image ID from OpenImage.
    pub image_id: u64,
    /// Layer digest (e.g., "sha256:...").
    pub layer_digest: String,
}

/// Result of the `GetLayerTarSplit` method (sent after all notifications).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetLayerTarSplitResult {
    /// Whether the stream was successfully sent.
    pub success: bool,
}

// ============================================================================
// Streaming Notification Types
// ============================================================================

/// Parameters for the `layer.start` notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerStartParams {
    /// Layer digest.
    pub digest: String,
    /// Uncompressed size of the layer in bytes.
    pub uncompressed_size: i64,
}

/// Parameters for the `layer.segment` notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerSegmentParams {
    /// Base64-encoded segment data (tar header/padding bytes).
    pub data: String,
}

/// Parameters for the `layer.file` notification.
///
/// Note: The file descriptor for the file content is passed positionally
/// in the `MessageWithFds.file_descriptors` vector, not as a field in
/// this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerFileParams {
    /// File name/path within the tar archive.
    pub name: String,
    /// File size in bytes.
    pub size: i64,
    /// File mode (Unix permissions).
    pub mode: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Modification time in RFC 3339 format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime: Option<String>,
    /// Symlink/hardlink target (empty for regular files).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_name: Option<String>,
}

/// Parameters for the `layer.end` notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerEndParams {
    /// Number of files sent in this stream.
    pub files_sent: u32,
}

// ============================================================================
// LayerItem - Processed stream items
// ============================================================================

/// Received item from a layer tar-split stream.
///
/// These are the processed items that clients receive when iterating over a
/// `LayerStream`. The base64 segment data is decoded and file descriptors
/// are extracted from the protocol messages.
#[derive(Debug)]
pub enum LayerItem {
    /// Stream start with layer metadata.
    Start {
        /// Layer digest.
        digest: String,
        /// Uncompressed size in bytes.
        uncompressed_size: i64,
    },
    /// Raw segment bytes (decoded from base64).
    ///
    /// These are tar header/padding bytes that should be written directly
    /// to reconstruct the tar archive.
    Segment(Vec<u8>),
    /// File entry with metadata and content file descriptor.
    File {
        /// File name/path in the archive.
        name: String,
        /// File size in bytes.
        size: i64,
        /// File mode (Unix permissions).
        mode: u32,
        /// File descriptor for reading the file content.
        fd: OwnedFd,
    },
    /// Stream end marker.
    End {
        /// Number of files that were sent.
        files_sent: u32,
    },
}

// ============================================================================
// ProxyV2Client
// ============================================================================

/// Client for the skopeo experimental-image-proxy v2 protocol.
///
/// This client communicates with a skopeo proxy over a Unix socket using
/// JSON-RPC 2.0 with file descriptor passing. It supports the v2 protocol
/// extensions for efficient layer extraction using tar-split metadata.
pub struct ProxyV2Client {
    sender: Sender,
    receiver: Receiver,
    request_id: u64,
}

impl std::fmt::Debug for ProxyV2Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyV2Client")
            .field("request_id", &self.request_id)
            .finish_non_exhaustive()
    }
}

impl ProxyV2Client {
    /// Create a new client connected to the given Unix socket.
    ///
    /// # Errors
    ///
    /// Create a new proxy client from a Unix socket.
    pub fn connect(socket: UnixStream) -> Self {
        let transport = UnixSocketTransport::new(socket);
        let (sender, receiver) = transport.split();

        Self {
            sender,
            receiver,
            request_id: 0,
        }
    }

    /// Get the next request ID.
    fn next_id(&mut self) -> u64 {
        self.request_id += 1;
        self.request_id
    }

    /// Send a JSON-RPC request and wait for the response.
    async fn call<P: Serialize, R: for<'de> Deserialize<'de>>(
        &mut self,
        method: &str,
        params: P,
    ) -> Result<R> {
        let id = self.next_id();
        let params_value = serde_json::to_value(params).map_err(StorageError::JsonParse)?;

        let request = JsonRpcRequest::new(
            method.to_string(),
            Some(params_value),
            serde_json::Value::Number(id.into()),
        );
        let message = MessageWithFds::new(JsonRpcMessage::Request(request), vec![]);

        self.sender
            .send(message)
            .await
            .map_err(|e| StorageError::TarSplitError(format!("Failed to send request: {}", e)))?;

        // Wait for response
        let response = self.receive_response(id).await?;
        Ok(response)
    }

    /// Wait for and parse a response with the given request ID.
    async fn receive_response<R: for<'de> Deserialize<'de>>(
        &mut self,
        expected_id: u64,
    ) -> Result<R> {
        loop {
            let msg_with_fds = match self.receiver.receive().await {
                Ok(m) => m,
                Err(RpcError::ConnectionClosed) => {
                    return Err(StorageError::TarSplitError(
                        "Connection closed while waiting for response".to_string(),
                    ));
                }
                Err(e) => {
                    return Err(StorageError::TarSplitError(format!(
                        "Failed to receive response: {}",
                        e
                    )));
                }
            };

            match msg_with_fds.message {
                JsonRpcMessage::Response(response) => {
                    // Check if this is the response we're waiting for
                    let response_id = response.id.as_u64().ok_or_else(|| {
                        StorageError::TarSplitError("Invalid response ID".to_string())
                    })?;

                    if response_id != expected_id {
                        return Err(StorageError::TarSplitError(format!(
                            "Unexpected response ID: expected {}, got {}",
                            expected_id, response_id
                        )));
                    }

                    // Check for error
                    if let Some(error) = response.error {
                        return Err(StorageError::TarSplitError(format!(
                            "RPC error {}: {}",
                            error.code(),
                            error.message()
                        )));
                    }

                    // Parse result
                    let result_value = response.result.ok_or_else(|| {
                        StorageError::TarSplitError("Response missing result".to_string())
                    })?;

                    let result: R =
                        serde_json::from_value(result_value).map_err(StorageError::JsonParse)?;
                    return Ok(result);
                }
                JsonRpcMessage::Notification(_) => {
                    // Skip notifications while waiting for response
                    // (shouldn't happen in normal call flow, but handle gracefully)
                    continue;
                }
                JsonRpcMessage::Request(_) => {
                    return Err(StorageError::TarSplitError(
                        "Unexpected request from server".to_string(),
                    ));
                }
            }
        }
    }

    /// Initialize the v2 protocol connection.
    ///
    /// This should be the first method called after connecting. It negotiates
    /// the protocol version and returns the server's capabilities.
    ///
    /// # Errors
    ///
    /// Returns an error if the server doesn't support v2 or communication fails.
    pub async fn initialize(&mut self) -> Result<InitializeResult> {
        self.call("Initialize", InitializeParams { version: 2 })
            .await
    }

    /// Open an image for reading.
    ///
    /// # Arguments
    ///
    /// * `image_ref` - Image reference (e.g., "containers-storage:fedora:latest")
    ///
    /// # Returns
    ///
    /// The image ID to use for subsequent operations.
    ///
    /// # Errors
    ///
    /// Returns an error if the image cannot be opened.
    pub async fn open_image(&mut self, image_ref: &str) -> Result<u64> {
        let result: OpenImageResult = self
            .call(
                "OpenImage",
                OpenImageParams {
                    image_ref: image_ref.to_string(),
                },
            )
            .await?;
        Ok(result.image_id)
    }

    /// Close an image session.
    ///
    /// # Arguments
    ///
    /// * `image_id` - Image ID from `open_image`
    ///
    /// # Errors
    ///
    /// Returns an error if the image cannot be closed.
    pub async fn close_image(&mut self, image_id: u64) -> Result<()> {
        let _: serde_json::Value = self
            .call("CloseImage", CloseImageParams { image_id })
            .await?;
        Ok(())
    }

    /// Start receiving a layer as a tar-split stream.
    ///
    /// This sends the `GetLayerTarSplit` request and returns a stream that yields
    /// `LayerItem`s. The caller should iterate over the stream to receive all
    /// layer data.
    ///
    /// # Arguments
    ///
    /// * `image_id` - Image ID from `open_image`
    /// * `layer_digest` - Layer digest (e.g., "sha256:...")
    ///
    /// # Returns
    ///
    /// A `LayerStream` that yields `LayerItem`s.
    ///
    /// # Errors
    ///
    /// Returns an error if the request cannot be sent.
    pub async fn get_layer_tar_split(
        &mut self,
        image_id: u64,
        layer_digest: &str,
    ) -> Result<LayerStream<'_>> {
        let id = self.next_id();
        let params = GetLayerTarSplitParams {
            image_id,
            layer_digest: layer_digest.to_string(),
        };
        let params_value = serde_json::to_value(params).map_err(StorageError::JsonParse)?;

        let request = JsonRpcRequest::new(
            "GetLayerTarSplit".to_string(),
            Some(params_value),
            serde_json::Value::Number(id.into()),
        );
        let message = MessageWithFds::new(JsonRpcMessage::Request(request), vec![]);

        self.sender.send(message).await.map_err(|e| {
            StorageError::TarSplitError(format!("Failed to send GetLayerTarSplit request: {}", e))
        })?;

        Ok(LayerStream {
            receiver: &mut self.receiver,
            request_id: id,
            finished: false,
        })
    }

    /// Shutdown the connection gracefully.
    ///
    /// # Errors
    ///
    /// Returns an error if the shutdown request fails.
    pub async fn shutdown(&mut self) -> Result<()> {
        // Send a notification to indicate we're done
        let notification = JsonRpcNotification::new("shutdown".to_string(), None);
        let message = MessageWithFds::new(JsonRpcMessage::Notification(notification), vec![]);

        self.sender
            .send(message)
            .await
            .map_err(|e| StorageError::TarSplitError(format!("Failed to send shutdown: {}", e)))?;

        Ok(())
    }
}

// ============================================================================
// LayerStream
// ============================================================================

/// Stream of layer items from a `GetLayerTarSplit` request.
///
/// This stream yields `LayerItem`s that represent the tar-split stream data.
/// Iterate over it using the `next()` method until it returns `None`.
pub struct LayerStream<'a> {
    receiver: &'a mut Receiver,
    request_id: u64,
    finished: bool,
}

impl std::fmt::Debug for LayerStream<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LayerStream")
            .field("request_id", &self.request_id)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl LayerStream<'_> {
    /// Get the next item from the layer stream.
    ///
    /// Returns `None` when the stream is complete (after receiving the final
    /// response from the server).
    ///
    /// # Errors
    ///
    /// Returns an error if communication fails or the stream data is invalid.
    pub async fn next(&mut self) -> Result<Option<LayerItem>> {
        if self.finished {
            return Ok(None);
        }

        let msg_with_fds = match self.receiver.receive().await {
            Ok(m) => m,
            Err(RpcError::ConnectionClosed) => {
                self.finished = true;
                return Ok(None);
            }
            Err(e) => {
                return Err(StorageError::TarSplitError(format!(
                    "Failed to receive layer stream message: {}",
                    e
                )));
            }
        };

        let mut fds = msg_with_fds.file_descriptors;

        match msg_with_fds.message {
            JsonRpcMessage::Notification(notification) => {
                self.parse_notification(&notification, &mut fds)
            }
            JsonRpcMessage::Response(response) => {
                // This is the final response - stream is complete
                self.finished = true;

                // Verify it's the response for our request
                let response_id = response.id.as_u64().ok_or_else(|| {
                    StorageError::TarSplitError("Invalid response ID".to_string())
                })?;

                if response_id != self.request_id {
                    return Err(StorageError::TarSplitError(format!(
                        "Unexpected response ID: expected {}, got {}",
                        self.request_id, response_id
                    )));
                }

                // Check for error
                if let Some(error) = response.error {
                    return Err(StorageError::TarSplitError(format!(
                        "GetLayerTarSplit failed: {} (code {})",
                        error.message(),
                        error.code()
                    )));
                }

                // Parse the success result (optional, we mostly care that it succeeded)
                if let Some(result) = response.result {
                    let _tar_split_result: GetLayerTarSplitResult =
                        serde_json::from_value(result).map_err(StorageError::JsonParse)?;
                }

                Ok(None)
            }
            JsonRpcMessage::Request(_) => Err(StorageError::TarSplitError(
                "Unexpected request from server during layer stream".to_string(),
            )),
        }
    }

    /// Parse a notification into a LayerItem.
    fn parse_notification(
        &self,
        notification: &JsonRpcNotification,
        fds: &mut Vec<OwnedFd>,
    ) -> Result<Option<LayerItem>> {
        let params = notification
            .params
            .clone()
            .unwrap_or(serde_json::Value::Null);

        match notification.method.as_str() {
            "layer.start" => {
                let start: LayerStartParams =
                    serde_json::from_value(params).map_err(StorageError::JsonParse)?;
                Ok(Some(LayerItem::Start {
                    digest: start.digest,
                    uncompressed_size: start.uncompressed_size,
                }))
            }
            "layer.segment" => {
                let segment: LayerSegmentParams =
                    serde_json::from_value(params).map_err(StorageError::JsonParse)?;

                // Decode base64 data
                let bytes = BASE64_STANDARD.decode(&segment.data).map_err(|e| {
                    StorageError::TarSplitError(format!("Failed to decode segment base64: {}", e))
                })?;

                Ok(Some(LayerItem::Segment(bytes)))
            }
            "layer.file" => {
                let file: LayerFileParams =
                    serde_json::from_value(params).map_err(StorageError::JsonParse)?;

                // Extract the file descriptor (passed positionally as first fd)
                if fds.is_empty() {
                    return Err(StorageError::TarSplitError(
                        "layer.file notification received without file descriptor".to_string(),
                    ));
                }

                // Take ownership of the first fd (file descriptors are passed positionally)
                let fd = fds.remove(0);

                Ok(Some(LayerItem::File {
                    name: file.name,
                    size: file.size,
                    mode: file.mode,
                    fd,
                }))
            }
            "layer.end" => {
                let end: LayerEndParams =
                    serde_json::from_value(params).map_err(StorageError::JsonParse)?;
                Ok(Some(LayerItem::End {
                    files_sent: end.files_sent,
                }))
            }
            other => {
                // Unknown notification - skip it
                tracing::warn!("Unknown notification method during layer stream: {}", other);
                // Recurse to get the next item (this is safe since we're in async context)
                // Actually, we can't recurse easily here, so just return None and let caller retry
                // For now, return an error for strict protocol compliance
                Err(StorageError::TarSplitError(format!(
                    "Unknown notification method: {}",
                    other
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpc_fdpass::JsonRpcResponse;
    use jsonrpc_fdpass::transport::UnixSocketTransport;

    /// Helper to create a notification MessageWithFds
    fn make_notification(
        method: &str,
        params: Option<serde_json::Value>,
        fds: Vec<OwnedFd>,
    ) -> MessageWithFds {
        let notification = JsonRpcNotification::new(method.to_string(), params);
        MessageWithFds::new(JsonRpcMessage::Notification(notification), fds)
    }

    /// Helper to create a response MessageWithFds
    fn make_response(id: u64, result: serde_json::Value) -> MessageWithFds {
        let response = JsonRpcResponse::success(result, serde_json::Value::Number(id.into()));
        MessageWithFds::new(JsonRpcMessage::Response(response), vec![])
    }

    #[tokio::test]
    async fn test_initialize() {
        let (sock_a, sock_b) = UnixStream::pair().unwrap();

        // Server side
        let server_handle = tokio::spawn(async move {
            let transport = UnixSocketTransport::new(sock_a);
            let (mut sender, mut receiver) = transport.split();

            // Receive Initialize request
            let msg = receiver.receive().await.unwrap();
            if let JsonRpcMessage::Request(req) = msg.message {
                assert_eq!(req.method, "Initialize");
                let params: InitializeParams = serde_json::from_value(req.params.unwrap()).unwrap();
                assert_eq!(params.version, 2);

                // Send response
                let result = InitializeResult {
                    version: "2.0.0".to_string(),
                    capabilities: vec!["tar-split-stream".to_string()],
                };
                let response = make_response(
                    req.id.as_u64().unwrap(),
                    serde_json::to_value(result).unwrap(),
                );
                sender.send(response).await.unwrap();
            } else {
                panic!("Expected Request");
            }
        });

        // Client side
        let mut client = ProxyV2Client::connect(sock_b);
        let result = client.initialize().await.unwrap();

        assert_eq!(result.version, "2.0.0");
        assert_eq!(result.capabilities, vec!["tar-split-stream"]);

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_open_image() {
        let (sock_a, sock_b) = UnixStream::pair().unwrap();

        // Server side
        let server_handle = tokio::spawn(async move {
            let transport = UnixSocketTransport::new(sock_a);
            let (mut sender, mut receiver) = transport.split();

            let msg = receiver.receive().await.unwrap();
            if let JsonRpcMessage::Request(req) = msg.message {
                assert_eq!(req.method, "OpenImage");
                let params: OpenImageParams = serde_json::from_value(req.params.unwrap()).unwrap();
                assert_eq!(params.image_ref, "containers-storage:test:latest");

                let result = OpenImageResult { image_id: 42 };
                let response = make_response(
                    req.id.as_u64().unwrap(),
                    serde_json::to_value(result).unwrap(),
                );
                sender.send(response).await.unwrap();
            } else {
                panic!("Expected Request");
            }
        });

        let mut client = ProxyV2Client::connect(sock_b);
        let image_id = client
            .open_image("containers-storage:test:latest")
            .await
            .unwrap();

        assert_eq!(image_id, 42);

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_layer_stream() {
        let (sock_a, sock_b) = UnixStream::pair().unwrap();

        // Server side
        let server_handle = tokio::spawn(async move {
            let transport = UnixSocketTransport::new(sock_a);
            let (mut sender, mut receiver) = transport.split();

            // Receive GetLayerTarSplit request
            let msg = receiver.receive().await.unwrap();
            let request_id = if let JsonRpcMessage::Request(req) = msg.message {
                assert_eq!(req.method, "GetLayerTarSplit");
                req.id.as_u64().unwrap()
            } else {
                panic!("Expected Request");
            };

            // Send layer.start notification
            let start_params = serde_json::json!({
                "digest": "sha256:abc123",
                "uncompressed_size": 1000
            });
            sender
                .send(make_notification("layer.start", Some(start_params), vec![]))
                .await
                .unwrap();

            // Send layer.segment notification
            let segment_data = BASE64_STANDARD.encode(b"tar header bytes");
            let segment_params = serde_json::json!({ "data": segment_data });
            sender
                .send(make_notification(
                    "layer.segment",
                    Some(segment_params),
                    vec![],
                ))
                .await
                .unwrap();

            // Send layer.file notification with fd
            let file = std::fs::File::open("/etc/hosts").unwrap();
            let fd: OwnedFd = file.into();
            // Note: fd is passed positionally via file_descriptors, not in JSON
            let file_params = serde_json::json!({
                "name": "etc/hosts",
                "size": 100,
                "mode": 0o644,
                "uid": 0,
                "gid": 0
            });
            sender
                .send(make_notification("layer.file", Some(file_params), vec![fd]))
                .await
                .unwrap();

            // Send layer.end notification
            let end_params = serde_json::json!({ "files_sent": 1 });
            sender
                .send(make_notification("layer.end", Some(end_params), vec![]))
                .await
                .unwrap();

            // Send final response
            let result = GetLayerTarSplitResult { success: true };
            let response = make_response(request_id, serde_json::to_value(result).unwrap());
            sender.send(response).await.unwrap();
        });

        // Client side
        let mut client = ProxyV2Client::connect(sock_b);
        let mut stream = client
            .get_layer_tar_split(1, "sha256:abc123")
            .await
            .unwrap();

        // Collect items
        let mut items = Vec::new();
        while let Some(item) = stream.next().await.unwrap() {
            items.push(item);
        }

        assert_eq!(items.len(), 4);

        // Check start
        if let LayerItem::Start {
            digest,
            uncompressed_size,
        } = &items[0]
        {
            assert_eq!(digest, "sha256:abc123");
            assert_eq!(*uncompressed_size, 1000);
        } else {
            panic!("Expected Start");
        }

        // Check segment
        if let LayerItem::Segment(data) = &items[1] {
            assert_eq!(data, b"tar header bytes");
        } else {
            panic!("Expected Segment");
        }

        // Check file
        if let LayerItem::File {
            name, size, mode, ..
        } = &items[2]
        {
            assert_eq!(name, "etc/hosts");
            assert_eq!(*size, 100);
            assert_eq!(*mode, 0o644);
        } else {
            panic!("Expected File");
        }

        // Check end
        if let LayerItem::End { files_sent } = &items[3] {
            assert_eq!(*files_sent, 1);
        } else {
            panic!("Expected End");
        }

        server_handle.await.unwrap();
    }
}
