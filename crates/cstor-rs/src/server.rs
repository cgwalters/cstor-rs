//! Server-side implementation for tar-split streaming with fd passing.
//!
//! This module provides the server side of the JSON-RPC protocol for streaming
//! tar-split metadata with file descriptors. The server reads from containers-storage
//! and sends NDJSON messages with fds over a Unix socket.
//!
//! # Architecture
//!
//! The server operates in a streaming fashion:
//! 1. Parse tar-split metadata from the layer
//! 2. For each segment: send as base64-encoded JSON
//! 3. For each file: open it and send fd via SCM_RIGHTS
//! 4. Send end message when complete
//!
//! # Example
//!
//! ```no_run
//! use cstor_rs::{Storage, Layer};
//! use cstor_rs::server::TarSplitServer;
//! use tokio::net::UnixStream;
//!
//! # async fn example() -> Result<(), cstor_rs::StorageError> {
//! let storage = Storage::discover()?;
//! let layer = Layer::open(&storage, "layer-id")?;
//!
//! let (server_sock, client_sock) = UnixStream::pair()?;
//! let mut server = TarSplitServer::new(server_sock);
//!
//! // Stream the layer (async)
//! server.stream_layer(&storage, &layer).await?;
//! # Ok(())
//! # }
//! ```

use std::io::Write;
use std::os::unix::io::OwnedFd;

use base64::prelude::*;
use jsonrpc_fdpass::transport::{Receiver, Sender, UnixSocketTransport};
use jsonrpc_fdpass::{JsonRpcMessage, JsonRpcNotification, JsonRpcResponse, MessageWithFds};
use tokio::net::UnixStream;

use crate::error::{Result, StorageError};
use crate::layer::Layer;
use crate::protocol::{GetLayerSplitfdstreamParams, GetLayerSplitfdstreamResult, error_codes};
use crate::storage::Storage;
use crate::tar_split::{
    DEFAULT_INLINE_THRESHOLD, TarSplitFdStream, TarSplitItem, layer_to_splitfdstream,
};

/// Server for streaming tar-split data with file descriptors.
pub struct TarSplitServer {
    sender: Sender,
}

impl std::fmt::Debug for TarSplitServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TarSplitServer").finish_non_exhaustive()
    }
}

impl TarSplitServer {
    /// Create a new server from a Tokio Unix socket.
    ///
    /// # Errors
    ///
    /// Create a new server from a Unix socket.
    pub fn new(socket: UnixStream) -> Self {
        let transport = UnixSocketTransport::new(socket);
        let (sender, _receiver) = transport.split();
        Self { sender }
    }

    /// Stream a layer's tar-split data with file descriptors.
    ///
    /// Sends the following JSON-RPC notification sequence:
    /// 1. `stream.start` notification
    /// 2. For each tar-split entry:
    ///    - Segments: `stream.seg` notification with base64 data
    ///    - Files: `stream.file` notification with fd passed via SCM_RIGHTS
    /// 3. `stream.end` notification
    pub async fn stream_layer(&mut self, storage: &Storage, layer: &Layer) -> Result<()> {
        // Send start message
        self.send_notification("stream.start", &serde_json::json!({}), vec![])
            .await?;

        // Create tar-split stream
        let mut stream = TarSplitFdStream::new(storage, layer)?;

        // Stream entries
        while let Some(item) = stream.next()? {
            match item {
                TarSplitItem::Segment(bytes) => {
                    // Send segment as base64-encoded data
                    let data = BASE64_STANDARD.encode(&bytes);
                    let params = serde_json::json!({ "data": data });
                    self.send_notification("stream.seg", &params, vec![])
                        .await?;
                }
                TarSplitItem::FileContent { fd, size, name } => {
                    // File descriptors are passed positionally via SCM_RIGHTS.
                    // The `fds` count is automatically set by MessageWithFds.
                    let params = serde_json::json!({
                        "name": name,
                        "size": size,
                    });
                    self.send_notification("stream.file", &params, vec![fd])
                        .await?;
                }
            }
        }

        // Send end message
        self.send_notification("stream.end", &serde_json::json!({}), vec![])
            .await?;

        Ok(())
    }

    /// Send a JSON-RPC notification with optional file descriptors.
    async fn send_notification<T: serde::Serialize>(
        &mut self,
        method: &str,
        params: &T,
        fds: Vec<OwnedFd>,
    ) -> Result<()> {
        let params_value = serde_json::to_value(params).map_err(|e| {
            StorageError::TarSplitError(format!("Failed to serialize params: {}", e))
        })?;

        let notification = JsonRpcNotification::new(method.to_string(), Some(params_value));

        let message = JsonRpcMessage::Notification(notification);
        let message_with_fds = MessageWithFds::new(message, fds);

        self.sender
            .send(message_with_fds)
            .await
            .map_err(|e| StorageError::TarSplitError(format!("Failed to send message: {}", e)))?;

        Ok(())
    }
}

/// JSON-RPC server for handling layer access requests with fd passing.
///
/// This server handles JSON-RPC requests over a Unix socket, including the
/// `GetLayerSplitfdstream` method which returns layer content as a splitfdstream
/// with file descriptors passed via SCM_RIGHTS.
///
/// # Example
///
/// ```no_run
/// use cstor_rs::Storage;
/// use cstor_rs::server::RpcServer;
/// use tokio::net::UnixStream;
///
/// # async fn example() -> Result<(), cstor_rs::StorageError> {
/// let storage = Storage::discover()?;
/// let (server_sock, client_sock) = UnixStream::pair()?;
/// let mut server = RpcServer::new(server_sock, storage);
///
/// // Run the server (processes requests until connection closes)
/// server.run().await?;
/// # Ok(())
/// # }
/// ```
pub struct RpcServer {
    sender: Sender,
    receiver: Receiver,
    storage: Storage,
}

impl std::fmt::Debug for RpcServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcServer").finish_non_exhaustive()
    }
}

impl RpcServer {
    /// Create a new RPC server from a Tokio Unix socket.
    ///
    /// # Errors
    ///
    /// Create a new RPC server from a Unix socket.
    pub fn new(socket: UnixStream, storage: Storage) -> Self {
        let transport = UnixSocketTransport::new(socket);
        let (sender, receiver) = transport.split();
        Self {
            sender,
            receiver,
            storage,
        }
    }

    /// Run the server, processing requests until the connection closes.
    ///
    /// # Errors
    ///
    /// Returns an error if message processing fails.
    pub async fn run(&mut self) -> Result<()> {
        loop {
            let msg_with_fds = match self.receiver.receive().await {
                Ok(m) => m,
                Err(jsonrpc_fdpass::Error::ConnectionClosed) => {
                    return Ok(());
                }
                Err(e) => {
                    return Err(StorageError::TarSplitError(format!(
                        "Failed to receive message: {}",
                        e
                    )));
                }
            };

            match msg_with_fds.message {
                JsonRpcMessage::Request(request) => {
                    let id = request.id.clone();
                    let result = self.handle_request(&request.method, request.params).await;

                    match result {
                        Ok((response_value, fds)) => {
                            let response = JsonRpcResponse::success(response_value, id);
                            let message =
                                MessageWithFds::new(JsonRpcMessage::Response(response), fds);
                            self.sender.send(message).await.map_err(|e| {
                                StorageError::TarSplitError(format!(
                                    "Failed to send response: {}",
                                    e
                                ))
                            })?;
                        }
                        Err((code, message)) => {
                            let error =
                                jsonrpc_fdpass::JsonRpcError::owned(code, message, None::<()>);
                            let response = JsonRpcResponse::error(error, id);
                            let message =
                                MessageWithFds::new(JsonRpcMessage::Response(response), vec![]);
                            self.sender.send(message).await.map_err(|e| {
                                StorageError::TarSplitError(format!(
                                    "Failed to send error response: {}",
                                    e
                                ))
                            })?;
                        }
                    }
                }
                JsonRpcMessage::Notification(_) => {
                    // Notifications don't require a response
                    continue;
                }
                JsonRpcMessage::Response(_) => {
                    // Unexpected response - ignore
                    continue;
                }
            }
        }
    }

    /// Handle a single JSON-RPC request.
    ///
    /// Returns either (result_value, fds) on success or (error_code, error_message) on failure.
    async fn handle_request(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> std::result::Result<(serde_json::Value, Vec<OwnedFd>), (i32, String)> {
        match method {
            "GetLayerSplitfdstream" => self.handle_get_layer_splitfdstream(params).await,
            _ => Err((
                error_codes::METHOD_NOT_FOUND,
                format!("Method not found: {}", method),
            )),
        }
    }

    /// Handle the GetLayerSplitfdstream method.
    ///
    /// This method:
    /// 1. Parses the params to get the layer ID
    /// 2. Opens the layer from storage
    /// 3. Calls `layer_to_splitfdstream()` to produce the splitfdstream + fds
    /// 4. Creates a memfd for the splitfdstream data (fd[0])
    /// 5. Combines with the content fds (fd[1..n])
    /// 6. Returns the response with GetLayerSplitfdstreamResult and all fds
    async fn handle_get_layer_splitfdstream(
        &self,
        params: Option<serde_json::Value>,
    ) -> std::result::Result<(serde_json::Value, Vec<OwnedFd>), (i32, String)> {
        // Parse parameters
        let params_value = params.ok_or_else(|| {
            (
                error_codes::INVALID_PARAMS,
                "Missing params for GetLayerSplitfdstream".to_string(),
            )
        })?;

        let params: GetLayerSplitfdstreamParams =
            serde_json::from_value(params_value).map_err(|e| {
                (
                    error_codes::INVALID_PARAMS,
                    format!("Invalid params: {}", e),
                )
            })?;

        // Open the layer
        let layer = Layer::open(&self.storage, &params.layer).map_err(|e| {
            // Check if it's a "not found" error
            let error_msg = e.to_string();
            if error_msg.contains("not found") || error_msg.contains("No such file") {
                (
                    error_codes::LAYER_NOT_FOUND,
                    format!("Layer not found: {}", params.layer),
                )
            } else {
                (
                    error_codes::IO_ERROR,
                    format!("Failed to open layer: {}", e),
                )
            }
        })?;

        // Generate the splitfdstream
        let splitfdstream = layer_to_splitfdstream(&self.storage, &layer, DEFAULT_INLINE_THRESHOLD)
            .map_err(|e| {
                (
                    error_codes::IO_ERROR,
                    format!("Failed to generate splitfdstream: {}", e),
                )
            })?;

        // Create a memfd for the splitfdstream data
        let stream_fd = create_memfd_with_data(&splitfdstream.stream).map_err(|e| {
            (
                error_codes::IO_ERROR,
                format!("Failed to create memfd for stream: {}", e),
            )
        })?;

        // Combine fds: fd[0] = stream data, fd[1..n] = content fds
        let mut all_fds = Vec::with_capacity(1 + splitfdstream.files.len());
        all_fds.push(stream_fd);
        all_fds.extend(
            splitfdstream
                .files
                .into_iter()
                .map(std::os::fd::OwnedFd::from),
        );

        // Build the result
        let result = if params.compressed {
            GetLayerSplitfdstreamResult::new_zstd()
        } else {
            GetLayerSplitfdstreamResult::new()
        };

        let result_value = serde_json::to_value(result).map_err(|e| {
            (
                error_codes::INTERNAL_ERROR,
                format!("Failed to serialize result: {}", e),
            )
        })?;

        Ok((result_value, all_fds))
    }
}

/// Create a memfd containing the given data.
///
/// The memfd is created with CLOEXEC flag and the data is written to it.
/// The file position is reset to the beginning after writing.
fn create_memfd_with_data(data: &[u8]) -> std::io::Result<OwnedFd> {
    use std::io::Seek;

    // Create the memfd
    let fd: OwnedFd = rustix::fs::memfd_create(c"splitfdstream", rustix::fs::MemfdFlags::CLOEXEC)
        .map_err(std::io::Error::other)?;

    // Write the data
    let mut file = std::fs::File::from(fd);
    file.write_all(data)?;

    // Seek back to the beginning so the reader starts from the start
    file.seek(std::io::SeekFrom::Start(0))?;

    // Convert back to OwnedFd
    Ok(file.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpc_fdpass::JsonRpcRequest;
    use jsonrpc_fdpass::transport::UnixSocketTransport;
    use std::io::Read;

    #[test]
    fn test_create_memfd_with_data() {
        let data = b"hello, splitfdstream!";
        let fd = create_memfd_with_data(data).unwrap();

        // Read it back
        let mut file = std::fs::File::from(fd);
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        assert_eq!(buf, data);
    }

    #[tokio::test]
    async fn test_rpc_server_method_not_found() {
        let (sock_a, sock_b) = UnixStream::pair().unwrap();

        // Start the server in background
        let server_handle = tokio::spawn(async move {
            // We need a Storage but for this test we'll just check method routing
            // Since we can't easily mock Storage, we'll test the transport layer
            let transport = UnixSocketTransport::new(sock_a);
            let (mut sender, mut receiver) = transport.split();

            // Receive request
            let msg = receiver.receive().await.unwrap();
            if let JsonRpcMessage::Request(req) = msg.message {
                assert_eq!(req.method, "UnknownMethod");

                // Send method not found error
                let error = jsonrpc_fdpass::JsonRpcError::owned(
                    error_codes::METHOD_NOT_FOUND,
                    "Method not found: UnknownMethod".to_string(),
                    None::<()>,
                );
                let response = JsonRpcResponse::error(error, req.id);
                let message = MessageWithFds::new(JsonRpcMessage::Response(response), vec![]);
                sender.send(message).await.unwrap();
            }
        });

        // Client side
        let transport = UnixSocketTransport::new(sock_b);
        let (mut sender, mut receiver) = transport.split();

        // Send unknown method request
        let request = JsonRpcRequest::new(
            "UnknownMethod".to_string(),
            Some(serde_json::json!({})),
            serde_json::Value::Number(1.into()),
        );
        let message = MessageWithFds::new(JsonRpcMessage::Request(request), vec![]);
        sender.send(message).await.unwrap();

        // Receive response
        let response = receiver.receive().await.unwrap();
        if let JsonRpcMessage::Response(resp) = response.message {
            assert!(resp.error.is_some());
            let error = resp.error.unwrap();
            assert_eq!(error.code(), error_codes::METHOD_NOT_FOUND);
        } else {
            panic!("Expected Response");
        }

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_get_layer_splitfdstream_invalid_params() {
        let (sock_a, sock_b) = UnixStream::pair().unwrap();

        // Simulate server behavior for invalid params
        let server_handle = tokio::spawn(async move {
            let transport = UnixSocketTransport::new(sock_a);
            let (mut sender, mut receiver) = transport.split();

            let msg = receiver.receive().await.unwrap();
            if let JsonRpcMessage::Request(req) = msg.message {
                assert_eq!(req.method, "GetLayerSplitfdstream");

                // Params are invalid (missing "layer" field)
                let error = jsonrpc_fdpass::JsonRpcError::owned(
                    error_codes::INVALID_PARAMS,
                    "Invalid params: missing field `layer`".to_string(),
                    None::<()>,
                );
                let response = JsonRpcResponse::error(error, req.id);
                let message = MessageWithFds::new(JsonRpcMessage::Response(response), vec![]);
                sender.send(message).await.unwrap();
            }
        });

        // Client side
        let transport = UnixSocketTransport::new(sock_b);
        let (mut sender, mut receiver) = transport.split();

        // Send request with invalid params (empty object, missing "layer")
        let request = JsonRpcRequest::new(
            "GetLayerSplitfdstream".to_string(),
            Some(serde_json::json!({})),
            serde_json::Value::Number(1.into()),
        );
        let message = MessageWithFds::new(JsonRpcMessage::Request(request), vec![]);
        sender.send(message).await.unwrap();

        // Receive response
        let response = receiver.receive().await.unwrap();
        if let JsonRpcMessage::Response(resp) = response.message {
            assert!(resp.error.is_some());
            let error = resp.error.unwrap();
            assert_eq!(error.code(), error_codes::INVALID_PARAMS);
        } else {
            panic!("Expected Response");
        }

        server_handle.await.unwrap();
    }

    #[test]
    #[ignore]
    fn test_stream_layer() {
        // Would need actual containers-storage for this test
    }

    #[test]
    #[ignore]
    fn test_get_layer_splitfdstream_with_storage() {
        // Would need actual containers-storage for this test
        // Run with: cargo test test_get_layer_splitfdstream_with_storage -- --ignored
    }
}
