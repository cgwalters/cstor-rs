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
//! let mut server = TarSplitServer::new(server_sock)?;
//!
//! // Stream the layer (async)
//! server.stream_layer(&storage, &layer).await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::os::unix::io::OwnedFd;

use base64::prelude::*;
use ndjson_rpc_fdpass::transport::{Sender, UnixSocketTransport};
use ndjson_rpc_fdpass::{JsonRpcMessage, JsonRpcNotification, MessageWithFds};
use tokio::net::UnixStream;

use crate::error::{Result, StorageError};
use crate::layer::Layer;
use crate::protocol::StreamMessage;
use crate::storage::Storage;
use crate::tar_split::{TarSplitFdStream, TarSplitItem};

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
    /// Returns an error if the socket cannot be converted to a transport.
    pub fn new(socket: UnixStream) -> Result<Self> {
        let transport = UnixSocketTransport::new(socket).map_err(|e| {
            StorageError::TarSplitError(format!("Failed to create transport: {}", e))
        })?;
        let (sender, _receiver) = transport.split();
        Ok(Self { sender })
    }

    /// Stream a layer's tar-split data with file descriptors.
    ///
    /// Sends the following JSON-RPC notification sequence:
    /// 1. `stream.start` notification
    /// 2. For each tar-split entry:
    ///    - Segments: `stream.seg` notification with base64 data
    ///    - Files: `stream.file` notification with fd placeholder
    /// 3. `stream.end` notification
    pub async fn stream_layer(&mut self, storage: &Storage, layer: &Layer) -> Result<()> {
        // Send start message
        let start_msg = StreamMessage::Start { segments_fd: None };
        self.send_notification("stream.start", &start_msg, vec![])
            .await?;

        // Create tar-split stream
        let mut stream = TarSplitFdStream::new(storage, layer)?;

        // Stream entries
        while let Some(item) = stream.next()? {
            match item {
                TarSplitItem::Segment(bytes) => {
                    // Send segment as base64-encoded data
                    let data = BASE64_STANDARD.encode(&bytes);
                    let msg = StreamMessage::Seg { data };
                    self.send_notification("stream.seg", &msg, vec![]).await?;
                }
                TarSplitItem::FileContent { fd, size, name } => {
                    let msg = StreamMessage::File {
                        name,
                        size,
                        digests: HashMap::new(),
                        fd: crate::protocol::FdPlaceholder::new(0),
                    };
                    self.send_notification("stream.file", &msg, vec![fd])
                        .await?;
                }
            }
        }

        // Send end message
        let end_msg = StreamMessage::End;
        self.send_notification("stream.end", &end_msg, vec![])
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

#[cfg(test)]
mod tests {
    // Integration tests would go here, but require actual storage
    #[test]
    #[ignore]
    fn test_stream_layer() {
        // Would need actual containers-storage for this test
    }
}
