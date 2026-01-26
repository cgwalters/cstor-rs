//! Client-side implementation for consuming tar-split streams.
//!
//! This module provides the client side of the JSON-RPC protocol for receiving
//! tar-split streams with file descriptors. The client receives NDJSON messages
//! and file descriptors from a server and can use them for tar reconstruction
//! or reflink extraction.
//!
//! # Example
//!
//! ```no_run
//! use cstor_rs::client::TarSplitClient;
//! use tokio::net::UnixStream;
//! use tokio::io::AsyncWriteExt;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let stream = UnixStream::connect("/tmp/cstor.sock").await?;
//! let mut client = TarSplitClient::new(stream);
//!
//! // Receive stream and write to tar
//! let mut tar_output = tokio::fs::File::create("layer.tar").await?;
//! client.receive_to_tar(&mut tar_output).await?;
//! # Ok(())
//! # }
//! ```

use std::io::Read;
use std::os::unix::io::OwnedFd;

use base64::prelude::*;
use jsonrpc_fdpass::transport::{Receiver, UnixSocketTransport};
use jsonrpc_fdpass::{Error as RpcError, JsonRpcMessage};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

use crate::error::{Result, StorageError};

/// Client for receiving tar-split streams with file descriptors.
pub struct TarSplitClient {
    receiver: Receiver,
}

impl std::fmt::Debug for TarSplitClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TarSplitClient").finish_non_exhaustive()
    }
}

/// Received item from the tar-split stream.
#[derive(Debug)]
pub enum ReceivedItem {
    /// Raw segment bytes to write directly to tar.
    Segment(Vec<u8>),
    /// File content with metadata and fd.
    File {
        /// File path in the archive
        name: String,
        /// File size
        size: u64,
        /// File descriptor for content
        fd: OwnedFd,
    },
    /// Stream has ended.
    End,
}

impl TarSplitClient {
    /// Create a new client from a tokio Unix socket.
    ///
    /// # Errors
    ///
    /// Create a new client from a Unix socket.
    pub fn new(socket: UnixStream) -> Self {
        let transport = UnixSocketTransport::new(socket);
        let (_sender, receiver) = transport.split();
        Self { receiver }
    }

    /// Receive the next item from the stream.
    ///
    /// Returns `None` on EOF (socket closed).
    pub async fn next_item(&mut self) -> Result<Option<ReceivedItem>> {
        let msg_with_fds = match self.receiver.receive().await {
            Ok(m) => m,
            Err(RpcError::ConnectionClosed) => return Ok(None),
            Err(e) => {
                return Err(StorageError::TarSplitError(format!(
                    "Failed to receive message: {}",
                    e
                )));
            }
        };

        let notification = match &msg_with_fds.message {
            JsonRpcMessage::Notification(n) => n,
            other => {
                return Err(StorageError::TarSplitError(format!(
                    "Expected notification, got {:?}",
                    other
                )));
            }
        };

        let mut fds = msg_with_fds.file_descriptors;
        let params = notification
            .params
            .clone()
            .unwrap_or(serde_json::Value::Null);

        match notification.method.as_str() {
            "stream.start" => {
                // Start message - continue to next item
                Box::pin(self.next_item()).await
            }
            "stream.seg" => {
                // Decode base64 segment data
                let data = params.get("data").and_then(|v| v.as_str()).ok_or_else(|| {
                    StorageError::TarSplitError("Segment missing 'data' field".to_string())
                })?;
                let bytes = BASE64_STANDARD.decode(data).map_err(|e| {
                    StorageError::TarSplitError(format!("Failed to decode segment: {}", e))
                })?;
                Ok(Some(ReceivedItem::Segment(bytes)))
            }
            "stream.file" => {
                // Parse file metadata from params
                let name = params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        StorageError::TarSplitError("File missing 'name' field".to_string())
                    })?
                    .to_string();
                let size = params.get("size").and_then(|v| v.as_u64()).ok_or_else(|| {
                    StorageError::TarSplitError("File missing 'size' field".to_string())
                })?;

                // File descriptors are passed positionally - fd[0] is the file content
                if fds.is_empty() {
                    return Err(StorageError::TarSplitError(
                        "File message received without fd".to_string(),
                    ));
                }
                // Take ownership of the first fd (positional)
                let fd = fds.remove(0);
                Ok(Some(ReceivedItem::File { name, size, fd }))
            }
            "stream.end" => Ok(Some(ReceivedItem::End)),
            other => Err(StorageError::TarSplitError(format!(
                "Unknown notification method: {}",
                other
            ))),
        }
    }

    /// Receive the entire stream and write to a tar archive.
    ///
    /// This reconstructs the tar archive bit-for-bit from the stream by writing
    /// segment data directly and copying file content from the passed fds.
    ///
    /// # Returns
    ///
    /// The number of files processed (not including segments).
    pub async fn receive_to_tar<W: AsyncWriteExt + Unpin>(
        &mut self,
        output: &mut W,
    ) -> Result<usize> {
        let mut file_count = 0;

        loop {
            match self.next_item().await? {
                Some(ReceivedItem::Segment(bytes)) => {
                    output.write_all(&bytes).await.map_err(|e| {
                        StorageError::TarSplitError(format!("Failed to write segment: {}", e))
                    })?;
                }
                Some(ReceivedItem::File { size, fd, .. }) => {
                    // Read file content from fd (sync read, then async write)
                    let mut file = std::fs::File::from(fd);
                    let mut remaining = size;
                    let mut buffer = [0u8; 8192];

                    while remaining > 0 {
                        let to_read = (remaining as usize).min(buffer.len());
                        let n = file.read(&mut buffer[..to_read]).map_err(|e| {
                            StorageError::TarSplitError(format!(
                                "Failed to read file content: {}",
                                e
                            ))
                        })?;
                        if n == 0 {
                            return Err(StorageError::TarSplitError(format!(
                                "Unexpected EOF while reading file (expected {} more bytes)",
                                remaining
                            )));
                        }
                        output.write_all(&buffer[..n]).await.map_err(|e| {
                            StorageError::TarSplitError(format!(
                                "Failed to write file content: {}",
                                e
                            ))
                        })?;
                        remaining -= n as u64;
                    }

                    file_count += 1;
                }
                Some(ReceivedItem::End) => break,
                None => break, // EOF
            }
        }

        Ok(file_count)
    }

    /// Receive stream items with a callback for each file.
    ///
    /// This allows custom handling of each file, such as reflink extraction.
    /// Segment data is discarded; only file entries invoke the callback.
    ///
    /// # Arguments
    ///
    /// * `callback` - Called for each file with `(name, size, fd)`
    ///
    /// # Returns
    ///
    /// The number of files processed.
    pub async fn receive_with_callback<F, Fut>(&mut self, mut callback: F) -> Result<usize>
    where
        F: FnMut(String, u64, OwnedFd) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        let mut file_count = 0;

        loop {
            match self.next_item().await? {
                Some(ReceivedItem::Segment(_)) => {
                    // Skip segments when not reconstructing tar
                }
                Some(ReceivedItem::File { name, size, fd }) => {
                    callback(name, size, fd).await?;
                    file_count += 1;
                }
                Some(ReceivedItem::End) => break,
                None => break,
            }
        }

        Ok(file_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpc_fdpass::transport::UnixSocketTransport;
    use jsonrpc_fdpass::{JsonRpcNotification, MessageWithFds};

    /// Helper to create a notification MessageWithFds for a StreamMessage
    fn make_notification(
        method: &str,
        params: Option<serde_json::Value>,
        fds: Vec<OwnedFd>,
    ) -> MessageWithFds {
        let notification = JsonRpcNotification::new(method.to_string(), params);
        MessageWithFds::new(JsonRpcMessage::Notification(notification), fds)
    }

    #[tokio::test]
    async fn test_receive_segment() {
        let (sock_a, sock_b) = UnixStream::pair().unwrap();

        // Set up sender
        let transport_a = UnixSocketTransport::new(sock_a);
        let (mut sender, _) = transport_a.split();

        // Set up client
        let mut client = TarSplitClient::new(sock_b);

        // Send a segment message as a notification
        let seg_params = serde_json::json!({
            "data": BASE64_STANDARD.encode(b"test data")
        });
        let msg = make_notification("stream.seg", Some(seg_params), vec![]);
        sender.send(msg).await.unwrap();

        // Receive it
        match client.next_item().await.unwrap() {
            Some(ReceivedItem::Segment(bytes)) => {
                assert_eq!(bytes, b"test data");
            }
            other => panic!("Expected Segment, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_receive_file() {
        let (sock_a, sock_b) = UnixStream::pair().unwrap();

        // Set up sender
        let transport_a = UnixSocketTransport::new(sock_a);
        let (mut sender, _) = transport_a.split();

        // Set up client
        let mut client = TarSplitClient::new(sock_b);

        // Open a test file
        let file = std::fs::File::open("/etc/hosts").unwrap();
        let file_size = file.metadata().unwrap().len();
        let owned_fd: OwnedFd = file.into();

        // Send a file message with fd (fds are passed positionally, not in JSON)
        let file_params = serde_json::json!({
            "name": "/etc/hosts",
            "size": file_size
        });
        let msg = make_notification("stream.file", Some(file_params), vec![owned_fd]);
        sender.send(msg).await.unwrap();

        // Receive it
        match client.next_item().await.unwrap() {
            Some(ReceivedItem::File { name, size, fd }) => {
                assert_eq!(name, "/etc/hosts");
                assert_eq!(size, file_size);

                // Verify we can read from the fd
                let mut received_file = std::fs::File::from(fd);
                let mut contents = String::new();
                std::io::Read::read_to_string(&mut received_file, &mut contents).unwrap();
                assert!(!contents.is_empty());
            }
            other => panic!("Expected File, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_receive_end() {
        let (sock_a, sock_b) = UnixStream::pair().unwrap();

        // Set up sender
        let transport_a = UnixSocketTransport::new(sock_a);
        let (mut sender, _) = transport_a.split();

        // Set up client
        let mut client = TarSplitClient::new(sock_b);

        // Send end message
        let msg = make_notification("stream.end", None, vec![]);
        sender.send(msg).await.unwrap();

        // Receive it
        match client.next_item().await.unwrap() {
            Some(ReceivedItem::End) => {}
            other => panic!("Expected End, got {:?}", other),
        }
    }
}
