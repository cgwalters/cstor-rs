//! JSON-RPC protocol definitions for splitfdstream layer access.
//!
//! This module defines the wire format for the JSON-RPC with FD passing protocol
//! used to stream layer content with file descriptor passing over Unix sockets.
//!
//! # Protocol Overview
//!
//! The protocol uses JSON-RPC 2.0 with file descriptors passed via `SCM_RIGHTS`
//! ancillary data. The `fds` field in messages indicates how many file descriptors
//! accompany the message.
//!
//! # Example: GetLayerSplitfdstream
//!
//! Request:
//! ```json
//! {"jsonrpc":"2.0","method":"GetLayerSplitfdstream","params":{"layer":"sha256:..."},"id":1}
//! ```
//!
//! Response:
//! ```json
//! {"jsonrpc":"2.0","result":{"mediaType":"application/vnd.containers.splitfdstream"},"id":1,"fds":47}
//! ```
//!
//! Where fd\[0\] is the splitfdstream and fd\[1..n\] are the external file contents.

use serde::{Deserialize, Serialize};

// Re-export JSON-RPC types from the crate
pub use jsonrpc_fdpass::{
    JsonRpcError, JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse,
    MessageWithFds,
};

/// Media type for uncompressed splitfdstream.
pub const SPLITFDSTREAM_MEDIA_TYPE: &str = "application/vnd.containers.splitfdstream";

/// Media type for zstd-compressed splitfdstream.
pub const SPLITFDSTREAM_MEDIA_TYPE_ZSTD: &str = "application/vnd.containers.splitfdstream+zstd";

/// Standard JSON-RPC error codes.
pub mod error_codes {
    /// Invalid JSON was received
    pub const PARSE_ERROR: i32 = -32700;
    /// The JSON sent is not a valid Request object
    pub const INVALID_REQUEST: i32 = -32600;
    /// The method does not exist / is not available
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// Invalid method parameter(s)
    pub const INVALID_PARAMS: i32 = -32602;
    /// Internal JSON-RPC error
    pub const INTERNAL_ERROR: i32 = -32603;

    // Application-specific error codes (-32000 to -32099 reserved)
    /// Layer not found
    pub const LAYER_NOT_FOUND: i32 = -32000;
    /// Image not found
    pub const IMAGE_NOT_FOUND: i32 = -32001;
    /// File not found in layer
    pub const FILE_NOT_FOUND: i32 = -32002;
    /// IO error
    pub const IO_ERROR: i32 = -32003;
}

/// Parameters for GetLayerSplitfdstream method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetLayerSplitfdstreamParams {
    /// Layer ID (typically sha256:...)
    pub layer: String,
    /// Whether to use zstd compression for the splitfdstream
    #[serde(default)]
    pub compressed: bool,
}

/// Result for GetLayerSplitfdstream method.
///
/// The actual splitfdstream and file content fds are passed separately
/// via SCM_RIGHTS. The `fds` field in the JSON-RPC response indicates
/// the count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetLayerSplitfdstreamResult {
    /// Media type of the splitfdstream (fd\[0\])
    #[serde(rename = "mediaType")]
    pub media_type: String,
}

impl GetLayerSplitfdstreamResult {
    /// Create a new result for uncompressed splitfdstream.
    pub fn new() -> Self {
        Self {
            media_type: SPLITFDSTREAM_MEDIA_TYPE.to_string(),
        }
    }

    /// Create a new result for zstd-compressed splitfdstream.
    pub fn new_zstd() -> Self {
        Self {
            media_type: SPLITFDSTREAM_MEDIA_TYPE_ZSTD.to_string(),
        }
    }
}

impl Default for GetLayerSplitfdstreamResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Parameters for layer.getMeta method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetMetaParams {
    /// Layer or image ID
    #[serde(alias = "layer_id", alias = "image_id")]
    pub id: String,
}

// ============================================================================
// Stream Protocol Messages
// ============================================================================

/// Parameters for `stream.start` notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamStartParams {
    /// Optional file descriptor for segments (not currently used).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segments_fd: Option<u32>,
}

/// Parameters for `stream.seg` notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSegParams {
    /// Base64-encoded segment data.
    pub data: String,
}

/// Parameters for `stream.file` notification.
///
/// File descriptors are passed positionally (fd\[0\] contains the file content).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamFileParams {
    /// File path in the archive.
    pub name: String,
    /// File size in bytes.
    pub size: u64,
    /// Optional content digests (algorithm -> hex digest).
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub digests: std::collections::HashMap<String, String>,
}

/// Stream message types for the tar-split streaming protocol.
///
/// File descriptors are passed positionally with the message, not inline in the JSON.
/// The `fds` count field in the JSON-RPC message indicates how many fds accompany it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum StreamMessage {
    /// Stream start notification.
    Start {
        /// Optional segments fd (not currently used).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        segments_fd: Option<u32>,
    },
    /// Segment data (base64-encoded tar header/padding bytes).
    Seg {
        /// Base64-encoded segment data.
        data: String,
    },
    /// File entry with fd passed positionally.
    File {
        /// File path in the archive.
        name: String,
        /// File size in bytes.
        size: u64,
        /// Optional content digests.
        #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
        digests: std::collections::HashMap<String, String>,
    },
    /// Stream end notification.
    End,
}

impl StreamMessage {
    /// Parse a stream message from a notification method and params.
    ///
    /// Returns an error if the method is unknown or params are invalid.
    pub fn from_notification(
        method: &str,
        params: Option<serde_json::Value>,
    ) -> std::result::Result<Self, jsonrpc_fdpass::JsonRpcError<'static>> {
        let params = params.unwrap_or(serde_json::Value::Null);
        match method {
            "stream.start" => {
                let start: StreamStartParams = serde_json::from_value(params).map_err(|e| {
                    jsonrpc_fdpass::JsonRpcError::owned(
                        error_codes::INVALID_PARAMS,
                        format!("Invalid stream.start params: {}", e),
                        None::<()>,
                    )
                })?;
                Ok(StreamMessage::Start {
                    segments_fd: start.segments_fd,
                })
            }
            "stream.seg" => {
                let seg: StreamSegParams = serde_json::from_value(params).map_err(|e| {
                    jsonrpc_fdpass::JsonRpcError::owned(
                        error_codes::INVALID_PARAMS,
                        format!("Invalid stream.seg params: {}", e),
                        None::<()>,
                    )
                })?;
                Ok(StreamMessage::Seg { data: seg.data })
            }
            "stream.file" => {
                let file: StreamFileParams = serde_json::from_value(params).map_err(|e| {
                    jsonrpc_fdpass::JsonRpcError::owned(
                        error_codes::INVALID_PARAMS,
                        format!("Invalid stream.file params: {}", e),
                        None::<()>,
                    )
                })?;
                Ok(StreamMessage::File {
                    name: file.name,
                    size: file.size,
                    digests: file.digests,
                })
            }
            "stream.end" => Ok(StreamMessage::End),
            _ => Err(jsonrpc_fdpass::JsonRpcError::owned(
                error_codes::METHOD_NOT_FOUND,
                format!("Unknown stream method: {}", method),
                None::<()>,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_splitfdstream_result_serialization() {
        let result = GetLayerSplitfdstreamResult::new();
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains(SPLITFDSTREAM_MEDIA_TYPE));

        let result_zstd = GetLayerSplitfdstreamResult::new_zstd();
        let json_zstd = serde_json::to_string(&result_zstd).unwrap();
        assert!(json_zstd.contains(SPLITFDSTREAM_MEDIA_TYPE_ZSTD));
    }

    #[test]
    fn test_params_deserialization() {
        let json = r#"{"layer":"sha256:abc123","compressed":true}"#;
        let params: GetLayerSplitfdstreamParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.layer, "sha256:abc123");
        assert!(params.compressed);

        // Test default for compressed
        let json_no_compress = r#"{"layer":"sha256:abc123"}"#;
        let params2: GetLayerSplitfdstreamParams = serde_json::from_str(json_no_compress).unwrap();
        assert!(!params2.compressed);
    }
}
