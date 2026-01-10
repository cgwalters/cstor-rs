//! JSON-RPC protocol definitions for tar-split streaming with fd passing.
//!
//! This module defines the wire format for the NDJSON-RPC-FD protocol used to
//! stream tar-split metadata with file descriptor passing over Unix sockets.
//!
//! # Wire Format
//!
//! The protocol uses NDJSON (newline-delimited JSON) with file descriptors
//! passed via `SCM_RIGHTS` ancillary data. Each message is a complete JSON
//! object on a single line.
//!
//! # Message Types
//!
//! The streaming protocol uses these message types:
//! - `start`: Stream header with optional segments_fd
//! - `seg`: Segment data (raw tar header/padding bytes)
//! - `file`: File entry with fd for content
//! - `end`: Stream complete
//!
//! # Example Stream
//!
//! ```text
//! {"type":"start"}
//! {"type":"seg","data":"<base64 tar header>"}
//! {"type":"file","name":"usr/bin/bash","size":1234567,"fd":{"__jsonrpc_fd__":true,"index":0}}
//! {"type":"seg","data":"<base64 padding>"}
//! {"type":"end"}
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Re-export FileDescriptorPlaceholder from ndjson-rpc-fdpass as FdPlaceholder for compatibility
pub use ndjson_rpc_fdpass::FileDescriptorPlaceholder as FdPlaceholder;

// Re-export JSON-RPC types from the crate
pub use ndjson_rpc_fdpass::{
    JsonRpcError, JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse,
    MessageWithFds,
};

/// Stream message types for tar-split streaming.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum StreamMessage {
    /// Stream start message.
    Start {
        /// Optional fd for concatenated segment data (alternative to inline base64)
        #[serde(skip_serializing_if = "Option::is_none")]
        segments_fd: Option<FdPlaceholder>,
    },

    /// Raw segment data (tar header, padding, footer).
    ///
    /// Contains base64-encoded bytes from tar-split that must be written
    /// directly to reconstruct the tar archive bit-for-bit.
    Seg {
        /// Base64-encoded segment bytes
        data: String,
    },

    /// File entry with content fd.
    ///
    /// The client should read `size` bytes from the passed fd.
    File {
        /// File path in the tar archive
        name: String,
        /// File size in bytes
        size: u64,
        /// Content digests (algorithm -> hex digest)
        #[serde(default, skip_serializing_if = "HashMap::is_empty")]
        digests: HashMap<String, String>,
        /// File descriptor placeholder for content
        fd: FdPlaceholder,
    },

    /// Stream end marker.
    End,
}

/// Error returned when parsing a notification into a StreamMessage fails.
#[derive(Debug, Clone)]
pub struct ParseError {
    /// Description of the error
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ParseError {}

impl StreamMessage {
    /// Convert to JSON-RPC notification method name.
    pub fn method_name(&self) -> &'static str {
        match self {
            StreamMessage::Start { .. } => "stream.start",
            StreamMessage::Seg { .. } => "stream.seg",
            StreamMessage::File { .. } => "stream.file",
            StreamMessage::End => "stream.end",
        }
    }

    /// Convert to notification params (serde_json::Value).
    pub fn to_params(&self) -> serde_json::Value {
        // Serialize the full message, then extract the inner fields
        // (the "type" tag is not needed in params since method encodes it)
        match self {
            StreamMessage::Start { segments_fd } => {
                let mut map = serde_json::Map::new();
                if let Some(fd) = segments_fd {
                    map.insert("segments_fd".to_string(), serde_json::to_value(fd).unwrap());
                }
                serde_json::Value::Object(map)
            }
            StreamMessage::Seg { data } => {
                serde_json::json!({ "data": data })
            }
            StreamMessage::File {
                name,
                size,
                digests,
                fd,
            } => {
                let mut map = serde_json::Map::new();
                map.insert("name".to_string(), serde_json::Value::String(name.clone()));
                map.insert("size".to_string(), serde_json::json!(size));
                if !digests.is_empty() {
                    map.insert(
                        "digests".to_string(),
                        serde_json::to_value(digests).unwrap(),
                    );
                }
                map.insert("fd".to_string(), serde_json::to_value(fd).unwrap());
                serde_json::Value::Object(map)
            }
            StreamMessage::End => serde_json::Value::Object(serde_json::Map::new()),
        }
    }

    /// Parse from notification method and params.
    pub fn from_notification(
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<Self, ParseError> {
        let params = params.unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

        match method {
            "stream.start" => {
                let segments_fd = params
                    .get("segments_fd")
                    .map(|v| {
                        serde_json::from_value(v.clone()).map_err(|e| ParseError {
                            message: format!("invalid segments_fd: {}", e),
                        })
                    })
                    .transpose()?;
                Ok(StreamMessage::Start { segments_fd })
            }
            "stream.seg" => {
                let data = params
                    .get("data")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ParseError {
                        message: "missing 'data' field in seg message".to_string(),
                    })?
                    .to_string();
                Ok(StreamMessage::Seg { data })
            }
            "stream.file" => {
                let name = params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ParseError {
                        message: "missing 'name' field in file message".to_string(),
                    })?
                    .to_string();
                let size =
                    params
                        .get("size")
                        .and_then(|v| v.as_u64())
                        .ok_or_else(|| ParseError {
                            message: "missing or invalid 'size' field in file message".to_string(),
                        })?;
                let digests: HashMap<String, String> = params
                    .get("digests")
                    .map(|v| {
                        serde_json::from_value(v.clone()).map_err(|e| ParseError {
                            message: format!("invalid digests: {}", e),
                        })
                    })
                    .transpose()?
                    .unwrap_or_default();
                let fd = params
                    .get("fd")
                    .ok_or_else(|| ParseError {
                        message: "missing 'fd' field in file message".to_string(),
                    })
                    .and_then(|v| {
                        serde_json::from_value(v.clone()).map_err(|e| ParseError {
                            message: format!("invalid fd: {}", e),
                        })
                    })?;
                Ok(StreamMessage::File {
                    name,
                    size,
                    digests,
                    fd,
                })
            }
            "stream.end" => Ok(StreamMessage::End),
            _ => Err(ParseError {
                message: format!("unknown stream method: {}", method),
            }),
        }
    }

    /// Create a JSON-RPC notification from this message.
    pub fn to_notification(&self) -> JsonRpcNotification {
        JsonRpcNotification::new(self.method_name().to_string(), Some(self.to_params()))
    }
}

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

/// Parameters for layer.streamTarSplit method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamTarSplitParams {
    /// Layer ID (typically sha256:...)
    pub layer_id: String,
}

/// Parameters for layer.getFiles method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetFilesParams {
    /// Layer ID
    pub layer_id: String,
    /// File positions (indices from TOC)
    pub positions: Vec<usize>,
}

/// Parameters for layer.getMeta or image.getMeta method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetMetaParams {
    /// Layer or image ID
    #[serde(alias = "layer_id", alias = "image_id")]
    pub id: String,
    /// Requested digest algorithms (optional)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub digest_algorithms: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fd_placeholder_serialization() {
        let placeholder = FdPlaceholder::new(0);
        let json = serde_json::to_string(&placeholder).unwrap();
        assert_eq!(json, r#"{"__jsonrpc_fd__":true,"index":0}"#);

        let parsed: FdPlaceholder = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.index, placeholder.index);
        assert_eq!(parsed.marker, placeholder.marker);
    }

    #[test]
    fn test_stream_message_start() {
        let msg = StreamMessage::Start { segments_fd: None };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, r#"{"type":"start"}"#);
    }

    #[test]
    fn test_stream_message_file() {
        let mut digests = HashMap::new();
        digests.insert("sha256".to_string(), "abc123".to_string());

        let msg = StreamMessage::File {
            name: "usr/bin/bash".to_string(),
            size: 1234567,
            digests,
            fd: FdPlaceholder::new(0),
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"file""#));
        assert!(json.contains(r#""name":"usr/bin/bash""#));
        assert!(json.contains(r#""size":1234567"#));
        assert!(json.contains(r#""__jsonrpc_fd__":true"#));
    }

    #[test]
    fn test_stream_message_seg() {
        let msg = StreamMessage::Seg {
            data: "dXN0YXIAMDA=".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"seg""#));
        assert!(json.contains(r#""data":"dXN0YXIAMDA=""#));
    }

    #[test]
    fn test_stream_message_end() {
        let msg = StreamMessage::End;
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, r#"{"type":"end"}"#);
    }

    #[test]
    fn test_stream_message_method_names() {
        assert_eq!(
            StreamMessage::Start { segments_fd: None }.method_name(),
            "stream.start"
        );
        assert_eq!(
            StreamMessage::Seg {
                data: String::new()
            }
            .method_name(),
            "stream.seg"
        );
        assert_eq!(
            StreamMessage::File {
                name: String::new(),
                size: 0,
                digests: HashMap::new(),
                fd: FdPlaceholder::new(0),
            }
            .method_name(),
            "stream.file"
        );
        assert_eq!(StreamMessage::End.method_name(), "stream.end");
    }

    #[test]
    fn test_stream_message_to_params() {
        let msg = StreamMessage::Seg {
            data: "test".to_string(),
        };
        let params = msg.to_params();
        assert_eq!(params.get("data").unwrap().as_str().unwrap(), "test");
    }

    #[test]
    fn test_stream_message_from_notification() {
        // Test start
        let msg = StreamMessage::from_notification("stream.start", None).unwrap();
        assert!(matches!(msg, StreamMessage::Start { segments_fd: None }));

        // Test seg
        let msg = StreamMessage::from_notification(
            "stream.seg",
            Some(serde_json::json!({"data": "abc"})),
        )
        .unwrap();
        if let StreamMessage::Seg { data } = msg {
            assert_eq!(data, "abc");
        } else {
            panic!("expected Seg");
        }

        // Test file
        let msg = StreamMessage::from_notification(
            "stream.file",
            Some(serde_json::json!({
                "name": "test.txt",
                "size": 100,
                "fd": {"__jsonrpc_fd__": true, "index": 0}
            })),
        )
        .unwrap();
        if let StreamMessage::File { name, size, fd, .. } = msg {
            assert_eq!(name, "test.txt");
            assert_eq!(size, 100);
            assert_eq!(fd.index, 0);
        } else {
            panic!("expected File");
        }

        // Test end
        let msg = StreamMessage::from_notification("stream.end", None).unwrap();
        assert!(matches!(msg, StreamMessage::End));
    }

    #[test]
    fn test_stream_message_from_notification_errors() {
        // Unknown method
        let err = StreamMessage::from_notification("unknown.method", None).unwrap_err();
        assert!(err.message.contains("unknown stream method"));

        // Missing data in seg
        let err = StreamMessage::from_notification("stream.seg", None).unwrap_err();
        assert!(err.message.contains("missing 'data' field"));

        // Missing name in file
        let err = StreamMessage::from_notification(
            "stream.file",
            Some(serde_json::json!({"size": 100, "fd": {"__jsonrpc_fd__": true, "index": 0}})),
        )
        .unwrap_err();
        assert!(err.message.contains("missing 'name' field"));
    }

    #[test]
    fn test_stream_message_roundtrip() {
        let original = StreamMessage::File {
            name: "test/path".to_string(),
            size: 42,
            digests: HashMap::new(),
            fd: FdPlaceholder::new(1),
        };

        let method = original.method_name();
        let params = original.to_params();
        let parsed = StreamMessage::from_notification(method, Some(params)).unwrap();

        if let StreamMessage::File { name, size, fd, .. } = parsed {
            assert_eq!(name, "test/path");
            assert_eq!(size, 42);
            assert_eq!(fd.index, 1);
        } else {
            panic!("expected File");
        }
    }

    #[test]
    fn test_to_notification() {
        let msg = StreamMessage::Seg {
            data: "test".to_string(),
        };
        let notif = msg.to_notification();
        assert_eq!(notif.method, "stream.seg");
        assert!(notif.params.is_some());
    }
}
