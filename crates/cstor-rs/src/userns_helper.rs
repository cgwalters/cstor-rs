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
//! # Usage
//!
//! Library users must call [`init_if_helper`] early in their `main()` function:
//!
//! ```no_run
//! fn main() {
//!     // This must be called before any other cstor-rs operations.
//!     // If this process was spawned as a userns helper, it will
//!     // serve requests and exit, never returning.
//!     cstor_rs::userns_helper::init_if_helper();
//!     
//!     // Normal application code continues here...
//! }
//! ```

use std::os::unix::io::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use serde::{Deserialize, Serialize};

use crate::userns::can_bypass_file_permissions;

/// Environment variable that indicates this process is a userns helper.
const HELPER_ENV: &str = "__CSTOR_USERNS_HELPER";

/// JSON-RPC method names.
#[allow(dead_code)]
mod methods {
    pub const OPEN_FILE: &str = "open_file";
    pub const SHUTDOWN: &str = "shutdown";
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
/// fn main() {
///     // Must be first!
///     cstor_rs::userns_helper::init_if_helper();
///     
///     // Rest of your application...
/// }
/// ```
pub fn init_if_helper() {
    // Check if we're a helper via environment variable
    if std::env::var(HELPER_ENV).is_err() {
        return; // Not a helper, continue normal execution
    }

    // We're a helper - stdin is our IPC socket
    // Use /dev/stdin to get a UnixStream from fd 0
    let socket = match UnixStream::connect("/proc/self/fd/0") {
        Ok(s) => s,
        Err(_) => {
            // Try alternative: the parent passed us a socket as stdin
            // We need to work with stdin directly
            // Since we can't easily convert stdin to UnixStream without unsafe,
            // let's use a different approach: read the socket path from stdin
            eprintln!("cstor-rs helper: stdin is not a connectable socket");
            std::process::exit(1);
        }
    };

    // Run the helper loop (never returns)
    run_helper_loop(socket);
}

/// Run the helper loop, serving requests from the parent.
fn run_helper_loop(_socket: UnixStream) -> ! {
    // TODO: implement the actual helper loop
    // For now, just exit - this is a skeleton
    eprintln!("cstor-rs helper: helper loop not yet implemented");
    std::process::exit(0);
}

/// Handle a JSON-RPC request.
#[allow(dead_code)]
fn handle_request(request: &jsonrpc_fdpass::JsonRpcRequest) -> (serde_json::Value, Vec<OwnedFd>) {
    match request.method.as_str() {
        methods::OPEN_FILE => {
            let params: OpenFileParams = match request
                .params
                .as_ref()
                .and_then(|p| serde_json::from_value(p.clone()).ok())
            {
                Some(p) => p,
                None => {
                    return (serde_json::json!({"error": "invalid params"}), vec![]);
                }
            };

            match std::fs::File::open(&params.path) {
                Ok(file) => {
                    let fd: OwnedFd = file.into();
                    (
                        serde_json::to_value(OpenFileResult { success: true }).unwrap(),
                        vec![fd],
                    )
                }
                Err(e) => (serde_json::json!({"error": e.to_string()}), vec![]),
            }
        }
        _ => (serde_json::json!({"error": "unknown method"}), vec![]),
    }
}

/// Proxy for accessing files via the userns helper process.
///
/// This spawns a helper process (via `podman unshare`) that runs inside a
/// user namespace and can read files with restrictive permissions. File
/// descriptors are passed back via SCM_RIGHTS.
pub struct StorageProxy {
    #[allow(dead_code)]
    child: Child,
    #[allow(dead_code)]
    socket: UnixStream,
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
    pub fn spawn() -> Result<Option<Self>, HelperError> {
        // Check if we even need a helper
        if can_bypass_file_permissions() {
            return Ok(None);
        }

        Self::spawn_helper().map(Some)
    }

    /// Spawn the helper unconditionally.
    fn spawn_helper() -> Result<Self, HelperError> {
        // Create a socket pair - one end for us, one for the child's stdin
        let (parent_sock, child_sock) = UnixStream::pair().map_err(HelperError::Socket)?;

        // Get our executable path
        let exe = std::fs::read_link("/proc/self/exe").map_err(HelperError::Io)?;

        // Spawn via podman unshare, with child_sock as the child's stdin
        let child = Command::new("podman")
            .arg("unshare")
            .arg(&exe)
            .env(HELPER_ENV, "1")
            .stdin(Stdio::from(OwnedFd::from(child_sock)))
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(HelperError::Spawn)?;

        Ok(Self {
            child,
            socket: parent_sock,
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
    pub fn open_file(&mut self, _path: impl AsRef<Path>) -> Result<OwnedFd, HelperError> {
        // TODO: implement via JSON-RPC
        Err(HelperError::Ipc("not yet implemented".to_string()))
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
        if can_bypass_file_permissions() {
            // If we can bypass, spawn should return None
            // But we can't actually test this without podman
        }
    }
}
