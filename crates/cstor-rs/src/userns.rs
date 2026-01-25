//! User namespace handling for rootless containers-storage access.
//!
//! This module provides utilities for entering user namespaces to access
//! overlay storage files that are owned by remapped UIDs/GIDs.
//!
//! # Background
//!
//! When podman runs rootless, it uses user namespaces to remap UIDs. Files in
//! the overlay storage are owned by these remapped UIDs (e.g., UID 100000+N on
//! the host corresponds to UID N inside the container). These files also retain
//! their original permission bits from the container image.
//!
//! # Why User Namespace Entry is Needed
//!
//! Even though we use tar-split metadata to know the structure of layers, we
//! still need to **read the actual file content** to reconstruct tarballs.
//! Files with restrictive permissions (e.g., `/etc/shadow` with mode 0600) are
//! only readable by their owner - a remapped UID we cannot access as an
//! unprivileged user.
//!
//! ## When userns entry is NOT needed
//!
//! - **Running as root**: Real root (UID 0) with `CAP_DAC_OVERRIDE` can read
//!   any file regardless of permissions
//! - **Having `CAP_DAC_OVERRIDE`**: A non-root process with this capability
//!   can also bypass file permission checks
//! - **Already in the correct userns**: If we've already re-exec'd via
//!   `podman unshare`, we're UID 0 inside the namespace
//!
//! ## When userns entry IS needed
//!
//! An unprivileged user without `CAP_DAC_OVERRIDE` must enter the same user
//! namespace that podman used when extracting the image. Inside this namespace:
//!
//! - The process runs as UID 0 (root inside the namespace)
//! - The UID mappings make the "unmapped" host UIDs accessible
//! - Files can be read regardless of their permission bits
//!
//! # Options for Namespace Entry
//!
//! 1. **`podman unshare`**: Re-exec via podman's namespace setup (recommended,
//!    handles edge cases)
//! 2. **Pure Rust**: Use `unshare(2)` + `newuidmap`/`newgidmap` (requires
//!    `fork()` which needs unsafe code)
//!
//! # ID Mappings
//!
//! ID mappings are read from `/etc/subuid` and `/etc/subgid` (or via NSS).
//! The format is: `username:start:count`
//!
//! For example:
//! ```text
//! alice:100000:65536
//! ```
//!
//! This means user `alice` can use subordinate UIDs 100000-165535.
//!
//! # Example
//!
//! ```no_run
//! use cstor_rs::userns::{IdMap, read_subid_mappings};
//!
//! // Read mappings for current user
//! let (uid_maps, gid_maps) = read_subid_mappings(None)?;
//!
//! // The maps show how container IDs map to host IDs
//! for map in &uid_maps {
//!     println!("container {} -> host {} (count: {})",
//!         map.container_id, map.host_id, map.size);
//! }
//! # Ok::<(), cstor_rs::userns::UsernsError>(())
//! ```

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Command;

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use rustix::process::{getgid, getuid};
use rustix::thread::{CapabilitySet, capabilities};
use thiserror::Error;

/// Errors that can occur during user namespace operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum UsernsError {
    /// Failed to read subuid/subgid file.
    #[error("failed to read {path}: {source}")]
    ReadSubidFile {
        /// Path to the file.
        path: &'static str,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Invalid format in subuid/subgid file.
    #[error("invalid format in {path} line {line_num}: {details}")]
    InvalidFormat {
        /// Path to the file.
        path: &'static str,
        /// Line number (1-based).
        line_num: usize,
        /// Description of the format error.
        details: String,
    },

    /// No mappings found for user.
    #[error("no {kind} mappings found for user {username}")]
    NoMappings {
        /// Type of mapping (subuid or subgid).
        kind: &'static str,
        /// Username that was searched for.
        username: String,
    },

    /// Failed to get current user information.
    #[error("failed to get current user: {0}")]
    CurrentUser(String),

    /// Failed to execute newuidmap/newgidmap.
    #[error("failed to execute {binary}: {source}")]
    MapBinaryExec {
        /// Name of the binary.
        binary: &'static str,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// newuidmap/newgidmap binary not found.
    #[error("{binary} not found in PATH")]
    MapBinaryNotFound {
        /// Name of the binary.
        binary: &'static str,
    },

    /// Failed to write to proc file.
    #[error("failed to write to {path}: {source}")]
    WriteProcFile {
        /// Path to the proc file.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Namespace operation failed.
    #[error("namespace operation failed: {0}")]
    Namespace(String),

    /// Failed to read /proc/self/uid_map or gid_map.
    #[error("failed to read current ID mappings: {0}")]
    ReadCurrentMappings(#[source] std::io::Error),

    /// Failed to open /etc directory.
    #[error("failed to open /etc: {0}")]
    OpenEtc(#[source] std::io::Error),
}

/// Handle to the `/etc` directory for reading configuration files.
///
/// This allows callers to provide their own `/etc` directory handle,
/// which is useful for:
/// - Testing with mock configuration files
/// - Containerized environments with different `/etc` locations
/// - Security-conscious code that wants to avoid ambient authority
///
/// If not provided, functions will open `/etc` using ambient authority.
#[derive(Debug)]
pub struct EtcDir {
    dir: Dir,
}

impl EtcDir {
    /// Create an `EtcDir` from an existing directory handle.
    ///
    /// The directory should contain `subuid`, `subgid`, and optionally `passwd` files.
    pub fn new(dir: Dir) -> Self {
        Self { dir }
    }

    /// Open the system `/etc` directory using ambient authority.
    ///
    /// This is the default behavior when no `EtcDir` is provided.
    pub fn open_system() -> Result<Self, UsernsError> {
        let dir =
            Dir::open_ambient_dir("/etc", ambient_authority()).map_err(UsernsError::OpenEtc)?;
        Ok(Self { dir })
    }

    /// Get a reference to the underlying directory handle.
    pub fn as_dir(&self) -> &Dir {
        &self.dir
    }
}

/// Check if the current process can read arbitrary files regardless of permissions.
///
/// This returns `true` if:
/// - The process is running as real root (UID 0), or
/// - The process has `CAP_DAC_OVERRIDE` in its effective capability set
///
/// When this returns `true`, there's no need to enter a user namespace for
/// file access - the process can already read any file in the storage.
///
/// # Example
///
/// ```
/// use cstor_rs::userns::can_bypass_file_permissions;
///
/// if can_bypass_file_permissions() {
///     println!("Can read any file without userns");
/// } else {
///     println!("May need userns for files with restrictive permissions");
/// }
/// ```
pub fn can_bypass_file_permissions() -> bool {
    // Real root can read anything
    if getuid().is_root() {
        return true;
    }

    // Check for CAP_DAC_OVERRIDE capability
    if let Ok(caps) = capabilities(None) {
        if caps.effective.contains(CapabilitySet::DAC_OVERRIDE) {
            return true;
        }
    }

    false
}

/// A single ID mapping entry.
///
/// Maps a range of IDs from the container namespace to the host namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdMap {
    /// The starting ID in the container namespace
    pub container_id: u32,
    /// The starting ID in the host namespace
    pub host_id: u32,
    /// The number of IDs in this mapping
    pub size: u32,
}

impl IdMap {
    /// Create a new ID mapping.
    pub fn new(container_id: u32, host_id: u32, size: u32) -> Self {
        Self {
            container_id,
            host_id,
            size,
        }
    }

    /// Format as a string for writing to /proc/{pid}/uid_map or gid_map.
    pub fn to_proc_format(&self) -> String {
        format!("{} {} {}", self.container_id, self.host_id, self.size)
    }
}

/// A subordinate ID range from /etc/subuid or /etc/subgid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubIdRange {
    /// Starting subordinate ID
    pub start: u32,
    /// Number of IDs in range
    pub count: u32,
}

/// Which subid file type we're parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubIdFileType {
    /// /etc/subuid
    Uid,
    /// /etc/subgid
    Gid,
}

impl SubIdFileType {
    fn filename(self) -> &'static str {
        match self {
            SubIdFileType::Uid => "subuid",
            SubIdFileType::Gid => "subgid",
        }
    }

    fn error_path(self) -> &'static str {
        match self {
            SubIdFileType::Uid => "/etc/subuid",
            SubIdFileType::Gid => "/etc/subgid",
        }
    }
}

/// Parse a subuid or subgid file from an `/etc` directory handle.
///
/// Returns all ranges allocated to the user. Matches by username or numeric UID.
fn parse_subid_from_etc(
    etc_dir: &Dir,
    file_type: SubIdFileType,
    username: &str,
    uid: Option<u32>,
) -> Result<Vec<SubIdRange>, UsernsError> {
    let uid_str = uid.map(|u| u.to_string());
    let filename = file_type.filename();
    let error_path = file_type.error_path();

    let file = match etc_dir.open(filename) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // File doesn't exist - return empty (will try other sources)
            return Ok(Vec::new());
        }
        Err(e) => {
            return Err(UsernsError::ReadSubidFile {
                path: error_path,
                source: e,
            });
        }
    };

    parse_subid_reader(
        BufReader::new(file),
        error_path,
        username,
        uid_str.as_deref(),
    )
}

/// Parse /etc/subuid or /etc/subgid file for a specific user.
///
/// Returns all ranges allocated to the user. Matches by username or numeric UID.
///
/// This function opens the file at the given path using ambient authority.
/// For fd-relative access, use [`read_subid_mappings_with_etc`] with an [`EtcDir`] handle.
pub fn parse_subid_file(
    path: &Path,
    username: &str,
    uid: Option<u32>,
) -> Result<Vec<SubIdRange>, UsernsError> {
    let uid_str = uid.map(|u| u.to_string());
    let path_str = path.to_string_lossy();
    let error_path: &'static str = if path_str.contains("subuid") {
        "/etc/subuid"
    } else {
        "/etc/subgid"
    };

    // Open the file directly at the given path (for backward compatibility with tests)
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // File doesn't exist - return empty (will try other sources)
            return Ok(Vec::new());
        }
        Err(e) => {
            return Err(UsernsError::ReadSubidFile {
                path: error_path,
                source: e,
            });
        }
    };

    parse_subid_reader(
        BufReader::new(file),
        error_path,
        username,
        uid_str.as_deref(),
    )
}

/// Internal helper to parse subid content from any reader.
fn parse_subid_reader<R: BufRead>(
    reader: R,
    error_path: &'static str,
    username: &str,
    uid_str: Option<&str>,
) -> Result<Vec<SubIdRange>, UsernsError> {
    let mut ranges = Vec::new();

    for (line_num, line_result) in reader.lines().enumerate() {
        let line = line_result.map_err(|e| UsernsError::ReadSubidFile {
            path: error_path,
            source: e,
        })?;

        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() != 3 {
            return Err(UsernsError::InvalidFormat {
                path: error_path,
                line_num: line_num + 1,
                details: format!("expected 3 colon-separated fields, got {}", parts.len()),
            });
        }

        // Match by username OR by numeric UID string
        let matches = parts[0] == username || uid_str == Some(parts[0]);

        if matches {
            let start: u32 = parts[1].parse().map_err(|_| UsernsError::InvalidFormat {
                path: error_path,
                line_num: line_num + 1,
                details: format!("invalid start ID: {}", parts[1]),
            })?;

            let count: u32 = parts[2].parse().map_err(|_| UsernsError::InvalidFormat {
                path: error_path,
                line_num: line_num + 1,
                details: format!("invalid count: {}", parts[2]),
            })?;

            ranges.push(SubIdRange { start, count });
        }
    }

    Ok(ranges)
}

/// Parse the current process's ID mappings from /proc/self/uid_map or gid_map.
///
/// This is useful when already running inside a user namespace (e.g., in a container
/// or after `podman unshare`).
pub fn parse_current_id_mappings(uid: bool) -> Result<Vec<IdMap>, UsernsError> {
    let path = if uid {
        "/proc/self/uid_map"
    } else {
        "/proc/self/gid_map"
    };
    let content = std::fs::read_to_string(path).map_err(UsernsError::ReadCurrentMappings)?;

    let mut maps = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let container_id: u32 = parts[0].parse().unwrap_or(0);
            let host_id: u32 = parts[1].parse().unwrap_or(0);
            let size: u32 = parts[2].parse().unwrap_or(0);
            if size > 0 {
                maps.push(IdMap::new(container_id, host_id, size));
            }
        }
    }

    Ok(maps)
}

/// Get the current username using the provided `/etc` directory.
fn get_current_username_with_etc(etc_dir: &Dir) -> Result<String, UsernsError> {
    // Try $USER first
    if let Ok(user) = std::env::var("USER") {
        return Ok(user);
    }

    // Fall back to getpwuid via /etc/passwd parsing
    let uid = getuid().as_raw();
    let passwd = etc_dir
        .read_to_string("passwd")
        .map_err(|e| UsernsError::CurrentUser(format!("failed to read /etc/passwd: {}", e)))?;

    for line in passwd.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3
            && let Ok(entry_uid) = parts[2].parse::<u32>()
            && entry_uid == uid
        {
            return Ok(parts[0].to_string());
        }
    }

    Err(UsernsError::CurrentUser(format!(
        "no passwd entry for uid {}",
        uid
    )))
}

/// Convert subordinate ID ranges to ID mappings.
///
/// Creates mappings where:
/// - Container ID 0 maps to the user's real UID/GID (size 1)
/// - Container IDs 1+ map to the subordinate ID ranges
///
/// This matches what `podman unshare` does.
pub fn ranges_to_id_maps(ranges: &[SubIdRange], real_id: u32) -> Vec<IdMap> {
    let mut maps = Vec::with_capacity(ranges.len() + 1);

    // First mapping: container 0 -> real user ID
    maps.push(IdMap::new(0, real_id, 1));

    // Subsequent mappings: subordinate ranges
    let mut container_id = 1u32;
    for range in ranges {
        maps.push(IdMap::new(container_id, range.start, range.count));
        container_id += range.count;
    }

    maps
}

/// Read subordinate ID mappings for a user using an explicit `/etc` directory.
///
/// If `username` is None, uses the current user.
///
/// Returns (uid_maps, gid_maps).
///
/// This function tries multiple sources:
/// 1. `subuid` and `subgid` files from the provided `/etc` directory
/// 2. Current /proc/self/uid_map and gid_map (if already in a userns)
pub fn read_subid_mappings_with_etc(
    etc_dir: &EtcDir,
    username: Option<&str>,
) -> Result<(Vec<IdMap>, Vec<IdMap>), UsernsError> {
    let username = match username {
        Some(u) => u.to_string(),
        None => get_current_username_with_etc(etc_dir.as_dir())?,
    };

    let uid = getuid().as_raw();
    let gid = getgid().as_raw();

    // Try subuid and subgid from the provided etc directory
    let uid_ranges =
        parse_subid_from_etc(etc_dir.as_dir(), SubIdFileType::Uid, &username, Some(uid))?;
    let gid_ranges =
        parse_subid_from_etc(etc_dir.as_dir(), SubIdFileType::Gid, &username, Some(gid))?;

    if !uid_ranges.is_empty() && !gid_ranges.is_empty() {
        let uid_maps = ranges_to_id_maps(&uid_ranges, uid);
        let gid_maps = ranges_to_id_maps(&gid_ranges, gid);
        return Ok((uid_maps, gid_maps));
    }

    // If subuid/subgid files are empty, check if we're already in a userns
    let current_uid_maps = parse_current_id_mappings(true)?;
    let current_gid_maps = parse_current_id_mappings(false)?;

    // If we have mappings and they're not just the trivial 0:0:4294967295 mapping,
    // we're in a user namespace and can use these mappings
    if current_uid_maps.len() > 1
        || (current_uid_maps.len() == 1 && current_uid_maps[0].size < 4294967295)
    {
        return Ok((current_uid_maps, current_gid_maps));
    }

    // No mappings found
    if uid_ranges.is_empty() {
        return Err(UsernsError::NoMappings {
            kind: "subuid",
            username: username.clone(),
        });
    }
    Err(UsernsError::NoMappings {
        kind: "subgid",
        username,
    })
}

/// Read subordinate ID mappings for a user.
///
/// If `username` is None, uses the current user.
///
/// Returns (uid_maps, gid_maps).
///
/// This function tries multiple sources:
/// 1. /etc/subuid and /etc/subgid files
/// 2. Current /proc/self/uid_map and gid_map (if already in a userns)
///
/// This function opens `/etc` using ambient authority. For more control,
/// use [`read_subid_mappings_with_etc`] with an [`EtcDir`] handle.
pub fn read_subid_mappings(
    username: Option<&str>,
) -> Result<(Vec<IdMap>, Vec<IdMap>), UsernsError> {
    let etc_dir = EtcDir::open_system()?;
    read_subid_mappings_with_etc(&etc_dir, username)
}

/// Check if unprivileged user namespaces are enabled.
pub fn unprivileged_userns_enabled() -> Result<bool, UsernsError> {
    let sysctl_path = Path::new("/proc/sys/kernel/unprivileged_userns_clone");
    if !sysctl_path.exists() {
        // Sysctl doesn't exist - assume enabled (common on modern kernels)
        return Ok(true);
    }

    let content = std::fs::read_to_string(sysctl_path)
        .map_err(|e| UsernsError::Namespace(format!("failed to read sysctl: {}", e)))?;

    match content.trim() {
        "0" => Ok(false),
        "1" => Ok(true),
        other => Err(UsernsError::Namespace(format!(
            "unexpected sysctl value: {}",
            other
        ))),
    }
}

/// Look up a mapping binary (newuidmap or newgidmap) in PATH.
pub fn lookup_map_binary(name: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|p| p.join(name))
            .find(|p| p.exists())
    })
}

/// Check if we need to use newuidmap/newgidmap for the given mappings.
///
/// Returns true if there are multiple mappings (requires setuid helpers).
pub fn needs_map_binaries(uid_maps: &[IdMap], gid_maps: &[IdMap]) -> bool {
    uid_maps.len() > 1 || gid_maps.len() > 1
}

/// Write ID mappings for a process using newuidmap/newgidmap.
///
/// This is required when there are multiple mapping entries.
pub fn write_id_mappings_with_binaries(
    pid: u32,
    uid_maps: &[IdMap],
    gid_maps: &[IdMap],
) -> Result<(), UsernsError> {
    // Write setgroups deny first (required for unprivileged users)
    let setgroups_path = format!("/proc/{}/setgroups", pid);
    std::fs::write(&setgroups_path, "deny").map_err(|e| UsernsError::WriteProcFile {
        path: setgroups_path,
        source: e,
    })?;

    // Write GID mappings first (required order)
    if gid_maps.len() == 1 {
        let gid_map_path = format!("/proc/{}/gid_map", pid);
        std::fs::write(&gid_map_path, gid_maps[0].to_proc_format()).map_err(|e| {
            UsernsError::WriteProcFile {
                path: gid_map_path,
                source: e,
            }
        })?;
    } else {
        let newgidmap = lookup_map_binary("newgidmap").ok_or(UsernsError::MapBinaryNotFound {
            binary: "newgidmap",
        })?;

        let mut args = vec![pid.to_string()];
        for map in gid_maps {
            args.push(map.container_id.to_string());
            args.push(map.host_id.to_string());
            args.push(map.size.to_string());
        }

        let status = Command::new(&newgidmap).args(&args).status().map_err(|e| {
            UsernsError::MapBinaryExec {
                binary: "newgidmap",
                source: e,
            }
        })?;

        if !status.success() {
            return Err(UsernsError::Namespace(format!(
                "newgidmap failed with status: {:?}",
                status.code()
            )));
        }
    }

    // Write UID mappings
    if uid_maps.len() == 1 {
        let uid_map_path = format!("/proc/{}/uid_map", pid);
        std::fs::write(&uid_map_path, uid_maps[0].to_proc_format()).map_err(|e| {
            UsernsError::WriteProcFile {
                path: uid_map_path,
                source: e,
            }
        })?;
    } else {
        let newuidmap = lookup_map_binary("newuidmap").ok_or(UsernsError::MapBinaryNotFound {
            binary: "newuidmap",
        })?;

        let mut args = vec![pid.to_string()];
        for map in uid_maps {
            args.push(map.container_id.to_string());
            args.push(map.host_id.to_string());
            args.push(map.size.to_string());
        }

        let status = Command::new(&newuidmap).args(&args).status().map_err(|e| {
            UsernsError::MapBinaryExec {
                binary: "newuidmap",
                source: e,
            }
        })?;

        if !status.success() {
            return Err(UsernsError::Namespace(format!(
                "newuidmap failed with status: {:?}",
                status.code()
            )));
        }
    }

    Ok(())
}

/// Check if we should enter a user namespace for storage access.
///
/// This function determines whether we need to re-exec via `podman unshare`
/// to gain access to files in containers-storage that may have restrictive
/// permissions (e.g., files owned by remapped UIDs with mode 0600).
///
/// # Returns
///
/// Returns `false` (no userns entry needed) if any of these are true:
/// - Already re-exec'd into userns (env marker is set)
/// - Running as real root (UID 0)
/// - Process has `CAP_DAC_OVERRIDE` capability
///
/// Returns `true` if we're an unprivileged user and have subuid/subgid
/// mappings available for namespace entry.
///
/// # Arguments
///
/// * `env_marker` - Environment variable that indicates we've already
///   re-exec'd (e.g., "CSTOR_IN_USERNS")
///
/// # Example
///
/// ```no_run
/// use cstor_rs::userns::should_enter_userns;
///
/// const USERNS_ENV: &str = "MY_APP_IN_USERNS";
///
/// if should_enter_userns(USERNS_ENV) {
///     // Need to re-exec via podman unshare
///     cstor_rs::userns::reexec_via_podman(USERNS_ENV)?;
/// }
/// // Now we can access all files in storage
/// # Ok::<(), cstor_rs::userns::UsernsError>(())
/// ```
pub fn should_enter_userns(env_marker: &str) -> bool {
    // Already in userns from our re-exec
    if std::env::var(env_marker).is_ok() {
        return false;
    }

    // If we can already bypass file permissions (root or CAP_DAC_OVERRIDE),
    // no need for userns entry
    if can_bypass_file_permissions() {
        return false;
    }

    // Check if we have mappings available for namespace entry
    read_subid_mappings(None).is_ok()
}

/// Try to reexec via podman unshare.
///
/// This uses podman's user namespace setup which handles all the edge cases
/// around UID/GID mapping, newuidmap/newgidmap, and namespace entry.
///
/// # Arguments
///
/// * `env_marker` - Environment variable to set to prevent re-entry loops
///
/// # Returns
///
/// This function does not return on success - it replaces the current process.
/// Returns an error only if exec fails.
pub fn reexec_via_podman(env_marker: &str) -> Result<std::convert::Infallible, UsernsError> {
    use std::os::unix::process::CommandExt;

    let exe = std::fs::read_link("/proc/self/exe")
        .map_err(|e| UsernsError::Namespace(format!("failed to read /proc/self/exe: {}", e)))?;

    let args: Vec<String> = std::env::args().skip(1).collect();

    let err = Command::new("podman")
        .arg("unshare")
        .arg(&exe)
        .args(&args)
        .env(env_marker, "1")
        .exec();

    // exec only returns on error
    Err(UsernsError::Namespace(format!(
        "failed to exec podman unshare: {}",
        err
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_subid_file_basic() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "alice:100000:65536").unwrap();
        writeln!(file, "bob:200000:65536").unwrap();

        let ranges = parse_subid_file(file.path(), "alice", None).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, 100000);
        assert_eq!(ranges[0].count, 65536);
    }

    #[test]
    fn test_parse_subid_file_multiple_ranges() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "alice:100000:65536").unwrap();
        writeln!(file, "alice:200000:10000").unwrap();

        let ranges = parse_subid_file(file.path(), "alice", None).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, 100000);
        assert_eq!(ranges[1].start, 200000);
    }

    #[test]
    fn test_parse_subid_file_by_uid() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "1000:100000:65536").unwrap();

        let ranges = parse_subid_file(file.path(), "alice", Some(1000)).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, 100000);
    }

    #[test]
    fn test_parse_subid_file_comments_and_empty() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# This is a comment").unwrap();
        writeln!(file).unwrap();
        writeln!(file, "alice:100000:65536").unwrap();
        writeln!(file, "  # Another comment").unwrap();

        let ranges = parse_subid_file(file.path(), "alice", None).unwrap();
        assert_eq!(ranges.len(), 1);
    }

    #[test]
    fn test_parse_subid_file_invalid_format() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "alice:100000").unwrap(); // Missing count

        let result = parse_subid_file(file.path(), "alice", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_subid_file_not_found() {
        let ranges = parse_subid_file(Path::new("/nonexistent/subuid"), "alice", None).unwrap();
        assert!(ranges.is_empty());
    }

    #[test]
    fn test_ranges_to_id_maps() {
        let ranges = vec![SubIdRange {
            start: 100000,
            count: 65536,
        }];

        let maps = ranges_to_id_maps(&ranges, 1000);

        assert_eq!(maps.len(), 2);
        // First: container 0 -> real uid
        assert_eq!(maps[0].container_id, 0);
        assert_eq!(maps[0].host_id, 1000);
        assert_eq!(maps[0].size, 1);
        // Second: container 1+ -> subordinate range
        assert_eq!(maps[1].container_id, 1);
        assert_eq!(maps[1].host_id, 100000);
        assert_eq!(maps[1].size, 65536);
    }

    #[test]
    fn test_ranges_to_id_maps_multiple() {
        let ranges = vec![
            SubIdRange {
                start: 100000,
                count: 1000,
            },
            SubIdRange {
                start: 200000,
                count: 2000,
            },
        ];

        let maps = ranges_to_id_maps(&ranges, 1000);

        assert_eq!(maps.len(), 3);
        assert_eq!(maps[0].container_id, 0);
        assert_eq!(maps[1].container_id, 1);
        assert_eq!(maps[1].size, 1000);
        assert_eq!(maps[2].container_id, 1001); // 1 + 1000
        assert_eq!(maps[2].size, 2000);
    }

    #[test]
    fn test_id_map_to_proc_format() {
        let map = IdMap::new(0, 1000, 1);
        assert_eq!(map.to_proc_format(), "0 1000 1");

        let map = IdMap::new(1, 100000, 65536);
        assert_eq!(map.to_proc_format(), "1 100000 65536");
    }

    #[test]
    fn test_needs_map_binaries() {
        let single = vec![IdMap::new(0, 1000, 65536)];
        let multiple = vec![IdMap::new(0, 1000, 1), IdMap::new(1, 100000, 65536)];

        assert!(!needs_map_binaries(&single, &single));
        assert!(needs_map_binaries(&multiple, &single));
        assert!(needs_map_binaries(&single, &multiple));
        assert!(needs_map_binaries(&multiple, &multiple));
    }

    #[test]
    fn test_parse_current_id_mappings() {
        // This test will work differently depending on whether we're in a userns
        let result = parse_current_id_mappings(true);
        assert!(result.is_ok());
        let maps = result.unwrap();
        assert!(!maps.is_empty()); // Should always have at least one mapping
    }

    #[test]
    fn test_unprivileged_userns_enabled() {
        // Just verify it doesn't panic
        let result = unprivileged_userns_enabled();
        assert!(result.is_ok());
    }

    #[test]
    fn test_lookup_map_binary() {
        // newuidmap may or may not exist
        let result = lookup_map_binary("newuidmap");
        // Just verify it returns a path or None, doesn't panic
        if let Some(path) = result {
            assert!(path.exists());
        }
    }

    #[test]
    fn test_should_enter_userns_without_marker() {
        // When the env marker is not set and we're not root,
        // the result depends on whether mappings are available
        // Use a random marker name that won't be set
        let result = should_enter_userns("TEST_USERNS_MARKER_UNLIKELY_TO_EXIST_67890");
        // We can't assert a specific value since it depends on the environment
        // Just verify it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_can_bypass_file_permissions() {
        // This function should not panic and should return a consistent result
        let result1 = can_bypass_file_permissions();
        let result2 = can_bypass_file_permissions();
        assert_eq!(result1, result2);

        // If we're root, it should return true
        if getuid().is_root() {
            assert!(result1, "root should be able to bypass permissions");
        }
    }
}
