# Container Image Operations: Reflinks and FD Passing Use Cases Analysis

This document analyzes use cases for efficient container image operations using reflinks and file descriptor passing on shared filesystems.

## Executive Summary

Container tooling currently suffers from significant inefficiency when copying images between storage locations (rootful ↔ rootless, between users, to/from VMs). The core problem: **data is serialized to tarballs and re-extracted**, even when source and destination share the same filesystem that supports reflinks (copy-on-write).

The NDJSON-RPC-FD protocol (as implemented in cstor-rs) enables a fundamentally different approach:
1. **Metadata channel**: JSON stream describing files, sizes, digests
2. **Data channel**: File descriptors passed via `SCM_RIGHTS`
3. **Zero-copy**: Client uses `FICLONE` ioctl to reflink from received fds

This enables O(metadata) operations instead of O(data) for same-filesystem copies.

---

## 1. Rootful to Rootless Podman Copy

### Current State

When copying an image from rootful (`/var/lib/containers/storage`) to rootless (`~/.local/share/containers/storage`), podman currently:

```
┌─────────────────┐     tar stream      ┌─────────────────┐
│  Rootful Store  │ ────────────────────>│  Rootless Store │
│ (root owned)    │   serialize/copy/    │ (user owned)    │
│                 │    deserialize       │                 │
└─────────────────┘                      └─────────────────┘
```

**Current workflow:**
1. `podman save` serializes image to tar archive (with compression)
2. Data is written to pipe or temp file
3. `podman load` reads and decompresses tar stream
4. Each layer is extracted and checksummed
5. tar-split metadata is regenerated

**Inefficiencies:**
- Full data copy even on same filesystem with reflink support
- CPU time for compression/decompression (typically gzip or zstd)
- Disk I/O proportional to image size (can be GBs for base images)
- Redundant checksum computation (data was already verified at pull time)
- Memory pressure for buffering compressed streams
- Locking contention (both stores locked during transfer)

**Real-world impact:**
- Copying a 1GB base image takes ~30 seconds on SSD
- With reflinks, the same operation could take <1 second

### Proposed FD-Passing Solution

```
┌─────────────────┐    NDJSON-RPC-FD     ┌─────────────────┐
│  Rootful Server │ ◄───────────────────► │    Coordinator  │
│ (runs as root)  │   metadata + O_RDONLY │  (user process) │
│                 │          fds          └────────┬────────┘
└─────────────────┘                                │
                                                   │ FICLONE ioctl
                                                   ▼
                                          ┌─────────────────┐
                                          │ Rootless Store  │
                                          │ (user owned)    │
                                          └─────────────────┘
```

**Protocol flow:**
1. User process connects to rootful storage server socket
2. Requests `image.getMeta` to get TOC with file digests
3. Creates destination files with correct UID/GID mapping
4. Requests `layer.getFiles` to receive O_RDONLY fds
5. Uses `FICLONE` ioctl to reflink content (zero-copy!)
6. Falls back to `copy_file_range()` if reflink fails

**Key insight**: The file descriptors received from the rootful server reference the actual content in `/var/lib/containers/storage/overlay/<layer>/diff/`. The kernel's reflink implementation copies the block references, not the data.

### UID/GID Mapping Challenges

This is the most complex aspect of rootful ↔ rootless copy:

**User namespace remapping:**
- Rootless containers use a user namespace with UID mapping
- Host UID 0 (in container) → User's UID (on host)
- Files in rootless storage must have remapped ownership

**How UID mapping works:**
```
# /etc/subuid: user1:100000:65536
# Container UID 0 → Host UID 100000
# Container UID 1 → Host UID 100001
# etc.
```

**Implications for fd-passing:**
1. Reflinked files keep original ownership metadata
2. Client must apply ownership *after* reflink:
   ```rust
   // Reflink the content (zero-copy)
   ioctl_ficlone(&dest_file, &src_fd)?;
   
   // Remap ownership for user namespace
   let mapped_uid = uid_map.translate(original_uid);
   let mapped_gid = gid_map.translate(original_gid);
   fchown(dest_file.as_raw_fd(), mapped_uid, mapped_gid)?;
   ```

3. SELinux labels need separate handling (reflink creates new inode, can have different xattrs)

**Protocol extension for mapping:**
```json
{
  "method": "layer.getFiles",
  "params": {
    "layer_id": "sha256:abc...",
    "positions": [0, 1, 2],
    "include_ownership": true
  }
}
```

Response includes original ownership for client-side remapping:
```json
{
  "files": [
    {
      "position": 0,
      "fd": {"__jsonrpc_fd__": true, "index": 0},
      "uid": 0,
      "gid": 0,
      "mode": 493
    }
  ]
}
```

### fsverity Trust Boundary

From [container-libs#144](https://github.com/containers/container-libs/issues/144):

> "Because fsverity is implemented in the kernel (a common shared trust domain) and enforces read-only state for content we can *efficiently* provide a file descriptor opened from a user's home directory and reflink into the rootful container storage, while knowing that:
> - There's no possibility that the user could concurrently mutate the file contents
> - We don't need to inefficiently recalculate the checksum for files"

**With fsverity enabled:**
- Kernel guarantees file immutability
- Digest can be read via `FS_IOC_MEASURE_VERITY` ioctl (no need to read content)
- Rootful server can accept fds from untrusted rootless users safely
- No re-checksumming required

**Without fsverity:**
- Server must verify content matches claimed digest
- Either re-compute checksum (slow) or trust client (insecure)
- fsverity is strongly recommended for bidirectional copy

---

## 2. Rootless to Rootless (Different Users)

### Current State

There is **no efficient mechanism** for user A to share container layers with user B. Options today:

1. **Via registry**: Push to shared registry, other user pulls
   - Requires network round-trip (even on localhost)
   - Full serialization/deserialization
   
2. **Via file export**: Save to shared location, other user loads
   - Same inefficiency as rootful copy
   - Permission challenges with tar archives

3. **Shared additional storage**: Both users read from system-wide store
   - Read-only access only
   - Doesn't help with user-built images

### Permission Requirements

For user A to share with user B:

**Read access path (A → B):**
```
User A's storage: ~/.local/share/containers/storage/
├── overlay/<layer>/diff/
│   └── <files owned by A's mapped UIDs>
```

User B needs:
- Execute permission on A's home directory path
- Read permission on storage directory tree
- Either:
  - ACLs granting B read access: `setfacl -R -m u:userB:rX ~/.local/share/containers/`
  - Group-based access with common group
  - Server process running as user A that can pass fds

### Proposed Multi-User Architecture

```
┌─────────────────┐                    ┌─────────────────┐
│  User A Server  │──────────────────> │  User B Client  │
│  (listening on  │    O_RDONLY fds    │                 │
│  socket in /tmp)│<─────────────────  │                 │
└─────────────────┘    reflink to B's  └─────────────────┘
                         storage
```

**Protocol considerations:**

1. **Authentication**: Socket access controls who can connect
   ```bash
   # User A exposes socket with group access
   cstor-rs serve --socket /tmp/user-a-storage.sock --mode 0660 --group shared-containers
   ```

2. **Authorization**: Server validates client can access requested content
   ```json
   {
     "method": "layer.getFiles",
     "params": {
       "layer_id": "sha256:abc...",
       "auth_token": "..."  // Optional, for fine-grained access
     }
   }
   ```

3. **UID translation**: B's user namespace differs from A's
   - A's files might be UID 100000-165535
   - B's namespace might use 200000-265535
   - B must remap ownership after reflink

**Systemd socket activation pattern:**
```ini
# ~/.config/systemd/user/cstor-share.socket
[Socket]
ListenStream=/run/user/%U/cstor-share.sock
SocketMode=0660
SocketGroup=container-share
```

### Alternative: Shared Object Store

A more scalable approach for multi-user scenarios:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│    User A       │     │  Shared Object  │     │     User B      │
│    Storage      │────>│      Store      │<────│     Storage     │
│                 │     │ (content-addr)  │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

- Object store keyed by content digest (SHA256 or fsverity)
- Each user's storage references shared objects
- Objects stored with world-readable permissions
- User storage contains only layer metadata and ownership info
- Similar to how composefs-rs works with a shared object store

---

## 3. Same-Host Container Builds

### Current Layer Duplication Problem

When building containers, significant duplication occurs:

```
Base image (e.g., fedora:40): 200MB
├── Build stage 1 adds packages: 50MB
├── Build stage 2 copies source: 10MB  
└── Final stage copies from stage 1

Each stage creates a full copy of the base layers!
```

**Real-world example:**
```dockerfile
# Multi-stage build
FROM fedora:40 AS builder
RUN dnf install -y gcc  # Adds 150MB

FROM fedora:40 AS runtime
COPY --from=builder /usr/bin/myapp /usr/bin/

# Result: Base image layers are stored TWICE
# (once for builder, once for runtime)
```

**Current behavior:**
- Each `FROM` pulls or references the same base layers
- Layer deduplication works within a single image only
- Build cache helps but still creates redundant layer storage
- Storage grows with O(builds × base_size)

### Layer Dedup Service

A centralized service could provide cross-build deduplication:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Buildah       │────>│  Layer Dedup    │<────│   Podman        │
│   Process       │     │    Service      │     │   Process       │
│                 │     │  (central store)│     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

**Service design:**
```json
// Register a layer (or discover existing)
{
  "method": "layer.register",
  "params": {
    "digest": "sha256:abc...",
    "diffid": "sha256:def...",  // Uncompressed content hash
    "size": 123456789
  }
}

// Response if layer already exists
{
  "result": {
    "exists": true,
    "layer_id": "sha256:abc...",
    "refcount": 5
  }
}

// Provide layer content if new
{
  "method": "layer.store",
  "params": {
    "digest": "sha256:abc...",
    "content_fd": {"__jsonrpc_fd__": true, "index": 0}
  }
}
```

**Benefits:**
- Single copy of each unique layer across all images
- O(1) storage for base layers regardless of build count
- Reflinks for instant layer reuse
- Reference counting for garbage collection

### Buildah/Podman Build Integration

Build tools could use fd-passing to the storage daemon:

**Current buildah flow:**
```
buildah → create temp layer → tar-split → store in overlay
                                    ↑
                           (file system walk + tar creation)
```

**Proposed flow:**
```
buildah → storage daemon (fd-pass each file) → reflink to store
                    ↓
        (parallel file creation, instant dedup)
```

**Write-path protocol extension:**
```json
// Start new layer
{
  "method": "layer.create",
  "params": {"parent": "sha256:base..."}
}

// Add file (fd passed via SCM_RIGHTS)
{
  "method": "layer.addFile",
  "params": {
    "handle": "temp-layer-123",
    "path": "usr/bin/myapp",
    "mode": 493,
    "uid": 0,
    "gid": 0,
    "content_fd": {"__jsonrpc_fd__": true, "index": 0}
  }
}

// Finalize layer
{
  "method": "layer.commit",
  "params": {"handle": "temp-layer-123"}
}

// Response includes generated layer ID and tar-split metadata
{
  "result": {
    "layer_id": "sha256:abc...",
    "diffid": "sha256:def..."
  }
}
```

---

## 4. Cross-Namespace Operations

### Podman Machine (VM) to Host

macOS and Windows users run containers in a Linux VM (podman machine). Sharing images between VM and host is currently slow:

```
┌─────────────────────────────────────────────────────┐
│                    Host (macOS)                      │
│  ┌───────────────┐        ┌───────────────────────┐ │
│  │ Host Tools    │  SSH   │   Podman Machine VM   │ │
│  │ (podman CLI)  │◄──────►│   (Linux guest)       │ │
│  │               │ stream │   ┌────────────────┐  │ │
│  │               │        │   │ containers-    │  │ │
│  │               │        │   │ storage        │  │ │
│  └───────────────┘        │   └────────────────┘  │ │
│                           └───────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

**Current limitations:**
- Image transfer via SSH stream (tarball)
- No reflink possible across VM boundary (different filesystems)
- Compression/decompression overhead

**Potential improvements with fd-passing:**

For **Linux** podman machine (QEMU with virtiofs):
- VM and host can share same filesystem via virtiofs
- Reflinks could work if underlying fs supports them
- Socket can be passed through virtiofs

```
Host: /var/lib/containers/storage (btrfs)
  ↓ virtiofs mount
VM: /mnt/host-storage
  ↓ reflink
VM: /var/lib/containers/storage
```

For **macOS** (with FUSE-based solutions):
- No true reflink support (APFS in VM != APFS on host)
- Protocol still helps by streaming metadata efficiently
- Data must still be copied, but checksums don't need recompute

### Container-in-Container Scenarios

Running containers inside containers (Docker-in-Docker, Podman-in-Podman):

```
┌─────────────────────────────────────────────────────┐
│                   Host                               │
│  ┌───────────────────────────────────────────────┐  │
│  │            Outer Container                     │  │
│  │  ┌───────────────────────────────────────┐    │  │
│  │  │          Inner Container               │    │  │
│  │  │   (wants to run containers)            │    │  │
│  │  └───────────────────────────────────────┘    │  │
│  │                                               │  │
│  │  /var/lib/containers/storage                  │  │
│  └───────────────────────────────────────────────┘  │
│                                                      │
│  /var/lib/containers/storage (host)                 │
└─────────────────────────────────────────────────────┘
```

**Scenarios:**
1. **Bind-mounted storage**: Outer container mounts host's storage
   - Works today but has UID mapping issues
   - fd-passing could help with ownership translation

2. **Nested storage**: Each level has independent storage
   - No sharing currently possible
   - fd-passing daemon at host level could serve to any depth

3. **Sidecar pattern**: Container A serves storage to container B
   - Socket shared via empty dir volume
   - Protocol enables efficient layer sharing

**Protocol adaptation for container scenarios:**
```json
{
  "method": "layer.getFiles",
  "params": {
    "layer_id": "sha256:abc...",
    "namespace_fd": {"__jsonrpc_fd__": true, "index": 0}  // /proc/$PID/ns/user
  }
}
```

Server can inspect the passed namespace fd to determine correct UID mapping.

### Kubernetes Node to Pod Image Sharing

Kubernetes already has image sharing via CRI, but there are inefficiencies:

```
┌─────────────────────────────────────────────────────────┐
│                   Kubernetes Node                        │
│                                                          │
│  ┌──────────────┐    ┌──────────────┐   ┌────────────┐  │
│  │  CRI Runtime │    │    Pod A     │   │   Pod B    │  │
│  │  (containerd │    │   ┌──────┐   │   │  ┌──────┐  │  │
│  │   / CRI-O)   │    │   │ ctr1 │   │   │  │ ctr1 │  │  │
│  │              │    │   └──────┘   │   │  └──────┘  │  │
│  │ image store  │    │              │   │            │  │
│  └──────────────┘    └──────────────┘   └────────────┘  │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

**Current flow for pod image access:**
- Kubelet pulls image via CRI if not cached
- Runtime unpacks layers to overlay
- Container sees unified filesystem

**Where fd-passing could help:**

1. **Init containers building images**: An init container could build an image and pass to the runtime efficiently

2. **Sidecar image loaders**: A sidecar could lazy-load image layers on demand via fd-passing

3. **Node-level image cache**: Pods could request specific files from images without full extraction:
   ```json
   {
     "method": "image.getFile",
     "params": {
       "image_ref": "registry.example.com/app:v1.0",
       "path": "/etc/app/config.yaml"
     }
   }
   ```

---

## 5. Filesystem Requirements

### Reflink-Capable Filesystems

| Filesystem | Reflink Support | Notes |
|------------|----------------|-------|
| **Btrfs** | ✅ Full | Native CoW, well-tested |
| **XFS** | ✅ With `reflink=1` | Must be enabled at mkfs time |
| **APFS** | ✅ Full | macOS native, clone() syscall |
| **bcachefs** | ✅ Full | Newer, still maturing |
| **OCFS2** | ✅ Full | Oracle cluster filesystem |
| **ext4** | ❌ None | No plans to add |
| **ZFS** | ❌ None | Uses different dedup mechanism |
| **NFS** | ⚠️ Limited | Server-side copy if supported |
| **overlayfs** | ⚠️ Passthrough | Uses underlying fs capability |

**Checking reflink support:**
```bash
# Check filesystem type
df -T /var/lib/containers/storage

# For XFS, check reflink feature
xfs_info /var/lib/containers/storage | grep reflink

# Test reflink capability
cp --reflink=always testfile testfile.copy
```

### FICLONE ioctl Details

The kernel's `FICLONE` ioctl performs the reflink:

```c
#include <linux/fs.h>
#include <sys/ioctl.h>

int ficlone(int dest_fd, int src_fd) {
    return ioctl(dest_fd, FICLONE, src_fd);
}
```

**Requirements:**
- Both fds must be on the same filesystem
- Destination file must be empty or truncated
- Source must be a regular file
- User must have read permission on source

**Rust implementation:**
```rust
use std::os::unix::io::AsRawFd;

const FICLONE: libc::c_ulong = 0x40049409;

pub fn ficlone(dest: &std::fs::File, src: &std::fs::File) -> std::io::Result<()> {
    let ret = unsafe {
        libc::ioctl(dest.as_raw_fd(), FICLONE, src.as_raw_fd())
    };
    if ret == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
```

### Fallback Strategy

When reflinks aren't available, the protocol should degrade gracefully:

```rust
fn copy_file_content(src_fd: &File, dest_fd: &File, size: u64) -> io::Result<()> {
    // Try reflink first (zero-copy, O(1))
    match ficlone(dest_fd, src_fd) {
        Ok(()) => return Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => {
            // Filesystem doesn't support reflinks
        }
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            // Cross-filesystem (shouldn't happen with proper checks)
        }
        Err(e) => return Err(e),
    }
    
    // Fallback: copy_file_range (kernel-space copy, efficient)
    match copy_file_range(src_fd, dest_fd, size) {
        Ok(()) => return Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {
            // Old kernel without copy_file_range
        }
        Err(e) => return Err(e),
    }
    
    // Final fallback: userspace copy (slowest)
    let mut src = BufReader::new(src_fd);
    let mut dest = BufWriter::new(dest_fd);
    io::copy(&mut src, &mut dest)?;
    Ok(())
}
```

**Performance comparison:**
| Method | Time for 1GB file | Memory Usage |
|--------|------------------|--------------|
| Reflink | <1ms | O(1) |
| copy_file_range | ~2s | O(1) kernel buffers |
| Userspace copy | ~5s | O(buffer_size) |

### Copy-on-Write Semantics

**Key property**: Reflinked files share physical blocks until one is modified.

**Implications for container storage:**
1. **Immutability is key**: Layer content should never be modified
2. **Running containers**: Container rootfs modifications go to overlay upper dir, not the reflinked base
3. **fsverity guarantee**: With fsverity enabled, kernel prevents modification
4. **Block-level sharing**: Even partial file modifications only copy affected blocks

**Diagram:**
```
Initial state:
File A (layer) ──┐
                 ├──► Physical blocks [1,2,3,4]
File B (copy)  ──┘

After modifying block 2 in File B:
File A (layer) ──────► Physical blocks [1,2,3,4]
File B (copy)  ──────► Physical blocks [1,2',3,4]
                         (only block 2 copied)
```

---

## Summary: Protocol-Enabled Improvements

| Use Case | Current | With NDJSON-RPC-FD |
|----------|---------|-------------------|
| Rootful→rootless | Full tar copy | O(metadata) reflink |
| User A→User B | Via registry | Direct fd-passing |
| Build dedup | Per-image only | Cross-build sharing |
| VM↔Host | SSH stream | virtiofs + reflink |
| Container-in-container | Nested copies | Socket-based sharing |
| K8s node→pod | CRI unpack | On-demand file access |

**Key enablers:**
1. **NDJSON-RPC-FD protocol**: Metadata + fd passing over Unix socket
2. **Reflink filesystems**: Zero-copy data sharing
3. **fsverity**: Trust without re-checksumming
4. **UID mapping awareness**: Correct ownership translation

**Next steps for cstor-rs:**
1. Implement server mode with Unix socket listener
2. Add reflink copy support to client operations
3. Integrate with podman for proof-of-concept rootful↔rootless copy
4. Propose protocol standardization for containers-storage ecosystem
