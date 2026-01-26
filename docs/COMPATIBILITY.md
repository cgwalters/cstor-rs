# containers-storage Compatibility

This document describes the compatibility between cstor-rs and the Go-based [containers/storage](https://github.com/containers/storage) library used by podman, buildah, and other container tools.

## Scope

cstor-rs is designed for a **specific, limited subset** of containers-storage functionality. It is NOT a complete reimplementation and does not aim to be.

### Primary Use Case

**Read/write access to the overlay driver** for:
- Pulling OCI images from registries and storing them
- Extracting container filesystems with reflink support
- Reading image/layer metadata

### What We Support

| Feature | Read | Write | Notes |
|---------|------|-------|-------|
| **Storage Driver** | | | |
| `overlay` | ✅ | ✅ | Primary and only supported driver |
| `vfs` | ❌ | ❌ | Not supported |
| `btrfs` | ❌ | ❌ | Not supported |
| `zfs` | ❌ | ❌ | Not supported |
| `aufs` | ❌ | ❌ | Not supported |
| **Storage Layout** | | | |
| `overlay/<layer-id>/diff/` | ✅ | ✅ | Layer content |
| `overlay/<layer-id>/link` | ✅ | ✅ | Link ID file |
| `overlay/<layer-id>/lower` | ✅ | ✅ | Lower layer chain |
| `overlay/l/<link-id>` symlinks | ✅ | ✅ | Short link symlinks |
| `overlay-layers/layers.json` | ✅ | ✅ | Layer metadata |
| `overlay-layers/<id>.tar-split.gz` | ✅ | ✅ | Tar-split metadata |
| `overlay-images/images.json` | ✅ | ✅ | Image metadata |
| `overlay-images/<id>/` big data | ✅ | ✅ | Manifest, config |
| `db.sql` (SQLite) | ✅ | ❌ | Read-only queries |
| **Image Operations** | | | |
| List images | ✅ | N/A | |
| Get image manifest/config | ✅ | N/A | |
| Create image | N/A | ✅ | |
| Delete image | N/A | ✅ | |
| Tag/untag image | N/A | ✅ | |
| **Layer Operations** | | | |
| List layers | ✅ | N/A | |
| Get layer metadata | ✅ | N/A | |
| Create layer | N/A | ✅ | |
| Delete layer | N/A | ✅ | |
| Export layer as tar | ✅ | N/A | Via tar-split |
| Extract layer to directory | ✅ | N/A | With reflink support |
| **Container Operations** | | | |
| Create/manage containers | ❌ | ❌ | Out of scope |
| Mount/unmount layers | ❌ | ❌ | Out of scope |

## storage.conf Support

### Supported Options

```toml
[storage]
driver = "overlay"          # MUST be "overlay"
graphroot = "/path/..."     # Primary storage path (aliased as 'root')
runroot = "/path/..."       # Runtime directory (read, not used for writes)
```

### Partially Supported Options

```toml
[storage.options]
# Read for discovery, but NOT used for writes
additionalimagestores = ["/path/..."]   # Read-only additional stores
```

### NOT Supported Options

These options are **ignored** or will cause errors:

```toml
[storage]
driver = "vfs"              # NOT SUPPORTED - only overlay works
driver = "btrfs"            # NOT SUPPORTED
driver = "zfs"              # NOT SUPPORTED

imagestore = "/separate/path"  # NOT SUPPORTED - separate image store
transient_store = true         # NOT SUPPORTED - transient metadata

[storage.options]
# User namespace remapping
remap-uids = "..."          # NOT SUPPORTED
remap-gids = "..."          # NOT SUPPORTED
remap-user = "..."          # NOT SUPPORTED
remap-group = "..."         # NOT SUPPORTED
root-auto-userns-user = "..." # NOT SUPPORTED

# Pull optimization
pull_options = {...}        # NOT SUPPORTED
  enable_partial_images     # NOT SUPPORTED - zstd:chunked
  use_hard_links            # NOT SUPPORTED
  ostree_repos              # NOT SUPPORTED
  convert_images            # NOT SUPPORTED

# Overlay-specific
mount_program = "..."       # NOT SUPPORTED - fuse-overlayfs
force_mask = "..."          # NOT SUPPORTED
size = "..."                # NOT SUPPORTED - quota
inodes = "..."              # NOT SUPPORTED - inode limits

[storage.options.overlay]
# Any overlay-specific mount options are NOT SUPPORTED
mountopt = "..."            # NOT SUPPORTED
```

## Locking Compatibility

cstor-rs implements **fcntl-based file locking** compatible with containers/storage:

- Uses `F_SETLKW` / `F_SETLK` for blocking/non-blocking locks
- Lock files: `layers.lock`, `images.lock` in respective directories
- **LastWrite tokens**: 64-byte change detection tokens written to lock files
- Supports shared (read) and exclusive (write) locks

This means cstor-rs and podman can safely access the same storage concurrently.

## Limitations

### 1. No Container Support

cstor-rs only handles **images and layers**. It does not support:
- Creating containers
- Container metadata (`containers.json`)
- Layer mounts for running containers
- Run-time container state

### 2. No UID/GID Remapping

cstor-rs does **not** support automatic UID/GID remapping. Files are stored with their original ownership. This means:
- Running as root: files have correct ownership
- Running rootless: files are owned by the user's subuid range (handled by kernel, not us)

### 3. No Additional Image Stores for Writes

While cstor-rs can **read** from additional image stores (for layer discovery), it can only **write** to the primary graphroot.

### 4. Overlay Driver Only

Only the `overlay` storage driver is supported. VFS, btrfs native, ZFS, and AUFS are not implemented.

### 5. No Partial/Chunked Pulls

The `pull_options` for zstd:chunked partial image pulls are not supported. Images are pulled as complete layers.

## Testing Compatibility

To verify cstor-rs images work with podman:

```bash
# 1. Pull an image using cstor-rs
cstor-rs pull docker.io/library/alpine:latest

# 2. Verify podman sees it
podman images

# 3. Run a container
podman run --rm alpine echo "Hello from cstor-rs pulled image"
```

### Known Working Scenarios

- Pulling public images from Docker Hub, ghcr.io, quay.io
- Images visible in `podman images` after cstor-rs pull
- Running containers from cstor-rs pulled images
- Exporting cstor-rs images with `podman save`

### Known Limitations

- Images requiring specific pull options (zstd:chunked) may not work optimally
- Images with unusual layer formats may fail
- Rootless mode requires proper subuid/subgid configuration

## Version Compatibility

cstor-rs is developed against:

| Component | Version | Notes |
|-----------|---------|-------|
| containers/storage | v1.50+ | JSON format compatibility |
| podman | 4.x, 5.x | Tested with both |
| storage.conf | Current | TOML format |

The on-disk format is stable and backward compatible, so cstor-rs should work with older storage as well.

## Future Work

Features we may add:

- [ ] Separate imagestore support
- [ ] Additional overlay mount options
- [ ] Read-only mounts for extraction
- [ ] Container creation (for build use cases)

Features we will NOT add:

- Non-overlay drivers (use containers/storage directly)
- Full container lifecycle management (use podman/buildah)
- Windows container support
