# Tar-Split Streaming with File Descriptor Passing

## Problem Statement

Container tooling currently relies heavily on serializing and deserializing tar streams when copying between containers-storage instances or exporting image content. This approach has several significant problems:

1. **Memory/disk pressure**: Temporary tarballs require storage proportional to layer size
2. **No reflink support**: Data must be copied byte-by-byte, even when source and destination share a filesystem
3. **Serialization overhead**: CPU time spent compressing/decompressing, checksumming redundantly
4. **Locking contention**: Long-running tar operations hold locks, blocking concurrent operations
5. **User namespace complexity**: Crossing privilege boundaries requires careful coordination

The fundamental insight is that **metadata and data should be separate channels**. This is already the direction of zstd:chunked, eStargz, and composefs's splitstream format. This proposal extends tar-split over IPC with file descriptor passing.

## Related Work

### composefs-rs Splitstream

The [splitstream format](https://github.com/containers/composefs-rs/blob/main/doc/splitstream.md) from composefs-rs provides a binary format for storing file formats (like tar) with data blocks stored separately in a content-addressed object store. Key properties:

- Binary format with zstd-compressed inline metadata
- External references via fs-verity digests to objects in the composefs store
- Bit-for-bit reconstruction of original files
- Named references for cross-document links (OCI manifests, configs, layers)

### tar-split

This library already uses [tar-split](https://github.com/vbatts/tar-split) metadata (NDJSON format, gzip compressed) to reconstruct tar archives. The current approach:

- Parse tar-split entries (Type 1: file references, Type 2: raw segment bytes)
- Return `TarSplitItem::Segment(Vec<u8>)` for headers/padding
- Return `TarSplitItem::FileContent(OwnedFd, u64)` for file data

This already demonstrates the core concept: **metadata + file descriptor references**.

### containers/container-libs Issues

- [Issue #144](https://github.com/containers/container-libs/issues/144): Fork into two processes / efficient layer access
  - Proposes passing readonly file descriptors instead of tarballs
  - Would enable reflinks between privileged/unprivileged storage
  - fsverity provides trust guarantees without re-checksumming

- [Issue #98](https://github.com/containers/container-libs/issues/98): Object store socket API
  - Proposes a socket-based API for accessing underlying files
  - Would work like `skopeo experimental-image-proxy` but for raw objects
  - Speaks a protocol over fd 0 by default

### skopeo experimental-image-proxy

The [skopeo experimental-image-proxy](https://github.com/containers/skopeo/blob/main/docs-experimental/skopeo-experimental-image-proxy.1.md) is the closest existing prior art. It provides:

**Protocol Design:**
- Uses `SOCK_SEQPACKET` (one JSON message per packet)
- Custom JSON protocol (not JSON-RPC): `{"method": "MethodName", "args": [...]}`
- Replies: `{"success": bool, "value": ..., "pipeid": N, "error": "..."}`
- Large data (manifests, blobs) transferred via separate pipes with fd passing
- `FinishPipe` method for signaling completion and error checking

**Key Methods:**
- `Initialize` - Returns protocol version (currently 0.2.8)
- `OpenImage` / `OpenImageOptional` - Open image by reference, returns opaque ID
- `CloseImage` - Release resources
- `GetManifest` - Manifest via pipe, returns digest
- `GetFullConfig` - OCI config via pipe
- `GetBlob` - Blob by digest+size via pipe, with digest verification
- `GetRawBlob` - Blob without verification, returns data fd + error fd
- `GetLayerInfoPiped` - Layer info as JSON array via pipe
- `FinishPipe` - Signal pipe consumption complete, get deferred errors

**Limitations for our use case:**
- Designed for **registry access**, not local storage access
- Operates at **blob level** (whole compressed layers), not file level
- No file-granularity access (can't request `/etc/passwd` from a layer)
- No tar-split awareness (can't do bit-for-bit reconstruction efficiently)
- No reflink path (data still copied through pipes)
- Uses `SOCK_SEQPACKET` (not available on macOS)

**What we can learn:**
- Proven pattern: metadata channel + fd passing for data
- Handle/ID pattern for stateful sessions (`OpenImage` returns ID)
- Separate error channel for streaming operations (`GetRawBlob`)
- Protocol versioning from the start
- Reference client library: [containers-image-proxy-rs](https://github.com/containers/containers-image-proxy-rs)

The proposed protocol extends this pattern to **file-granular access** with tar-split awareness.

## Proposed Solution: NDJSON-RPC-FD Protocol

The [spec-json-rpc-fdpass](https://github.com/cgwalters/spec-json-rpc-fdpass) specification defines a portable IPC mechanism that combines JSON-RPC 2.0 with file descriptor passing over Unix domain sockets.

Key properties:

- Uses SOCK_STREAM with NDJSON framing
- Each `sendmsg()` contains exactly one NDJSON message
- File descriptors passed via `SCM_RIGHTS` ancillary data
- Placeholder objects (`{"__jsonrpc_fd__": true, "index": N}`) mark FD positions
- Portable to macOS (unlike SOCK_SEQPACKET)

### Why JSON-RPC?

- Already widely used (LSP, MCP)
- Human-readable for debugging
- Extensible request/response model
- Bidirectional communication
- Well-defined error handling

## Proposed API Design

### Service Model

A **storage server** process holds the containers-storage instance open and serves requests via Unix socket. Clients connect and request metadata + file descriptors.

```
┌─────────────────┐                    ┌─────────────────┐
│     Client      │                    │  Storage Server │
│  (podman copy,  │◄──Unix Socket──────│  (cstor-rs or   │
│   bootc, etc.)  │   NDJSON-RPC-FD    │   c/storage)    │
└─────────────────┘                    └─────────────────┘
```

### Core Concept: Tar-Split with FD Passing

The fundamental insight is that tar-split already separates metadata from data. The protocol extends this by replacing "read file at path X" with "here's an fd for file X".

**Two primary use cases with different needs:**

1. **Tar reconstruction** (push to registry, copy-to-oci): Need tar-split metadata for bit-for-bit reconstruction
2. **File extraction** (bootc install, reflink copy): Need file metadata (TOC) + file content

Both share the pattern: **metadata stream + file descriptor references**.

### Tar-Split Stream Structure

The protocol's core operation is streaming tar-split metadata with inline fd references:

```
┌─────────────────────────────────────────────────────────────┐
│                    Tar-Split over IPC                        │
├──────────────┬──────────────┬──────────────┬────────────────┤
│  Inline data │   FD ref     │  Inline data │    FD ref      │
│ (tar header) │ (file content)│  (padding)  │ (file content) │
└──────────────┴──────────────┴──────────────┴────────────────┘
```

Each "FD ref" in the stream is accompanied by an actual file descriptor passed via `SCM_RIGHTS`.

### Wire Format: Extended Tar-Split NDJSON

The tar format itself lacks important metadata (checksums, fsverity digests). Rather than inventing a new format, we extend the existing tar-split NDJSON with additional fields.

**Problem: Segment data is bulky**

Standard tar-split embeds raw bytes as base64 in JSON:
```json
{"type":2,"payload":"AAAAAAAAAAAAAAAAAAAAAA..."}  // 512+ bytes of mostly zeros
```

Tar headers are 512 bytes each, mostly zero padding. Base64 adds 33% overhead. For a layer with thousands of files, this is wasteful.

**Solution: Separate segment stream**

Pass segment data via a dedicated fd, with JSON containing only lengths:

```json
{"type":"start","segments_fd":{"__jsonrpc_fd__":true,"index":0}}
{"type":"seg","len":512}
{"type":"file","name":"usr/bin/bash","size":1234567,"digests":{"sha256":"..."},"fd":{"__jsonrpc_fd__":true,"index":1}}
{"type":"seg","len":512}
{"type":"file","name":"etc/passwd","size":1234,"digests":{"sha256":"..."},"fd":{"__jsonrpc_fd__":true,"index":2}}
{"type":"seg","len":1024}
{"type":"end"}
```

**Stream structure:**

1. First message passes `segments_fd` - a pipe/memfd containing all segment data concatenated
2. `seg` messages specify how many bytes to read from `segments_fd`
3. `file` messages include the file's fd for content
4. Client interleaves: read segment bytes, then file content, repeat

**Benefits:**

- JSON stays small (just lengths and metadata)
- Segment data can be compressed in the pipe (zstd stream)
- No base64 overhead
- Server can write segments ahead while client processes

**Message types:**

| Type | Fields | Description |
|------|--------|-------------|
| `start` | `segments_fd` | Stream header with segment data fd |
| `seg` | `len` | Read `len` bytes from segments_fd |
| `file` | `name`, `size`, `digests`, `fd` | File content via passed fd |
| `end` | - | Stream complete |

**Extended fields for file entries:**

| Field | Purpose |
|-------|---------|
| `digests` | Map of algorithm → content digest (fills gap in tar format) |
| `fd` | File descriptor for content |

**Why extend tar-split rather than invent new format?**

- containers-storage already generates tar-split
- We're just changing the serialization for IPC, not the data model
- Digests computed once at import time, stored alongside tar-split
- Server enriches entries when streaming over IPC

### Digest Sources

The `digests` field addresses a fundamental limitation of tar: no per-file checksums. Where do these digests come from?

**Option 1: Computed at layer import (preferred)**

When podman/buildah imports a layer, compute and store digests alongside tar-split:
- Store in a sidecar file (e.g., `layer.digests.json`) or extend tar-split storage
- One-time cost at import
- Available immediately for all subsequent operations

**Option 2: Computed on-demand by server**

Server reads each file and computes digests when client requests:
- No storage overhead
- Slower first access (must read all file content)
- Could cache results

**Option 3: From source metadata (zstd:chunked, eStargz)**

If the layer was fetched with chunk-level digests:
- zstd:chunked TOC contains per-file digests
- eStargz TOC contains `chunkDigest` fields
- Preserve this metadata at import time

**Recommendation**: Option 1 for new layers, Option 3 when available from source. Option 2 as fallback.

**fsverity digests:**

If files have fsverity enabled, the digest can be read from the kernel via `FS_IOC_MEASURE_VERITY` ioctl - no need to read file content.

### TOC Format (eStargz-inspired, extended)

For clients that need file-level metadata without tar reconstruction (e.g., reflink extraction), provide a TOC:

```json
{
  "version": 1,
  "entries": [
    {
      "name": "usr/bin/bash",
      "type": "reg",
      "size": 1234567,
      "mode": 493,
      "uid": 0,
      "gid": 0,
      "modtime": "2024-01-15T10:30:00Z",
      "position": 0,
      "digests": {
        "sha256": "abc123...",
        "fsverity-sha512": "def456..."
      }
    },
    {
      "name": "etc/passwd",
      "type": "reg",
      "size": 1234,
      "mode": 420,
      "uid": 0,
      "gid": 0,
      "position": 1,
      "digests": {
        "sha256": "...",
        "fsverity-sha512": "..."
      }
    },
    {
      "name": "usr/lib",
      "type": "dir",
      "mode": 493,
      "uid": 0,
      "gid": 0
    },
    {
      "name": "bin/sh",
      "type": "hardlink",
      "linkName": "usr/bin/bash"
    }
  ]
}
```

**Key fields:**

| Field | Purpose |
|-------|---------|
| `position` | Index into the fd array returned by `layer.getFiles` |
| `digests` | Map of algorithm → digest (sha256, fsverity-sha512, etc.) |

The `position` field correlates TOC entries to file descriptors returned in batch operations.

**Why `digests` (plural)?**

- Classic OCI uses sha256 for content addressing
- composefs-rs uses fsverity-sha512 for kernel-verified content
- Server can advertise what it has available
- Client can verify with preferred algorithm
- Enables future algorithm transitions

### Core Methods

#### `layer.streamTarSplit` (Primary Method)

Stream the layer as tar-split with file descriptors. This is the **core operation** for tar reconstruction.

```json
{
  "jsonrpc": "2.0",
  "method": "layer.streamTarSplit",
  "params": {"layer_id": "sha256:abc123..."},
  "id": 1
}
```

Response is a streaming sequence of NDJSON messages with fds:

```json
{"type":"start","segments_fd":{"__jsonrpc_fd__":true,"index":0}}
{"type":"seg","len":512}
{"type":"file","name":"usr/bin/bash","size":1234567,"digests":{"sha256":"e3b0c44..."},"fd":{"__jsonrpc_fd__":true,"index":1}}
{"type":"seg","len":512}
{"type":"file","name":"etc/passwd","size":1234,"digests":{"sha256":"..."},"fd":{"__jsonrpc_fd__":true,"index":2}}
{"type":"seg","len":1024}
{"type":"end"}
```

**Message types:**

| Type | Fields | FD? |
|------|--------|-----|
| `start` | `segments_fd` | Yes - pipe/memfd with all segment data |
| `seg` | `len` | No - read `len` bytes from segments_fd |
| `file` | `name`, `size`, `digests`, `fd` | Yes - O_RDONLY fd for file content |
| `end` | - | No |

**Client reconstructs tar by:**
1. Receive `start`, save `segments_fd`
2. For each `seg`: read `len` bytes from `segments_fd`, write to tar
3. For each `file`: read `size` bytes from `fd`, write to tar
4. Optionally verify content against `digests`
5. Continue until `end`

**Benefits of separate segments_fd:**
- No base64 overhead (raw bytes in pipe)
- Segment data can be zstd-compressed in the pipe
- JSON messages stay small (just lengths and metadata)
- Server can buffer-ahead while client processes files

#### `layer.getMeta`

Get TOC for a layer (for clients that don't need tar reconstruction).

```json
{
  "jsonrpc": "2.0",
  "method": "layer.getMeta",
  "params": {"layer_id": "sha256:abc123..."},
  "id": 2
}
```

Response includes fd for TOC JSON:
```json
{
  "jsonrpc": "2.0",
  "result": {
    "toc": {"__jsonrpc_fd__": true, "index": 0},
    "entry_count": 1234,
    "total_size": 567890123
  },
  "id": 2
}
```

The TOC is passed as a file descriptor (pipe or memfd) rather than inline JSON because:
- TOCs can be large (thousands of entries)
- Avoids JSON-in-JSON escaping issues
- Client can mmap if using memfd

#### `layer.getFiles`

Request O_RDONLY file descriptors for specific files by position (from TOC).

```json
{
  "jsonrpc": "2.0",
  "method": "layer.getFiles",
  "params": {
    "layer_id": "sha256:abc123...",
    "positions": [0, 1, 2, 3]
  },
  "id": 3
}
```

Response includes file descriptors in position order:
```json
{
  "jsonrpc": "2.0",
  "result": {
    "files": [
      {"position": 0, "fd": {"__jsonrpc_fd__": true, "index": 0}},
      {"position": 1, "fd": {"__jsonrpc_fd__": true, "index": 1}},
      {"position": 2, "fd": {"__jsonrpc_fd__": true, "index": 2}},
      {"position": 3, "fd": {"__jsonrpc_fd__": true, "index": 3}}
    ]
  },
  "id": 3
}
```

**Design notes:**
- Batch request: multiple positions in one call reduces round trips
- Returns fds in request order for easy correlation
- Server opens files O_RDONLY, client can reflink or read
- File descriptors are to the actual overlay diff files (not through overlay mount)

#### `image.getMeta`

Get merged TOC for an image (all layers, whiteouts processed).

```json
{
  "jsonrpc": "2.0",
  "method": "image.getMeta",
  "params": {"image_id": "sha256:def456..."},
  "id": 4
}
```

Response includes fd for merged TOC, plus layer mapping:
```json
{
  "jsonrpc": "2.0",
  "result": {
    "toc": {"__jsonrpc_fd__": true, "index": 0},
    "layers": ["sha256:layer1...", "sha256:layer2...", "sha256:layer3..."]
  },
  "id": 4
}
```

The merged TOC entries include a `layer` field indicating which layer provides each file, enabling targeted `layer.getFiles` calls.

### Example: Tar Reconstruction (Primary Use Case)

```rust
// Stream layer as splitstream, reconstruct tar
let mut tar_output = File::create("layer.tar")?;

// Start streaming - server sends NDJSON messages with fds
client.call("layer.streamTarSplit", json!({"layer_id": layer_id}))?;

// Process stream messages
loop {
    let (msg, fds) = client.recv_message()?;
    
    match msg["type"].as_str() {
        Some("segment") => {
            // Raw tar bytes (header, padding, trailer) - write directly
            let data = base64::decode(msg["data"].as_str().unwrap())?;
            tar_output.write_all(&data)?;
        }
        Some("file") => {
            // File content - read from passed fd
            let fd = fds[msg["fd"]["index"].as_u64().unwrap() as usize];
            let size = msg["size"].as_u64().unwrap();
            copy_fd_to_writer(&fd, size, &mut tar_output)?;
        }
        Some("end") => break,
        _ => return Err(anyhow!("Unknown message type")),
    }
}

// tar_output now contains bit-for-bit identical tarball
```

### Example: Reflink Image Extraction

```rust
// 1. Get merged TOC for image
let resp = client.call("image.getMeta", json!({"image_id": image_id}))?;
let toc: Toc = read_fd_as_json(resp.result["toc"])?;

// 2. Group files by source layer
let mut by_layer: HashMap<String, Vec<(usize, PathBuf)>> = HashMap::new();
for entry in &toc.entries {
    if entry.entry_type == "reg" {
        by_layer.entry(entry.layer.clone())
            .or_default()
            .push((entry.position, entry.name.clone()));
    }
}

// 3. For each layer, batch-fetch file descriptors
for (layer_id, files) in by_layer {
    let positions: Vec<usize> = files.iter().map(|(p, _)| *p).collect();
    
    // Batch request - one round trip per layer
    let resp = client.call("layer.getFiles", json!({
        "layer_id": layer_id,
        "positions": positions
    }))?;
    
    // 4. Reflink each file to destination
    for (file_info, (_, dest_path)) in resp.result["files"].iter().zip(files.iter()) {
        let dest_file = dest_dir.create(dest_path)?;
        let src_fd = get_fd_from_response(file_info)?;
        ioctl_ficlone(&dest_file, &src_fd)?;  // Zero-copy!
    }
}
```

### Example: Push to Registry

```rust
// For pushing, we need the compressed layer blob with correct digest
let mut hasher = Sha256::new();
let mut compressed = GzEncoder::new(Vec::new(), Compression::default());

// Stream layer, compress on the fly
client.call("layer.streamTarSplit", json!({"layer_id": layer_id}))?;

loop {
    let (msg, fds) = client.recv_message()?;
    
    match msg["type"].as_str() {
        Some("segment") => {
            let data = base64::decode(msg["data"].as_str().unwrap())?;
            compressed.write_all(&data)?;
        }
        Some("file") => {
            let fd = fds[msg["fd"]["index"].as_u64().unwrap() as usize];
            let size = msg["size"].as_u64().unwrap();
            copy_fd_to_writer(&fd, size, &mut compressed)?;
        }
        Some("end") => break,
        _ => continue,
    }
}

let blob = compressed.finish()?;
hasher.update(&blob);
let digest = format!("sha256:{:x}", hasher.finalize());

// Push blob to registry
registry.push_blob(&digest, &blob)?;
```

## Digest Strategy

The `digests` field supports multiple content-addressing algorithms:

```json
"digests": {
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "fsverity-sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce..."
}
```

### Why Multiple Digests?

| Algorithm | Use Case |
|-----------|----------|
| `sha256` | OCI content addressing, registry interaction |
| `fsverity-sha256` | Kernel-enforced integrity (4K block Merkle tree) |
| `fsverity-sha512` | composefs-rs native format |

**Key insight from container-libs#144:**
> "Because fsverity is implemented in the kernel (a common shared trust domain) and enforces read-only state for content we can *efficiently* provide a file descriptor opened from a user's home directory and reflink into the rootful container storage, while knowing that:
> - There's no possibility that the user could concurrently mutate the file contents
> - We don't need to inefficiently recalculate the checksum for files"

With fsverity:
- Server can trust files from untrusted sources (user's home dir)
- No need to re-checksum on copy
- Kernel guarantees immutability

### Digest Negotiation

Client can request preferred algorithms:

```json
{
  "jsonrpc": "2.0",
  "method": "layer.getMeta",
  "params": {
    "layer_id": "sha256:abc123...",
    "digest_algorithms": ["fsverity-sha512", "sha256"]
  },
  "id": 1
}
```

Server includes only requested algorithms (in preference order) that it can provide.

## Use Cases

### 1. Cross-Storage Copy with Reflinks

Copy image from rootful to rootless storage (or vice versa):

```
┌─────────────────┐              ┌─────────────────┐
│  Rootful Server │──getInodes──>│     Client      │
│  (privileged)   │<──O_RDONLY───│  (coordinator)  │
└─────────────────┘      fds     └────────┬────────┘
                                          │ reflink
                                          ▼
                                 ┌─────────────────┐
                                 │ Rootless Storage│
                                 │ (user namespace)│
                                 └─────────────────┘
```

Flow:
1. Client calls `image.getMeta` on rootful server
2. Client creates files in rootless storage with correct UID mapping
3. Client calls `layer.getInodes` to get fds from rootful server
4. Client uses `FICLONE` to reflink content (zero-copy!)
5. Falls back to `copy_file_range()` if reflink unsupported

**Result**: Same content, different ownership, no data copying on CoW filesystems.

### 2. bootc Image Installation

Install a bootc image from containers-storage to a disk:

```
┌─────────────────┐              ┌─────────────────┐
│ c/storage Server│──getInodes──>│     bootc       │
│                 │<──O_RDONLY───│                 │
└─────────────────┘      fds     └────────┬────────┘
                                          │ reflink + relabel
                                          ▼
                                 ┌─────────────────┐
                                 │  Target rootfs  │
                                 │ (SELinux labels)│
                                 └─────────────────┘
```

Key benefits:
- No temporary tarballs (memory/disk savings)
- Parallel file extraction across layers
- **Different SELinux labels on destination** (reflink creates new inode, can have different xattrs)
- fsverity digests enable trust without re-checksumming

### 3. Image Export to OCI Directory / Registry Push

Replace current tar-based export with splitstream:

```
┌─────────────────┐              ┌─────────────────┐
│ cstor-rs Server │─streamTarSplit─>│     Client     │
│                 │    (NDJSON     │                │
│                 │     + fds)     │                │
└─────────────────┘               └───────┬────────┘
                                          │ reconstruct + compress
                                          ▼
                                 ┌─────────────────┐
                                 │   OCI blobs/    │
                                 │   or registry   │
                                 └─────────────────┘
```

Advantages:
- **Bit-for-bit tar reconstruction** via splitstream (tar-split) metadata
- Client controls compression (zstd levels, parallel compression)
- No temporary files - stream directly to destination
- Can pipeline: compress while still receiving more data

### 4. Container Build Layer Creation (Future)

During container builds, efficiently create new layers:

```
┌─────────────────┐              ┌─────────────────┐
│  Build Process  │──createLayer─>│ Storage Server │
│                 │──addFile(fd)──>│               │
│                 │──commit───────>│               │
└─────────────────┘               └─────────────────┘
```

Write-path operations (Phase 4):
- `layer.create` - Start a new layer
- `layer.addFile` - Add file from fd (server can reflink if same fs)
- `layer.commit` - Finalize layer, generate tar-split metadata

## Implementation Plan

### Phase 1: Read-Only Server in cstor-rs

Extend cstor-rs with a server mode:

```bash
cstor-rs serve --socket /run/cstor.sock
```

Implement core methods:
- `layer.streamTarSplit` - Stream tar-split with embedded fds (primary)
- `layer.getMeta` - Return TOC for file-level access
- `layer.getFiles` - Return O_RDONLY fds for specific files
- `image.getMeta` - Return merged TOC across layers

Internal changes needed:
- NDJSON-RPC-FD protocol implementation over Unix socket
- Streaming tar-split with fd passing (extend existing `TarSplitFdStream`)
- Position assignment in TOC entries
- fd passing via `sendmsg`/`SCM_RIGHTS`

### Phase 2: Client Library

Create a Rust client library for the protocol:

```rust
use cstor_client::{Client, SplitMessage};

let client = Client::connect("/run/cstor.sock")?;

// Stream layer for tar reconstruction
let mut tar_out = File::create("layer.tar")?;
for msg in client.stream_tar_split("sha256:layer1...")? {
    match msg {
        SplitMessage::Segment(data) => tar_out.write_all(&data)?,
        SplitMessage::File { fd, size, .. } => {
            std::io::copy(&mut fd.take(size), &mut tar_out)?;
        }
        SplitMessage::End => break,
    }
}

// Or for reflink extraction
let toc = client.image_get_meta("sha256:abc...")?;
let files = client.layer_get_files("sha256:layer1...", &[0, 1, 2])?;
for (entry, fd) in toc.reg_entries().zip(files) {
    let dest = dest_dir.create(&entry.name)?;
    ioctl_ficlone(&dest, &fd)?;
}
```

### Phase 3: Integration with containers/storage

Options:
1. **Go client for cstor-rs server**: Implement protocol client in Go
2. **Native Go server**: Port protocol to containers/storage Go code
3. **Hybrid**: cstor-rs serves read operations, Go handles writes

Provide CLI integration:
```bash
podman image object-store serve --socket /run/podman-store.sock
podman image object-store get-meta <image-id>
```

### Phase 4: Write Support

Extend protocol for layer creation:
- `layer.create` - Start new layer, returns layer handle
- `layer.addFile` - Add file from client-provided fd
- `layer.addMeta` - Add non-regular entries (dirs, symlinks, devices)
- `layer.commit` - Finalize, generate tar-split, return layer ID

### Phase 5: composefs Integration

If source/destination both use composefs:
- Include fsverity digests in TOC
- Server can verify fsverity-enabled files without reading content
- Enable efficient object store deduplication

## Relation to composefs Splitstream

This protocol shares the same fundamental insight as composefs splitstream:

> "Splitstream is a trivial way of storing file formats (like tar) with the 'data blocks' stored externally... with the goal that it's possible to bit-for-bit recreate the entire file."

However, this protocol uses **tar-split** (the existing containers-storage format) rather than the composefs splitstream binary format.

**Comparison:**

| Aspect | composefs Splitstream | This Protocol (tar-split) |
|--------|----------------------|---------------------------|
| Base format | Custom binary | NDJSON (tar-split native) |
| Inline data | zstd-compressed | base64 encoded |
| External refs | fsverity digest → object store | fd via SCM_RIGHTS |
| Storage | File on disk | Stream over Unix socket |
| Bit-for-bit | Yes | Yes |

**Why tar-split, not splitstream?**

- containers-storage already generates tar-split metadata
- No conversion step needed
- Existing tooling understands the format
- cstor-rs already parses it (`TarSplitFdStream`)

**Future path to composefs:**

If composefs adoption grows, a conversion layer could translate:
```
tar-split metadata + fds
    ↓ convert
splitstream + object store refs
```

This would enable storing layers in composefs format while maintaining compatibility with tar-split-based workflows.

## Security Considerations

- **Socket permissions**: Primary access control via filesystem permissions
- **Read-only by default**: Server only provides read access initially
- **fsverity trust**: If files have fsverity, kernel guarantees immutability
- **userns isolation**: Different processes can be in different user namespaces; server provides fds, client handles ownership

## Open Questions

1. **Streaming backpressure**: How does client signal "slow down"?
   - TCP-style flow control (Unix socket handles this?)
   - Explicit ack messages after N files?
   - Client controls pace by when it reads from socket

2. **FD limits per message**: Linux has `SCM_MAX_FD` (253) limit per sendmsg
   - For `streamTarSplit`: one fd per message (natural)
   - For `getFiles` batch: may need chunked response
   - Or client limits batch size

3. **Error recovery mid-stream**: What if fd open fails during `streamTarSplit`?
   - Error message in stream, client decides to abort or continue?
   - Fail entire stream?
   - Skip file and continue (client gets incomplete tar)?

4. **Caching**: Should server cache parsed tar-split?
   - Re-parse each time (simple, stateless)
   - Cache per layer (faster, memory cost)
   - LRU cache with size limit

5. **Hardlink handling in streamTarSplit**: 
   - tar-split includes hardlink entries (no content)
   - Stream as segment only (tar header), no fd
   - Client handles hardlink creation

6. **Symlink/device in streamTarSplit**:
   - Symlink target is in tar header (segment)
   - Devices: just header, no content
   - Only `reg` entries get file fds

7. **Wire format choice**: NDJSON vs binary splitstream?
   - Start with NDJSON (debuggable, compatible with spec-json-rpc-fdpass)
   - Binary mode as negotiable option for performance
   - Same semantics, different encoding

8. **Protocol versioning**: How to handle version negotiation?
   - Add `initialize` method like skopeo image-proxy
   - Returns supported methods and wire format options
   - Enables future extensions without breaking clients

## Protocol Comparison

| Feature | skopeo image-proxy | Proposed Protocol |
|---------|-------------------|-------------------|
| Socket type | SOCK_SEQPACKET | SOCK_STREAM |
| Message format | Custom JSON | JSON-RPC 2.0 |
| Framing | Packet boundaries | NDJSON |
| macOS support | No | Yes |
| Granularity | Whole blobs | Individual files |
| tar-split aware | No | Yes |
| Reflink path | No (pipe copy) | Yes (fd passing) |
| Bit-for-bit reconstruct | No | Yes |
| Protocol versioning | Yes (0.2.8) | Via JSON-RPC |
| Error handling | success/error fields | JSON-RPC errors |
| Streaming | Via pipes + FinishPipe | Via notifications |

## References

- [eStargz TOC specification](https://github.com/containerd/stargz-snapshotter/blob/main/docs/estargz.md#toc-tocentries-and-footer) - TOC format inspiration
- [composefs-rs splitstream](https://github.com/containers/composefs-rs/blob/main/doc/splitstream.md) - Binary splitstream format
- [container-libs#144](https://github.com/containers/container-libs/issues/144) - Efficient layer access discussion
- [container-libs#98](https://github.com/containers/container-libs/issues/98) - Object store socket API proposal
- [spec-json-rpc-fdpass](https://github.com/cgwalters/spec-json-rpc-fdpass) - NDJSON-RPC-FD IPC specification
- [tar-split](https://github.com/vbatts/tar-split) - Original tar metadata format
- [skopeo experimental-image-proxy](https://github.com/containers/skopeo/blob/main/docs-experimental/skopeo-experimental-image-proxy.1.md) - Prior art for IPC proxy
- [containers-image-proxy-rs](https://github.com/containers/containers-image-proxy-rs) - Rust client for image-proxy
