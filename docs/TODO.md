# cstor-rs TODO

## Current Status

**READ-ONLY IMPLEMENTATION COMPLETE** - Production-ready for read-only use cases.

Core features implemented:
- Storage discovery with cap-std (fd-relative operations)
- Layer reading with link resolution and parent chain traversal
- Image manifest parsing
- Tar-split integration with bit-for-bit identical reconstruction
- TOC generation (eStargz-compatible)
- CLI with 8 commands including reflink extraction
- Automatic rootless mode support

## Future Work

### Write Support (Major)

Adding write support would enable creating/modifying layers and images. This requires:

- Understanding containers-storage locking (`storage/pkg/lockfile/`)
- Atomic operations and crash safety
- Integration with existing container runtimes (podman, buildah, cri-o)
- tar-split generation from filesystem content
- Database (SQLite) transactional updates

**Warning**: Complex feature that could corrupt storage if implemented incorrectly.

### Enhancements (Minor)

**Platform selection**: Handle multi-arch images with target architecture specification.

**Performance**: Optional CRC verification bypass, larger buffer sizes, concurrent access support.

**Additional features**: Composefs (EROFS) support, zstd:chunked metadata, additional image stores.

## References

- Go implementation: `github.com/containers/storage`
- Overlay filesystem: https://docs.kernel.org/filesystems/overlayfs.html
- OCI Image Spec: https://github.com/opencontainers/image-spec
