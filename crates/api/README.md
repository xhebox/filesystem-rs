# boxfs-api

Traits and zero-copy types for file systems and volumes in [`filesystem-rs`](https://github.com/xhebox/filesystem-rs).

## Overview

A storage back-end implements up to two core async traits from this crate:

- `Fuse` — FUSE protocol operations (`lookup`, `getattr`, `setattr`, `open`, `create`, `read`, `write`, `readdir`, `readdirplus`, extended attributes, locks/sync, etc.) driven by a transport such as virtio-fs.
- `Volume` — path-addressed operations (`read`, `write`, `stat`, `readlink`, `symlink`, `list`, `walk`, `create_dir`, `create_dir_all`, `remove_file`, `remove_dir`, `remove_all`, `rename`, `copy`, `clone_tree`) for host or agent callers outside a guest.

`SubVolume` scopes any `Volume` to a subdirectory root, and `diff_trees` / `diff_volumes` compare directory trees across subtrees or volumes.

Every trait method defaults to returning `ENOSYS`, so a back-end implements only the operations it supports.

## Zero-Copy I/O

For guest-memory transports, `Fuse::read` and `Fuse::write` take `ZeroCopyWriter` and `ZeroCopyReader` rather than intermediate byte buffers. A transport exposes mapped guest regions through the `Memory` trait (`Extent` -> `MemoryRange`), allowing back-ends to read from or write directly into guest address space in place.

## License

MIT
