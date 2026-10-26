# boxfs-erofs

Read-only EROFS image back-end for [`filesystem-rs`](https://github.com/xhebox/filesystem-rs), built on [`rust-fs-erofs`](https://crates.io/crates/rust-fs-erofs).

## Overview

`Erofs` mounts an EROFS image and serves it over both `boxfs_api::Fuse` and `boxfs_api::Volume`:

- `Erofs::open_path(path)` opens an image file on the host.
- `Erofs::from_bytes(bytes)` opens an image backed by an in-memory buffer.
- `Erofs::open(device)` opens an image over any `BlockRead` device with metadata block caching.

All read operations (`lookup`, `getattr`, `readlink`, `open`, `read`, `readdir`, `readdirplus`, `getxattr`, `listxattr`, `statfs`, and path-addressed `Volume` reads/listings) are supported; mutating operations return `EROFS`.

This crate also re-exports `BlockRead` (from `rust-fs-core`) and `mkfs` (from `rust-fs-erofs`) for building images.

## License

MIT
