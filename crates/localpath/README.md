# boxfs-localpath

Confined host-directory passthrough filesystem implementing `boxfs-api`.

## Overview

`PassthroughFs` serves a preopened host directory (`std::fs::File`) over `boxfs_api::Fuse` and `boxfs_api::Volume`:

- `PassthroughFs::new(root, read_only)` creates a passthrough volume confined to `root`.
- `Volume::clone_tree` clones subtrees within the volume using Copy-on-Write (`btrfs` snapshots / `FICLONE` on Linux, `clonefile` on macOS, or recursive copy fallback).

## License

MIT
