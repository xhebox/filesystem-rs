# boxfs-memfs

In-memory file system back-end for [`filesystem-rs`](https://github.com/xhebox/filesystem-rs), built on [`imbl`](https://crates.io/crates/imbl) persistent trees.

## Overview

`MemFs` implements `boxfs_api::Fuse`, `boxfs_api::Volume`, and `boxfs_api::Snapshot` purely in memory with structural sharing:

- `MemFs::new(read_only)` (or `MemFs::default()` for a writable instance) creates an empty in-memory file system.
- The inode table is an `imbl::HashMap`, making `Snapshot::snapshot`, `Snapshot::branch`, and `Snapshot::restore` $O(1)$ Copy-on-Write clones.
- Directories and extended attributes are `imbl::OrdMap`s that share unchanged subtrees across snapshots and branches.
- Regular file contents are stored as an `imbl::Vector` of 4 KiB pages (`Option<Arc<[u8; 4096]>>`, where `None` represents a sparse zero page), so modifying a file after a snapshot copies only the touched 4 KiB pages.

## License

MIT
