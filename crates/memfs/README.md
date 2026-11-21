# boxfs-memfs

In-memory Copy-on-Write filesystem implementing `boxfs-api`.

## Overview

`MemFs` implements `boxfs_api::Fuse` and `boxfs_api::Volume` purely in memory with structural sharing:

- Directories and extended attributes are `imbl::OrdMap`s, and the inode table is an `imbl::HashMap`.
- `Volume::clone_tree` clones subtrees with page-level Copy-on-Write sharing (`imbl::Vector` of 4 KiB `Option<Arc<[u8; 4096]>>` pages), so a small edit to a large file after cloning copies only the touched 4 KiB pages.

## License

MIT
