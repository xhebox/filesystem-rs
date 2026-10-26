# boxfs-localpath

Confined host-directory back-end for [`filesystem-rs`](https://github.com/xhebox/filesystem-rs).

## Overview

`PassthroughFs` serves a preopened host directory (`std::fs::File`) over `boxfs_api::Fuse`, `boxfs_api::Volume`, and `boxfs_api::Snapshot`:

- `PassthroughFs::new(root, read_only)` serves the directory tree rooted at `root`.
- `PassthroughFs::with_snapshots(root, snapshots, read_only)` enables `Snapshot` lifecycle operations (`snapshot`, `branch`, `restore`, `delete`) stored beneath a separate preopened `snapshots` directory.

Every lookup and open is resolved relative to the root descriptor so no guest or caller path can escape the directory tree:

- **Linux**: atomic `openat2` resolution with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` and no `/proc` dependency; handle upgrades re-open from `(parent, name)` and verify `(st_dev, st_ino)`.
- **macOS**: single-component validation, `O_SYMLINK` to open symlinks without following them, and `(st_dev, st_ino)` identity verification on reopen.
- **Windows**: single-component validation, `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT` so junctions and symlinks are never traversed, and `(volume_serial, file_index)` verification via `GetFileInformationByHandle`.

All replies carry zero cache timeouts and `FOPEN_DIRECT_IO`, making host-side mutations immediately visible without cache invalidation notifications.

## License

MIT
