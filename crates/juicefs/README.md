# boxfs-juicefs

JuiceFS volume back-end for [`filesystem-rs`](https://github.com/xhebox/filesystem-rs), linking the JuiceFS Go runtime into the process as a `c-archive`.

## Overview

`Volume` mounts a JuiceFS volume in-process without a helper daemon or FUSE wire serialization across the boundary:

- `Volume::mount(meta_url, cache_dir)` initializes the embedded Go runtime (or callers may invoke `start_runtime()` explicitly beforehand), mounts the volume against `meta_url` with local chunk caching under `cache_dir`, and starts a dedicated worker thread pool.
- Blocking calls into Go (object storage and metadata engine I/O) run on the session's plain worker threads and return via oneshot channels, keeping async device reactors unblocked and preventing Go threads from inheriting per-thread seccomp filters.
- Dropping `Volume` closes the worker queues and unmounts the Go session.

`Volume` implements `boxfs_api::Fuse`, `boxfs_api::Volume`, and `boxfs_api::Snapshot`.

## Linking the Go Archive

`build.rs` searches for `libjuicefs-{os}-{arch}.a` in order:

1. `target/juicefs` in the workspace (built locally via `task juicefs`).
2. `$JUICEFS_CACHE/v{version}/`.
3. `$OUT_DIR/v{version}/`, downloading and verifying the `.a.zst` archive against `SHA256SUMS` from the matching GitHub release if not yet cached.

## License

MIT
