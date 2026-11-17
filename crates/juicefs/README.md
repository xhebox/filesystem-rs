# boxfs-juicefs

JuiceFS volume back-end for [`filesystem-rs`](https://github.com/xhebox/filesystem-rs), linking the JuiceFS Go runtime into the process as a `c-archive`.

## Overview

`Volume` mounts a JuiceFS volume in-process without a helper daemon or FUSE wire serialization across the boundary:

- `Volume::mount(meta_url, cache_dir)` initializes the embedded Go runtime with a read-write metadata client. `Volume::mount_with_options` additionally accepts `MountOptions { read_only: true }`, which sets JuiceFS `meta.Config.ReadOnly` before the client is created.
- JuiceFS and Go standard-library logs are discarded by default so the embedded archive never writes into the host application's stdout or stderr. Operation failures are returned through the Rust API.
- Blocking calls into Go (object storage and metadata engine I/O) run on the session's plain worker threads and return via oneshot channels, keeping async device reactors unblocked and preventing Go threads from inheriting per-thread seccomp filters.
- Dropping `Volume` closes the worker queues and unmounts the Go session.

`Volume` implements `boxfs_api::Fuse`, `boxfs_api::Volume`, and `boxfs_api::Snapshot`.

## Linking the Go Archive

The exact `boxfs-juicefs-sys` dependency owns the Go binding, runtime startup,
and native linking. It downloads the matching precompiled archive from its own
`juicefs-sys-v{version}` GitHub Release and verifies `SHA256SUMS`.
Normal Cargo builds do not require Go, Docker, Podman, or `task juicefs`.

Use `task juicefs` to build the local archive under `target/juicefs-sys`, or
`JUICEFS_SYS_CACHE` to use a shared archive cache. These are native build
settings, separate from the volume's chunk cache directory.
See [boxfs-juicefs-sys](../juicefs-sys/README.md) for maintainer build and release
instructions.

## License

MIT
