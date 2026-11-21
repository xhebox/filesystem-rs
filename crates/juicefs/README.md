# boxfs-juicefs

JuiceFS volume back-end for [`filesystem-rs`](https://github.com/xhebox/filesystem-rs), linking the JuiceFS Go runtime into the process as a `c-archive`.

## Overview

`Volume` mounts a JuiceFS volume in-process without a helper daemon or FUSE wire serialization across the boundary:

- `Volume::mount(meta_url, MountOptions::default())` mounts the whole volume read-write with the default local cache directory. `MountOptions` covers the mount-time configuration a VMM needs, and `Default` matches the values this crate has always used, so `..Default::default()` is the short way to set one field.
- `subdir: Some("/data")` mounts `/data` as the root; a writable mount creates a missing subdirectory, a read-only one requires it to exist. `read_only: true` sets `meta.Config.ReadOnly` before the metadata client is created.
- `cache_dir: Some(path)` picks the chunk cache directory, and `Some(Path::new("memory"))` keeps chunks in memory only. `cache_size`, `cache_items`, `free_space_permille`, `cache_eviction` and `cache_checksum` size and police it.
- `hide_internal: true` omits `.stats`, `.config`, `.accesslog` and `.trash` from root listings. It is a listing policy only: the nodes stay reachable by name, as with upstream `--hide-internal`. `--prefix-internal` is deliberately not offered, because the pinned JuiceFS rewrites process-global state for it and would corrupt every other volume in the process.
- `no_bgjob` defaults to `true` here (upstream defaults to `false`): background cleanup and backups are off, which is what many short-lived volumes sharing one VMM want. `backup_meta` only takes effect with `no_bgjob: false` and a writable mount; upstream's backup loop has no stop channel, so it keeps running after this volume is dropped.
- JuiceFS and Go standard-library logs are discarded by default so the embedded archive never writes into the host application's stdout or stderr. Operation failures are returned through the Rust API.
- Blocking calls into Go (object storage and metadata engine I/O) run on the session's plain worker threads and return via oneshot channels, keeping async device reactors unblocked and preventing Go threads from inheriting per-thread seccomp filters.
- Dropping `Volume` closes the worker queues and unmounts the Go session.

`Volume` implements `boxfs_api::Fuse` and `boxfs_api::Volume`.

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
