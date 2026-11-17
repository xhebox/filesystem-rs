# filesystem-rs

[![Test](https://github.com/xhebox/filesystem-rs/actions/workflows/test.yml/badge.svg)](https://github.com/xhebox/filesystem-rs/actions/workflows/test.yml)
[![Release](https://github.com/xhebox/filesystem-rs/actions/workflows/release.yml/badge.svg)](https://github.com/xhebox/filesystem-rs/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/github/license/xhebox/filesystem-rs)](https://github.com/xhebox/filesystem-rs/blob/main/LICENSE)

Generic file systems served over FUSE-style operations and volume APIs.

- `api` (`boxfs-api`): the `Fuse`, `Volume`, and `Snapshot` traits and the zero-copy reader and writer types a back-end implements.
- `erofs` (`boxfs-erofs`): a read-only EROFS image back-end built on `rust-fs-erofs`.
- `juicefs-sys` (`boxfs-juicefs-sys`): raw bindings, Go runtime startup, and independently released native archives.
- `juicefs` (`boxfs-juicefs`): a safe async JuiceFS volume back-end.
- `localpath` (`boxfs-localpath`): a host directory, served with every name resolved beneath its descriptor, so nothing a request names can reach past it.
- `memfs` (`boxfs-memfs`): an in-memory file system built on `imbl` persistent trees with $O(1)$ Copy-on-Write snapshots and 4 KiB page sharing.

## Build

```
task check
task test
```

Normal Cargo builds download the archive matching the exact `boxfs-juicefs-sys`
dependency; Go and container tools are only needed to build native archives.
`task test` builds the local sys archive before running tests.

## Release

A `v*` tag publishes the boxfs crates, excluding `boxfs-juicefs-sys`.
A `juicefs-sys-v*` tag independently builds and tests native archives,
uploads them and `SHA256SUMS` to GitHub Release, then publishes the sys crate.
