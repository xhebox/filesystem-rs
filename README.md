# filesystem-rs

[![Test](https://github.com/xhebox/filesystem-rs/actions/workflows/test.yml/badge.svg)](https://github.com/xhebox/filesystem-rs/actions/workflows/test.yml)
[![Release](https://github.com/xhebox/filesystem-rs/actions/workflows/release.yml/badge.svg)](https://github.com/xhebox/filesystem-rs/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/github/license/xhebox/filesystem-rs)](https://github.com/xhebox/filesystem-rs/blob/main/LICENSE)

File systems served over FUSE-style operations, for hosts that handle the guest's requests themselves.

- `fuse-api`: the `FileSystem` trait and the zero-copy reader and writer types a back-end implements.
- `juicefs-rs`: a JuiceFS volume, mounted by a Go c-archive linked into the process.
- `localpath-rs`: a host directory, served with every name resolved beneath its descriptor, so nothing a request names can reach past it. Unix only.

## Build

```
task check
task test
```

`task check` formats and lints every target a release ships. `build.rs` in `juicefs-rs` links the JuiceFS archive: `task juicefs` builds it into `target/juicefs`, using Docker on Linux and the host Go toolchain elsewhere. Without it the link fails, and `cargo check` still works.

## Release

Pushing a `v*` tag builds the archives for each target and publishes them with the matching `SHA256SUMS`, which `juicefs-rs` downloads and verifies.
