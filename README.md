# filesystem-rs

[![Test](https://github.com/xhebox/filesystem-rs/actions/workflows/test.yml/badge.svg)](https://github.com/xhebox/filesystem-rs/actions/workflows/test.yml)
[![Release](https://github.com/xhebox/filesystem-rs/actions/workflows/release.yml/badge.svg)](https://github.com/xhebox/filesystem-rs/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/github/license/xhebox/filesystem-rs)](https://github.com/xhebox/filesystem-rs/blob/main/LICENSE)

Generic file systems served over FUSE-style operations.

- `fuse-api`: the `FileSystem` trait and the zero-copy reader and writer types a back-end implements.
- `juicefs-rs`: a JuiceFS volume, mounted by a Go c-archive linked into the process.
- `localpath-rs`: a host directory, served with every name resolved beneath its descriptor, so nothing a request names can reach past it. Unix only.

## Build

```
task check
task test
```

## Release

A `v*` tag builds the archives for each target and publishes them with the matching `SHA256SUMS`.
