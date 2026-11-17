# boxfs-juicefs-sys

Raw FFI and Go runtime initialization for the embedded JuiceFS binding maintained
by filesystem-rs. This is not an upstream JuiceFS C API.

This crate has its own version, independent of the other boxfs crates. Each
`juicefs-sys-v{version}` GitHub Release contains the corresponding archives
and `SHA256SUMS`. Cargo downloads `libjuicefs-{os}-{arch}.a.zst` from that
release, checks its SHA-256, and links it. Normal builds need neither Go nor a
container runtime. Release checksums detect corruption; they are not an independent
signature or protection against replacement of the entire release.

## Local Development

- `JUICEFS_SYS_CACHE` selects an additional archive cache directory. Archives
  are stored below `v{version}` using their target-specific names. Otherwise a
  downloaded archive is kept under Cargo's `OUT_DIR`.
- Missing downloads produce a warning so `cargo check` can proceed. Actual
  linking requires an archive. Invalid checksums fail the build.

Run `task test` to build the archive and run tests against the local sys crate.
This requires Go/CGO and the platform build tools; Linux/Android builds use
Docker. `task generate` regenerates the committed raw FFI
and additionally needs bindgen and libclang.

Before calling any raw FFI function, call `start_runtime()` from an unconfined
thread, after namespace setup and before installing host signal handlers. See
its API documentation for the runtime lifetime and signal handling contract.

## Release

Bump this crate's version when the Go binding or archive build inputs change.
Push `juicefs-sys-v{version}` to build/test the archives, upload them with
`softprops/action-gh-release`, and then publish only this crate to crates.io.
Published archives must not be replaced. Update `boxfs-juicefs`'s exact sys
dependency after the sys release is available. Crates.io trusted publishing must
allow the `juicefs-sys.yml` workflow in the `crates-io` environment.

MIT
