//! A host directory served as a FUSE file system, confined to that directory.
//!
//! [`PassthroughFs`] implements [`fuse_api::FileSystem`] over a directory the
//! caller opened. Every name is resolved beneath that directory's descriptor,
//! so nothing a guest names can reach past it. The request protocol, dispatch
//! and reply encoding belong to whoever drives the file system; this crate is
//! the back-end they call.
//!
//! The back-end is Unix-only: it resolves names with `openat`-style calls. On
//! other targets the crate is empty.

#![cfg(unix)]

mod abi;
mod passthrough;
mod span;

pub use passthrough::PassthroughFs;
