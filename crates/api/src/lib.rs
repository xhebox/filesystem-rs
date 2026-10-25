//! The interfaces a file-system or volume back-end implements: [`Fuse`] for
//! FUSE transports (such as virtio-fs), [`Volume`] for path-addressed
//! host/agent access, and [`Snapshot`] for point-in-time snapshots and
//! branches.

mod fuse;
mod memory;
mod snapshot;
mod volume;

pub use fuse::{
	Attr, Context, CreateArgs, DirEntry, DirentInfo, Entry, Extent, Fuse, GetxattrReply, Kstatfs,
	ListxattrReply, ZeroCopyReader, ZeroCopyWriter,
};
pub use memory::{Memory, MemoryRange};
pub use snapshot::Snapshot;
pub use volume::Volume;
