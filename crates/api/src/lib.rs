//! [`Fuse`] transport operations, path-addressed [`Volume`] access, and
//! [`Snapshot`] lifecycle and diff operations.

mod fuse;
mod memory;
mod snapshot;
mod volume;

pub use fuse::{
	Attr, Context, CreateArgs, DirEntry, DirentInfo, Entry, Extent, Fuse, GetxattrReply, Kstatfs,
	ListxattrReply, ZeroCopyReader, ZeroCopyWriter,
};
pub use memory::{Memory, MemoryRange};
pub use snapshot::{DiffEntry, DiffKind, Snapshot, diff_volumes};
pub use volume::{Volume, WalkEntry, name_to_path};
