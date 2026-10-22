//! The interface a FUSE back-end implements to be served over virtio-fs or
//! any other FUSE transport.
//!
//! The transport parses the guest's requests and calls the [`FileSystem`]
//! methods; a back-end answers with the reply the request asks for. Guest
//! memory appears only as the [`Extent`] ranges of [`ZeroCopyReader`] and
//! [`ZeroCopyWriter`], resolved through [`Memory`]. The types here carry no
//! wire layout: a transport turns them into the bytes the kernel reads.

mod filesystem;
mod memory;

pub use filesystem::{
	Attr, Context, CreateArgs, DirEntry, DirentInfo, Entry, Extent, FileSystem, GetxattrReply,
	Kstatfs, ListxattrReply, ZeroCopyReader, ZeroCopyWriter,
};
pub use memory::{Memory, MemoryRange};
