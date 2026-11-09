//! [`Fuse`] transport operations, path-addressed [`Volume`] access, and
//! [`Snapshot`] lifecycle and diff operations.

mod fuse;
mod memory;
mod search;
mod snapshot;
mod volume;

pub use fuse::{
	Attr, Context, CreateArgs, DirEntry, DirentInfo, Entry, Extent, Fuse, GetxattrReply, Kstatfs,
	ListxattrReply, ZeroCopyReader, ZeroCopyWriter,
};
pub use memory::{Memory, MemoryRange};
pub use snapshot::{DiffEntry, DiffKind, Snapshot, diff_volumes};
pub use volume::{Volume, WalkEntry, name_to_path};

pub use search::{
	ContentIndex, FileSignatures, FileStamp, IndexOptions, PageSig, PathIndex, SEARCH_OVERLAP,
	SEARCH_PAGE_SIZE, SIG_BYTES, Search, SearchIndex, SearchMatch, SearchQuery, VolumeHook,
	XATTR_SIG_NAME, compute_file_sigs, compute_page_sig, decode_sig_xattr, encode_sig_xattr,
	query_buckets, search_volume,
};
