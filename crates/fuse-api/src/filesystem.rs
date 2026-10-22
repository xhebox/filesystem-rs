//! The filesystem interface a FUSE back-end implements, plus the reply
//! types the server passes to it.

use std::ffi::CStr;
use std::io;
use std::sync::Arc;

use crate::memory::Memory;

/// Per-request credentials from the guest.
#[derive(Clone, Copy, Debug, Default)]
pub struct Context {
	pub uid: u32,
	pub gid: u32,
	/// The guest process the request is attributed to.
	pub pid: u32,
}

impl Context {
	pub fn new(uid: u32, gid: u32, pid: u32) -> Self {
		Self { uid, gid, pid }
	}
}

/// A directory entry in a READDIR/READDIRPLUS reply.
#[derive(Clone, Debug, Default)]
pub struct DirEntry {
	/// Inode number the guest should use.
	pub ino: u64,
	/// Offset that resumes the listing after this entry.
	pub offset: u64,
	/// Entry type (an `FUSE_DT_*` value, which matches `DT_*`).
	pub type_: u32,
	/// Name, without separators.
	pub name: Vec<u8>,
}

/// A name resolution result: the inode plus its attributes.
#[derive(Clone, Debug, Default)]
pub struct Entry {
	pub inode: u64,
	pub generation: u64,
	pub attr: Attr,
	/// Attribute cache timeout, seconds and nanoseconds.
	pub attr_timeout: (u64, u32),
	/// Name cache timeout.
	pub entry_timeout: (u64, u32),
}

/// Reply to GETXATTR: either the value or the size the caller must supply.
#[derive(Clone, Debug)]
pub enum GetxattrReply {
	Value(Vec<u8>),
	Size(u32),
}

/// Reply to LISTXATTR: either the name list or the size it needs.
#[derive(Clone, Debug)]
pub enum ListxattrReply {
	Names(Vec<u8>),
	Size(u32),
}

/// The reply body a READ fills, as guest memory the back-end can write
/// straight into.
pub trait ZeroCopyWriter {
	/// The address space the ranges resolve in.
	fn memory(&self) -> Arc<dyn Memory>;

	/// The ranges left for the reply body, from the cursor on.
	fn extents(&self) -> Vec<Extent>;

	/// Records `count` body bytes as written.
	fn written(&mut self, count: usize) -> io::Result<()>;
}

/// The request bytes a WRITE takes, as guest memory the back-end can read
/// straight from.
pub trait ZeroCopyReader {
	/// The address space the ranges resolve in.
	fn memory(&self) -> Arc<dyn Memory>;

	/// The next `count` request bytes, as ranges.
	fn extents(&self, count: usize) -> Vec<Extent>;
}

/// The operations the server dispatches to. Every method has a default that
/// reports `ENOSYS`, so a back-end implements only what it serves.
#[allow(async_fn_in_trait)]
pub trait FileSystem {
	type Inode: Into<u64> + From<u64> + Copy;
	type Handle: Into<u64> + From<u64> + Copy;

	/// Handshake: `capable` are the kernel's flags, the return value is the
	/// subset the server accepts.
	async fn init(&self, _capable: u32) -> io::Result<u32> {
		Err(unsupported())
	}

	async fn lookup(
		&self,
		_ctx: &Context,
		_parent: Self::Inode,
		_name: &CStr,
	) -> io::Result<Entry> {
		Err(unsupported())
	}

	async fn forget(&self, _ctx: &Context, _inode: Self::Inode, _count: u64) {}

	async fn batch_forget(&self, _ctx: &Context, _requests: Vec<(Self::Inode, u64)>) {}

	/// `handle` is `Some` for a fstat-style lookup on an open file.
	async fn getattr(
		&self,
		_ctx: &Context,
		_inode: Self::Inode,
		_handle: Option<Self::Handle>,
	) -> io::Result<(Attr, (u64, u32))> {
		Err(unsupported())
	}

	async fn setattr(
		&self,
		_ctx: &Context,
		_inode: Self::Inode,
		_attr: Attr,
		_handle: Option<Self::Handle>,
		_valid: u32,
	) -> io::Result<(Attr, (u64, u32))> {
		Err(unsupported())
	}

	async fn readlink(&self, _ctx: &Context, _inode: Self::Inode) -> io::Result<Vec<u8>> {
		Err(unsupported())
	}

	async fn symlink(
		&self,
		_ctx: &Context,
		_linkname: &CStr,
		_parent: Self::Inode,
		_name: &CStr,
	) -> io::Result<Entry> {
		Err(unsupported())
	}

	async fn mknod(
		&self,
		_ctx: &Context,
		_parent: Self::Inode,
		_name: &CStr,
		_mode: u32,
		_rdev: u32,
		_umask: u32,
	) -> io::Result<Entry> {
		Err(unsupported())
	}

	async fn mkdir(
		&self,
		_ctx: &Context,
		_parent: Self::Inode,
		_name: &CStr,
		_mode: u32,
		_umask: u32,
	) -> io::Result<Entry> {
		Err(unsupported())
	}

	async fn unlink(&self, _ctx: &Context, _parent: Self::Inode, _name: &CStr) -> io::Result<()> {
		Err(unsupported())
	}

	async fn rmdir(&self, _ctx: &Context, _parent: Self::Inode, _name: &CStr) -> io::Result<()> {
		Err(unsupported())
	}

	async fn rename(
		&self,
		_ctx: &Context,
		_olddir: Self::Inode,
		_oldname: &CStr,
		_newdir: Self::Inode,
		_newname: &CStr,
		_flags: u32,
	) -> io::Result<()> {
		Err(unsupported())
	}

	async fn link(
		&self,
		_ctx: &Context,
		_inode: Self::Inode,
		_newparent: Self::Inode,
		_newname: &CStr,
	) -> io::Result<Entry> {
		Err(unsupported())
	}

	async fn open(
		&self,
		_ctx: &Context,
		_inode: Self::Inode,
		_flags: u32,
	) -> io::Result<(Self::Handle, u32)> {
		Err(unsupported())
	}

	async fn create(
		&self,
		_ctx: &Context,
		_parent: Self::Inode,
		_name: &CStr,
		_args: CreateArgs,
	) -> io::Result<(Entry, Self::Handle, u32)> {
		Err(unsupported())
	}

	async fn read(
		&self,
		_ctx: &Context,
		_inode: Self::Inode,
		_handle: Self::Handle,
		_w: &mut dyn ZeroCopyWriter,
		_size: u32,
		_offset: u64,
	) -> io::Result<usize> {
		Err(unsupported())
	}

	async fn write(
		&self,
		_ctx: &Context,
		_inode: Self::Inode,
		_handle: Self::Handle,
		_r: &mut dyn ZeroCopyReader,
		_size: u32,
		_offset: u64,
	) -> io::Result<usize> {
		Err(unsupported())
	}

	/// Preallocates or punches a range, as `fallocate(2)` asks. The default is
	/// `ENOSYS`, which the kernel reads as an unsupported operation.
	async fn fallocate(
		&self,
		_ctx: &Context,
		_inode: Self::Inode,
		_handle: Self::Handle,
		_offset: u64,
		_length: u64,
		_mode: u32,
	) -> io::Result<()> {
		Err(unsupported())
	}

	async fn flush(
		&self,
		_ctx: &Context,
		_inode: Self::Inode,
		_handle: Self::Handle,
	) -> io::Result<()> {
		Err(unsupported())
	}

	async fn fsync(
		&self,
		_ctx: &Context,
		_inode: Self::Inode,
		_datasync: bool,
		_handle: Self::Handle,
	) -> io::Result<()> {
		Err(unsupported())
	}

	async fn release(
		&self,
		_ctx: &Context,
		_inode: Self::Inode,
		_flags: u32,
		_handle: Self::Handle,
	) -> io::Result<()> {
		Err(unsupported())
	}

	async fn statfs(&self, _ctx: &Context, _inode: Self::Inode) -> io::Result<Kstatfs> {
		Err(unsupported())
	}

	async fn setxattr(
		&self,
		_ctx: &Context,
		_inode: Self::Inode,
		_name: &CStr,
		_value: &[u8],
		_flags: u32,
	) -> io::Result<()> {
		Err(unsupported())
	}

	async fn getxattr(
		&self,
		_ctx: &Context,
		_inode: Self::Inode,
		_name: &CStr,
		_size: u32,
	) -> io::Result<GetxattrReply> {
		Err(unsupported())
	}

	async fn listxattr(
		&self,
		_ctx: &Context,
		_inode: Self::Inode,
		_size: u32,
	) -> io::Result<ListxattrReply> {
		Err(unsupported())
	}

	async fn removexattr(
		&self,
		_ctx: &Context,
		_inode: Self::Inode,
		_name: &CStr,
	) -> io::Result<()> {
		Err(unsupported())
	}

	async fn opendir(&self, _ctx: &Context, _inode: Self::Inode) -> io::Result<Self::Handle> {
		Err(unsupported())
	}

	async fn readdir(
		&self,
		_ctx: &Context,
		_inode: Self::Inode,
		_handle: Self::Handle,
		_size: u32,
		_offset: u64,
	) -> io::Result<Vec<DirEntry>> {
		Err(unsupported())
	}

	async fn readdirplus(
		&self,
		_ctx: &Context,
		_inode: Self::Inode,
		_handle: Self::Handle,
		_size: u32,
		_offset: u64,
	) -> io::Result<Vec<(Entry, DirentInfo)>> {
		Err(unsupported())
	}

	async fn fsyncdir(
		&self,
		_ctx: &Context,
		_inode: Self::Inode,
		_datasync: bool,
		_handle: Self::Handle,
	) -> io::Result<()> {
		Err(unsupported())
	}

	async fn releasedir(
		&self,
		_ctx: &Context,
		_inode: Self::Inode,
		_handle: Self::Handle,
	) -> io::Result<()> {
		Err(unsupported())
	}

	async fn access(&self, _ctx: &Context, _inode: Self::Inode, _mask: u32) -> io::Result<()> {
		Err(unsupported())
	}
}

/// Arguments of a CREATE request.
#[derive(Clone, Copy, Debug, Default)]
pub struct CreateArgs {
	/// Open flags (`O_*`).
	pub flags: u32,
	/// File mode to create.
	pub mode: u32,
	/// umask the guest applied.
	pub umask: u32,
}

/// The dirent fields a READDIRPLUS reply needs beyond [`Entry`].
#[derive(Clone, Debug, Default)]
pub struct DirentInfo {
	pub ino: u64,
	pub offset: u64,
	pub type_: u32,
	pub name: Vec<u8>,
}

/// A range of guest memory: `len` bytes at guest address `offset`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Extent {
	pub offset: u64,
	pub len: usize,
}

/// The error every unimplemented operation reports: the guest's `ENOSYS`.
fn unsupported() -> io::Error {
	io::Error::from_raw_os_error(libc::ENOSYS)
}

/// The attributes of one inode, as a reply reports them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Attr {
	pub ino: u64,
	pub size: u64,
	pub blocks: u64,
	pub atime: u64,
	pub mtime: u64,
	pub ctime: u64,
	pub atimensec: u32,
	pub mtimensec: u32,
	pub ctimensec: u32,
	pub mode: u32,
	pub nlink: u32,
	pub uid: u32,
	pub gid: u32,
	pub rdev: u32,
	pub blksize: u32,
	pub flags: u32,
}

/// The filesystem-wide statistics a STATFS reply carries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Kstatfs {
	pub blocks: u64,
	pub bfree: u64,
	pub bavail: u64,
	pub files: u64,
	pub ffree: u64,
	pub bsize: u32,
	pub namelen: u32,
	pub frsize: u32,
	pub padding: u32,
	pub spare: [u32; 6],
}
