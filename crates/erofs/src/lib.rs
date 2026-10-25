//! Read-only EROFS file system and volume back-end over [`fs_erofs`].
//!
//! [`Erofs`] implements [`api::Fuse`] and [`api::Volume`] over any
//! [`fs_core::BlockRead`] device (a host path via [`Erofs::open_path`], an
//! in-memory buffer via [`Erofs::from_bytes`], or a custom [`BlockRead`] via
//! [`Erofs::open`]).

use std::collections::HashMap;
use std::ffi::CStr;
use std::io;
use std::path::{Component, Path};
use std::sync::{Arc, Mutex};

use api::{
	Attr, Context, CreateArgs, DirEntry, DirentInfo, Entry, Fuse, GetxattrReply, Kstatfs,
	ListxattrReply, Volume, ZeroCopyReader, ZeroCopyWriter,
};
pub use fs_core::BlockRead;
use fs_core::FileDevice;
use fs_erofs::dir::ftype;
use fs_erofs::fs::DEFAULT_METADATA_CACHE_BLOCKS;
pub use fs_erofs::mkfs;
use fs_erofs::{Error as ErofsError, Filesystem, Inode as ErofsInode};

const ROOT_ID: u64 = 1;
const CACHE_TTL: (u64, u32) = (u64::MAX / 2, 0);

const FOPEN_KEEP_CACHE: u32 = 1 << 1;
const FUSE_ASYNC_READ: u32 = 1 << 0;
const FUSE_MAX_PAGES: u32 = 1 << 22;

const O_RDONLY: u32 = 0;
const O_ACCMODE: u32 = 3;
const O_CREAT: u32 = libc::O_CREAT as u32;
const O_TRUNC: u32 = libc::O_TRUNC as u32;

const DT_FIFO: u32 = 1;
const DT_CHR: u32 = 2;
const DT_DIR: u32 = 4;
const DT_BLK: u32 = 6;
const DT_REG: u32 = 8;
const DT_LNK: u32 = 10;
const DT_SOCK: u32 = 12;

struct OpenHandle {
	nid: u64,
	directory: bool,
}

struct HandleTable {
	handles: HashMap<u64, OpenHandle>,
	next: u64,
}

impl HandleTable {
	fn new() -> Self {
		Self {
			handles: HashMap::new(),
			next: 1,
		}
	}

	fn insert(&mut self, handle: OpenHandle) -> io::Result<u64> {
		let id = self.next;
		self.next = self
			.next
			.checked_add(1)
			.ok_or_else(|| errno(libc::EOVERFLOW))?;
		self.handles.insert(id, handle);
		Ok(id)
	}
}

struct BytesDevice(Arc<[u8]>);

impl BlockRead for BytesDevice {
	fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_core::Result<()> {
		let size = self.0.len() as u64;
		let len = buf.len() as u64;
		let start = usize::try_from(offset).map_err(|_| fs_core::Error::OutOfBounds {
			offset,
			len,
			size,
		})?;
		let end = start
			.checked_add(buf.len())
			.ok_or(fs_core::Error::OutOfBounds { offset, len, size })?;
		if end > self.0.len() {
			return Err(fs_core::Error::ShortRead {
				offset,
				want: buf.len(),
				got: self.0.len().saturating_sub(start),
			});
		}
		buf.copy_from_slice(&self.0[start..end]);
		Ok(())
	}

	fn size_bytes(&self) -> u64 {
		self.0.len() as u64
	}
}

/// A mounted read-only EROFS image serving [`api::Fuse`] and [`api::Volume`].
pub struct Erofs {
	inner: Filesystem,
	root_nid: u64,
	handles: Mutex<HandleTable>,
}

impl Erofs {
	/// Opens an EROFS image from `device` with the default metadata block cache.
	pub fn open(device: Arc<dyn BlockRead>) -> io::Result<Self> {
		let inner =
			Filesystem::open_with_cache(device, DEFAULT_METADATA_CACHE_BLOCKS).map_err(erofs_io)?;
		let root_nid = u64::from(inner.superblock().root_nid);
		Ok(Self {
			inner,
			root_nid,
			handles: Mutex::new(HandleTable::new()),
		})
	}

	/// Opens an EROFS image backed by an in-memory byte buffer.
	pub fn from_bytes(bytes: impl Into<Arc<[u8]>>) -> io::Result<Self> {
		Self::open(Arc::new(BytesDevice(bytes.into())))
	}

	/// Opens an EROFS image file at `path`.
	pub fn open_path(path: impl AsRef<Path>) -> io::Result<Self> {
		let device = FileDevice::open(path).map_err(|e| errno_from_block(&e))?;
		Self::open(Arc::new(device))
	}

	fn to_ino(&self, nid: u64) -> u64 {
		if nid == self.root_nid {
			ROOT_ID
		} else {
			nid.saturating_add(2)
		}
	}

	fn to_nid(&self, ino: u64) -> io::Result<u64> {
		if ino == ROOT_ID {
			Ok(self.root_nid)
		} else if ino >= 2 {
			Ok(ino - 2)
		} else {
			Err(errno(libc::ENOENT))
		}
	}

	fn inode(&self, ino: u64) -> io::Result<ErofsInode> {
		let nid = self.to_nid(ino)?;
		self.inner.read_inode(nid).map_err(erofs_io)
	}

	fn wire_attr(&self, inode: &ErofsInode) -> Attr {
		let bsize = self.inner.superblock().block_size();
		let rdev = inode
			.rdev()
			.map(|(maj, min)| (maj << 8) | (min & 0xff) | ((min & !0xff) << 12))
			.unwrap_or(0);
		Attr {
			ino: self.to_ino(inode.nid),
			size: inode.size,
			blocks: inode.size.div_ceil(512),
			atime: inode.mtime,
			mtime: inode.mtime,
			ctime: inode.mtime,
			atimensec: inode.mtime_nsec,
			mtimensec: inode.mtime_nsec,
			ctimensec: inode.mtime_nsec,
			mode: u32::from(inode.mode),
			nlink: inode.nlink,
			uid: inode.uid,
			gid: inode.gid,
			rdev,
			blksize: bsize as u32,
			flags: 0,
		}
	}

	fn entry(&self, inode: &ErofsInode) -> Entry {
		Entry {
			inode: self.to_ino(inode.nid),
			generation: 0,
			attr: self.wire_attr(inode),
			attr_timeout: CACHE_TTL,
			entry_timeout: CACHE_TTL,
		}
	}

	fn resolve_path(&self, path: &Path) -> io::Result<ErofsInode> {
		let mut current = self.inner.root_inode().map_err(erofs_io)?;
		for component in path.components() {
			match component {
				Component::RootDir | Component::CurDir => {}
				Component::Normal(name) => {
					let bytes = name.as_encoded_bytes();
					validate_component(bytes)?;
					current = self.inner.lookup(&current, bytes).map_err(erofs_io)?;
				}
				Component::ParentDir | Component::Prefix(_) => {
					return Err(errno(libc::EINVAL));
				}
			}
		}
		Ok(current)
	}

	fn read_dir_entries(&self, nid: u64, offset: u64, max: usize) -> io::Result<Vec<DirEntry>> {
		let dir = self.inner.read_inode(nid).map_err(erofs_io)?;
		let raw = self.inner.read_dir(&dir).map_err(erofs_io)?;
		let mut out = Vec::new();
		let mut bytes = 0usize;
		for (index, item) in raw
			.into_iter()
			.filter(|entry| entry.name != b"." && entry.name != b"..")
			.enumerate()
			.skip(offset as usize)
		{
			let entry_len = (24 + item.name.len() + 7) & !7;
			if entry_len > max || bytes + entry_len > max {
				break;
			}
			out.push(DirEntry {
				ino: self.to_ino(item.nid),
				offset: (index + 1) as u64,
				type_: map_ftype(item.file_type),
				name: item.name,
			});
			bytes += entry_len;
		}
		Ok(out)
	}
}

impl Fuse for Erofs {
	type Inode = u64;
	type Handle = u64;

	async fn init(&self, capable: u32) -> io::Result<u32> {
		Ok(capable & (FUSE_ASYNC_READ | FUSE_MAX_PAGES))
	}

	async fn lookup(&self, _ctx: &Context, parent: u64, name: &CStr) -> io::Result<Entry> {
		validate_component(name.to_bytes())?;
		let dir = self.inode(parent)?;
		let child = self.inner.lookup(&dir, name.to_bytes()).map_err(erofs_io)?;
		Ok(self.entry(&child))
	}

	async fn forget(&self, _ctx: &Context, _inode: u64, _count: u64) {}

	async fn batch_forget(&self, _ctx: &Context, _requests: Vec<(u64, u64)>) {}

	async fn getattr(
		&self,
		_ctx: &Context,
		inode: u64,
		_handle: Option<u64>,
	) -> io::Result<(Attr, (u64, u32))> {
		let node = self.inode(inode)?;
		Ok((self.wire_attr(&node), CACHE_TTL))
	}

	async fn setattr(
		&self,
		_ctx: &Context,
		_inode: u64,
		_attr: Attr,
		_handle: Option<u64>,
		_valid: u32,
	) -> io::Result<(Attr, (u64, u32))> {
		Err(errno(libc::EROFS))
	}

	async fn readlink(&self, _ctx: &Context, inode: u64) -> io::Result<Vec<u8>> {
		let node = self.inode(inode)?;
		self.inner.read_symlink_target(&node).map_err(erofs_io)
	}

	async fn symlink(
		&self,
		_ctx: &Context,
		_linkname: &CStr,
		_parent: u64,
		_name: &CStr,
	) -> io::Result<Entry> {
		Err(errno(libc::EROFS))
	}

	async fn mknod(
		&self,
		_ctx: &Context,
		_parent: u64,
		_name: &CStr,
		_mode: u32,
		_rdev: u32,
		_umask: u32,
	) -> io::Result<Entry> {
		Err(errno(libc::EROFS))
	}

	async fn mkdir(
		&self,
		_ctx: &Context,
		_parent: u64,
		_name: &CStr,
		_mode: u32,
		_umask: u32,
	) -> io::Result<Entry> {
		Err(errno(libc::EROFS))
	}

	async fn unlink(&self, _ctx: &Context, _parent: u64, _name: &CStr) -> io::Result<()> {
		Err(errno(libc::EROFS))
	}

	async fn rmdir(&self, _ctx: &Context, _parent: u64, _name: &CStr) -> io::Result<()> {
		Err(errno(libc::EROFS))
	}

	async fn rename(
		&self,
		_ctx: &Context,
		_olddir: u64,
		_oldname: &CStr,
		_newdir: u64,
		_newname: &CStr,
		_flags: u32,
	) -> io::Result<()> {
		Err(errno(libc::EROFS))
	}

	async fn link(
		&self,
		_ctx: &Context,
		_inode: u64,
		_newparent: u64,
		_newname: &CStr,
	) -> io::Result<Entry> {
		Err(errno(libc::EROFS))
	}

	async fn open(&self, _ctx: &Context, inode: u64, flags: u32) -> io::Result<(u64, u32)> {
		if flags & O_ACCMODE != O_RDONLY || flags & (O_CREAT | O_TRUNC) != 0 {
			return Err(errno(libc::EROFS));
		}
		let node = self.inode(inode)?;
		if node.is_symlink() {
			return Err(errno(libc::ELOOP));
		}
		if node.is_dir() {
			return Err(errno(libc::EISDIR));
		}
		if !node.is_regular_file() {
			return Err(errno(libc::EPERM));
		}
		let handle = self
			.handles
			.lock()
			.unwrap_or_else(|e| e.into_inner())
			.insert(OpenHandle {
				nid: node.nid,
				directory: false,
			})?;
		Ok((handle, FOPEN_KEEP_CACHE))
	}

	async fn create(
		&self,
		_ctx: &Context,
		_parent: u64,
		_name: &CStr,
		_args: CreateArgs,
	) -> io::Result<(Entry, u64, u32)> {
		Err(errno(libc::EROFS))
	}

	async fn read(
		&self,
		_ctx: &Context,
		_inode: u64,
		handle: u64,
		out: &mut dyn ZeroCopyWriter,
		size: u32,
		offset: u64,
	) -> io::Result<usize> {
		let nid = {
			let table = self.handles.lock().unwrap_or_else(|e| e.into_inner());
			match table.handles.get(&handle) {
				Some(open) if !open.directory => open.nid,
				_ => return Err(errno(libc::EBADF)),
			}
		};
		let node = self.inner.read_inode(nid).map_err(erofs_io)?;
		if offset >= node.size || size == 0 {
			out.written(0)?;
			return Ok(0);
		}
		let avail = (node.size - offset).min(u64::from(size)) as usize;
		let memory = out.memory();
		let mut written = 0usize;
		let mut at = offset;
		for extent in out.extents() {
			let take = extent.len.min(avail - written);
			if take == 0 {
				break;
			}
			let range = memory.resolve(extent.offset as usize, take)?;
			let dst = unsafe { std::slice::from_raw_parts_mut(range.ptr, range.len) };
			self.inner.read_file(&node, at, dst).map_err(erofs_io)?;
			written += take;
			at += take as u64;
			if written == avail {
				break;
			}
		}
		out.written(written)?;
		Ok(written)
	}

	async fn write(
		&self,
		_ctx: &Context,
		_inode: u64,
		_handle: u64,
		_input: &mut dyn ZeroCopyReader,
		_size: u32,
		_offset: u64,
	) -> io::Result<usize> {
		Err(errno(libc::EROFS))
	}

	async fn flush(&self, _ctx: &Context, _inode: u64, handle: u64) -> io::Result<()> {
		let table = self.handles.lock().unwrap_or_else(|e| e.into_inner());
		match table.handles.get(&handle) {
			Some(open) if !open.directory => Ok(()),
			_ => Err(errno(libc::EBADF)),
		}
	}

	async fn fsync(
		&self,
		_ctx: &Context,
		_inode: u64,
		_datasync: bool,
		handle: u64,
	) -> io::Result<()> {
		let table = self.handles.lock().unwrap_or_else(|e| e.into_inner());
		match table.handles.get(&handle) {
			Some(open) if !open.directory => Ok(()),
			_ => Err(errno(libc::EBADF)),
		}
	}

	async fn release(
		&self,
		_ctx: &Context,
		_inode: u64,
		_flags: u32,
		handle: u64,
	) -> io::Result<()> {
		let mut table = self.handles.lock().unwrap_or_else(|e| e.into_inner());
		match table.handles.remove(&handle) {
			Some(open) if !open.directory => Ok(()),
			Some(open) => {
				table.handles.insert(handle, open);
				Err(errno(libc::EBADF))
			}
			None => Err(errno(libc::EBADF)),
		}
	}

	async fn statfs(&self, _ctx: &Context, _inode: u64) -> io::Result<Kstatfs> {
		let sb = self.inner.superblock();
		let bsize = sb.block_size() as u32;
		Ok(Kstatfs {
			blocks: u64::from(sb.blocks),
			bfree: 0,
			bavail: 0,
			files: sb.inos,
			ffree: 0,
			bsize,
			namelen: 255,
			frsize: bsize,
			..Kstatfs::default()
		})
	}

	async fn setxattr(
		&self,
		_ctx: &Context,
		_inode: u64,
		_name: &CStr,
		_value: &[u8],
		_flags: u32,
	) -> io::Result<()> {
		Err(errno(libc::EROFS))
	}

	async fn getxattr(
		&self,
		_ctx: &Context,
		inode: u64,
		name: &CStr,
		size: u32,
	) -> io::Result<GetxattrReply> {
		if !name.to_bytes().starts_with(b"user.") {
			return Err(errno(libc::ENODATA));
		}
		let node = self.inode(inode)?;
		if node.is_symlink() {
			return Err(errno(libc::ENODATA));
		}
		let entries = self.inner.xattrs(&node).map_err(erofs_io)?;
		let (_, value) = entries
			.into_iter()
			.find(|(k, _)| k.as_slice() == name.to_bytes())
			.ok_or_else(|| errno(libc::ENODATA))?;
		if size == 0 {
			Ok(GetxattrReply::Size(value.len() as u32))
		} else if value.len() > size as usize {
			Err(errno(libc::ERANGE))
		} else {
			Ok(GetxattrReply::Value(value))
		}
	}

	async fn listxattr(&self, _ctx: &Context, inode: u64, size: u32) -> io::Result<ListxattrReply> {
		let node = self.inode(inode)?;
		if node.is_symlink() {
			return if size == 0 {
				Ok(ListxattrReply::Size(0))
			} else {
				Ok(ListxattrReply::Names(Vec::new()))
			};
		}
		let entries = self.inner.xattrs(&node).map_err(erofs_io)?;
		let mut names = Vec::new();
		for (key, _) in entries {
			if key.starts_with(b"user.") {
				names.extend_from_slice(&key);
				names.push(0);
			}
		}
		if size == 0 {
			Ok(ListxattrReply::Size(names.len() as u32))
		} else if names.len() > size as usize {
			Err(errno(libc::ERANGE))
		} else {
			Ok(ListxattrReply::Names(names))
		}
	}

	async fn removexattr(&self, _ctx: &Context, _inode: u64, _name: &CStr) -> io::Result<()> {
		Err(errno(libc::EROFS))
	}

	async fn opendir(&self, _ctx: &Context, inode: u64) -> io::Result<u64> {
		let node = self.inode(inode)?;
		if !node.is_dir() {
			return Err(errno(libc::ENOTDIR));
		}
		self.handles
			.lock()
			.unwrap_or_else(|e| e.into_inner())
			.insert(OpenHandle {
				nid: node.nid,
				directory: true,
			})
	}

	async fn readdir(
		&self,
		_ctx: &Context,
		_inode: u64,
		handle: u64,
		size: u32,
		offset: u64,
	) -> io::Result<Vec<DirEntry>> {
		let nid = {
			let table = self.handles.lock().unwrap_or_else(|e| e.into_inner());
			match table.handles.get(&handle) {
				Some(open) if open.directory => open.nid,
				_ => return Err(errno(libc::EBADF)),
			}
		};
		self.read_dir_entries(nid, offset, size as usize)
	}

	async fn readdirplus(
		&self,
		_ctx: &Context,
		_inode: u64,
		handle: u64,
		size: u32,
		offset: u64,
	) -> io::Result<Vec<(Entry, DirentInfo)>> {
		let nid = {
			let table = self.handles.lock().unwrap_or_else(|e| e.into_inner());
			match table.handles.get(&handle) {
				Some(open) if open.directory => open.nid,
				_ => return Err(errno(libc::EBADF)),
			}
		};
		let entries = self.read_dir_entries(nid, offset, size as usize)?;
		let mut out = Vec::with_capacity(entries.len());
		for item in entries {
			let child = self.inode(item.ino)?;
			out.push((
				self.entry(&child),
				DirentInfo {
					ino: item.ino,
					offset: item.offset,
					type_: item.type_,
					name: item.name,
				},
			));
		}
		Ok(out)
	}

	async fn fsyncdir(
		&self,
		_ctx: &Context,
		_inode: u64,
		_datasync: bool,
		handle: u64,
	) -> io::Result<()> {
		let table = self.handles.lock().unwrap_or_else(|e| e.into_inner());
		match table.handles.get(&handle) {
			Some(open) if open.directory => Ok(()),
			_ => Err(errno(libc::EBADF)),
		}
	}

	async fn releasedir(&self, _ctx: &Context, _inode: u64, handle: u64) -> io::Result<()> {
		let mut table = self.handles.lock().unwrap_or_else(|e| e.into_inner());
		match table.handles.remove(&handle) {
			Some(open) if open.directory => Ok(()),
			Some(open) => {
				table.handles.insert(handle, open);
				Err(errno(libc::EBADF))
			}
			None => Err(errno(libc::EBADF)),
		}
	}

	async fn access(&self, ctx: &Context, inode: u64, mask: u32) -> io::Result<()> {
		if mask == 0 {
			return Ok(());
		}
		if mask & 2 != 0 {
			return Err(errno(libc::EROFS));
		}
		let node = self.inode(inode)?;
		let mode = u32::from(node.mode);
		if ctx.uid == 0 {
			if mask & 1 != 0 && !node.is_dir() && mode & 0o111 == 0 {
				return Err(errno(libc::EACCES));
			}
			return Ok(());
		}
		let bits = if ctx.uid == node.uid {
			(mode >> 6) & 0o7
		} else if ctx.gid == node.gid {
			(mode >> 3) & 0o7
		} else {
			mode & 0o7
		};
		if mask & !bits != 0 {
			return Err(errno(libc::EACCES));
		}
		Ok(())
	}
}

impl Volume for Erofs {
	async fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
		let node = self.resolve_path(path)?;
		if node.is_dir() {
			return Err(errno(libc::EISDIR));
		}
		if !node.is_regular_file() {
			return Err(errno(libc::EPERM));
		}
		let len = usize::try_from(node.size).map_err(|_| errno(libc::EFBIG))?;
		let mut buf = vec![0u8; len];
		if len > 0 {
			self.inner.read_file(&node, 0, &mut buf).map_err(erofs_io)?;
		}
		Ok(buf)
	}

	async fn write(&self, _path: &Path, _data: &[u8]) -> io::Result<()> {
		Err(errno(libc::EROFS))
	}

	async fn stat(&self, path: &Path) -> io::Result<Attr> {
		let node = self.resolve_path(path)?;
		Ok(self.wire_attr(&node))
	}

	async fn readlink(&self, path: &Path) -> io::Result<Vec<u8>> {
		let node = self.resolve_path(path)?;
		self.inner.read_symlink_target(&node).map_err(erofs_io)
	}

	async fn symlink(&self, _target: &Path, _link: &Path) -> io::Result<()> {
		Err(errno(libc::EROFS))
	}

	async fn list(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
		let node = self.resolve_path(path)?;
		self.read_dir_entries(node.nid, 0, usize::MAX)
	}

	async fn create_dir(&self, _path: &Path) -> io::Result<()> {
		Err(errno(libc::EROFS))
	}

	async fn create_dir_all(&self, _path: &Path) -> io::Result<()> {
		Err(errno(libc::EROFS))
	}

	async fn remove_file(&self, _path: &Path) -> io::Result<()> {
		Err(errno(libc::EROFS))
	}

	async fn remove_dir(&self, _path: &Path) -> io::Result<()> {
		Err(errno(libc::EROFS))
	}

	async fn remove_all(&self, _path: &Path) -> io::Result<()> {
		Err(errno(libc::EROFS))
	}

	async fn rename(&self, _from: &Path, _to: &Path) -> io::Result<()> {
		Err(errno(libc::EROFS))
	}

	async fn copy(&self, _from: &Path, _to: &Path) -> io::Result<u64> {
		Err(errno(libc::EROFS))
	}
}

fn map_ftype(file_type: u8) -> u32 {
	match file_type {
		ftype::REG_FILE => DT_REG,
		ftype::DIR => DT_DIR,
		ftype::CHRDEV => DT_CHR,
		ftype::BLKDEV => DT_BLK,
		ftype::FIFO => DT_FIFO,
		ftype::SOCK => DT_SOCK,
		ftype::SYMLINK => DT_LNK,
		_ => 0,
	}
}

fn validate_component(name: &[u8]) -> io::Result<()> {
	if name.is_empty() || name == b"." || name == b".." || name.contains(&0) || name.contains(&b'/')
	{
		Err(errno(libc::EINVAL))
	} else {
		Ok(())
	}
}

fn erofs_io(error: ErofsError) -> io::Error {
	match error {
		ErofsError::NotFound => errno(libc::ENOENT),
		ErofsError::NotADirectory => errno(libc::ENOTDIR),
		ErofsError::OutOfRange => errno(libc::EINVAL),
		ErofsError::UnsupportedLayout(_) => errno(libc::EOPNOTSUPP),
		ErofsError::Block(ref block) => errno_from_block(block),
		ErofsError::NotErofs
		| ErofsError::BadSuperblock(_)
		| ErofsError::BadInode(_)
		| ErofsError::BadDirent(_)
		| ErofsError::BadXattr(_) => errno(libc::EIO),
	}
}

fn errno_from_block(error: &fs_core::Error) -> io::Error {
	match error {
		fs_core::Error::Io(io_err) => io::Error::new(io_err.kind(), io_err.to_string()),
		fs_core::Error::ReadOnly => errno(libc::EROFS),
		_ => errno(libc::EIO),
	}
}

fn errno(code: libc::c_int) -> io::Error {
	io::Error::from_raw_os_error(code)
}

#[cfg(test)]
mod tests {
	use std::collections::BTreeMap;
	use std::future::Future;
	use std::path::Path;
	use std::sync::{Arc, Mutex};
	use std::task::{Context as TaskContext, Poll, Waker};

	use api::{Context, Extent, Fuse, GetxattrReply, Memory, MemoryRange, Volume, ZeroCopyWriter};
	use fs_erofs::mkfs::{
		self, DEFAULT_DIR_MODE, DEFAULT_FILE_MODE, DEFAULT_SYMLINK_MODE, Node, NodeMeta, XattrSpec,
	};

	use super::*;

	fn block_on<F: Future>(future: F) -> F::Output {
		let mut future = std::pin::pin!(future);
		let mut cx = TaskContext::from_waker(Waker::noop());
		loop {
			if let Poll::Ready(val) = future.as_mut().poll(&mut cx) {
				return val;
			}
		}
	}

	struct TestMem(Mutex<Vec<u8>>);

	unsafe impl Memory for TestMem {
		fn resolve(&self, offset: usize, len: usize) -> io::Result<MemoryRange> {
			let mut guard = self.0.lock().unwrap();
			if offset.checked_add(len).is_none_or(|end| end > guard.len()) {
				return Err(io::Error::new(io::ErrorKind::InvalidInput, "out of bounds"));
			}
			Ok(MemoryRange {
				ptr: unsafe { guard.as_mut_ptr().add(offset) },
				len,
			})
		}
	}

	struct TestBuf {
		mem: Arc<TestMem>,
		written: usize,
	}

	impl TestBuf {
		fn new(len: usize) -> Self {
			Self {
				mem: Arc::new(TestMem(Mutex::new(vec![0u8; len]))),
				written: 0,
			}
		}

		fn bytes(&self) -> Vec<u8> {
			self.mem.0.lock().unwrap()[..self.written].to_vec()
		}
	}

	impl ZeroCopyWriter for TestBuf {
		fn memory(&self) -> Arc<dyn Memory> {
			self.mem.clone()
		}

		fn extents(&self) -> Vec<Extent> {
			let len = self.mem.0.lock().unwrap().len();
			vec![Extent { offset: 0, len }]
		}

		fn written(&mut self, count: usize) -> io::Result<()> {
			self.written = count;
			Ok(())
		}
	}

	fn sample_erofs() -> Erofs {
		let mut sub_entries = BTreeMap::new();
		sub_entries.insert(
			"nested.txt".to_string(),
			Node::File {
				mode: DEFAULT_FILE_MODE,
				data: b"nested payload".to_vec(),
				meta: NodeMeta::default(),
				xattrs: Vec::new(),
			},
		);

		let mut root_entries = BTreeMap::new();
		root_entries.insert(
			"hello.txt".to_string(),
			Node::File {
				mode: DEFAULT_FILE_MODE,
				data: b"hello erofs".to_vec(),
				meta: NodeMeta::default(),
				xattrs: vec![XattrSpec::new(1, b"tag".to_vec(), b"v1".to_vec())],
			},
		);
		root_entries.insert(
			"link".to_string(),
			Node::Symlink {
				mode: DEFAULT_SYMLINK_MODE,
				target: "hello.txt".to_string(),
				meta: NodeMeta::default(),
				xattrs: Vec::new(),
			},
		);
		root_entries.insert(
			"sub".to_string(),
			Node::Dir {
				mode: DEFAULT_DIR_MODE,
				entries: sub_entries,
				meta: NodeMeta::default(),
				xattrs: Vec::new(),
			},
		);

		let root = Node::Dir {
			mode: DEFAULT_DIR_MODE,
			entries: root_entries,
			meta: NodeMeta::default(),
			xattrs: Vec::new(),
		};
		let image = mkfs::build_image(root, 12).expect("build erofs image");
		Erofs::from_bytes(image).expect("mount erofs")
	}

	#[test]
	fn volume_reads_files_links_and_dirs() {
		let fs = sample_erofs();
		assert_eq!(
			block_on(Volume::read(&fs, Path::new("/hello.txt"))).unwrap(),
			b"hello erofs"
		);
		assert_eq!(
			block_on(Volume::read(&fs, Path::new("sub/nested.txt"))).unwrap(),
			b"nested payload"
		);
		assert_eq!(
			block_on(Volume::readlink(&fs, Path::new("/link"))).unwrap(),
			b"hello.txt"
		);
		assert_eq!(
			block_on(Volume::write(&fs, Path::new("/hello.txt"), b"x"))
				.unwrap_err()
				.raw_os_error(),
			Some(libc::EROFS)
		);
		let mut names: Vec<Vec<u8>> = block_on(fs.list(Path::new("/")))
			.unwrap()
			.into_iter()
			.map(|e| e.name)
			.collect();
		names.sort();
		assert_eq!(
			names,
			vec![b"hello.txt".to_vec(), b"link".to_vec(), b"sub".to_vec()]
		);
	}

	#[test]
	fn fuse_lookup_read_xattr_and_readdir() {
		let fs = sample_erofs();
		let ctx = Context::default();

		let entry = block_on(fs.lookup(&ctx, ROOT_ID, c"hello.txt")).unwrap();
		assert_eq!(entry.attr.size, 11);

		match block_on(fs.getxattr(&ctx, entry.inode, c"user.tag", 16)).unwrap() {
			GetxattrReply::Value(v) => assert_eq!(v, b"v1"),
			GetxattrReply::Size(_) => panic!("expected value"),
		}

		let (fh, _) = block_on(fs.open(&ctx, entry.inode, O_RDONLY)).unwrap();
		let mut out = TestBuf::new(64);
		let n = block_on(Fuse::read(&fs, &ctx, entry.inode, fh, &mut out, 64, 0)).unwrap();
		assert_eq!(n, 11);
		assert_eq!(out.bytes(), b"hello erofs");
		block_on(fs.release(&ctx, entry.inode, 0, fh)).unwrap();

		let dir_fh = block_on(fs.opendir(&ctx, ROOT_ID)).unwrap();
		let entries = block_on(fs.readdir(&ctx, ROOT_ID, dir_fh, 4096, 0)).unwrap();
		assert_eq!(entries.len(), 3);
		block_on(fs.releasedir(&ctx, ROOT_ID, dir_fh)).unwrap();
	}
}
