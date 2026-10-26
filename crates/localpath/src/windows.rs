//! Windows confined passthrough filesystem and its FUSE protocol surface.
//!
//! [`PassthroughFs`] implements [`api::Fuse`], [`api::Volume`], and
//! [`api::Snapshot`] over a preopened root directory handle.
//!
//! Confinement is achieved by construction and identity verification:
//! - Every component is validated (`validate_component`) to reject `.`, `..`,
//!   `/`, `\`, `:`, and NUL bytes.
//! - Handles are opened with `FILE_FLAG_BACKUP_SEMANTICS |
//!   FILE_FLAG_OPEN_REPARSE_POINT` so symbolic links and junctions are never
//!   traversed.
//! - Handle upgrades re-derive the object from its `(parent, name)` locator
//!   and verify `(volume_serial, file_index)` via
//!   `GetFileInformationByHandle` against the pinned node handle.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::abi::{
	FATTR_ATIME, FATTR_ATIME_NOW, FATTR_GID, FATTR_MODE, FATTR_MTIME, FATTR_MTIME_NOW, FATTR_SIZE,
	FATTR_UID, FOPEN_DIRECT_IO, FUSE_ASYNC_READ, FUSE_BIG_WRITES, ROOT_ID,
};
use crate::span::{engine_io, read_exact, read_into, write_into};
use api::{
	Attr, Context, CreateArgs, DirEntry, DirentInfo, Entry, Fuse, GetxattrReply, Kstatfs,
	ListxattrReply, Snapshot, Volume, ZeroCopyReader, ZeroCopyWriter,
};

const NO_CACHE: Timeout = (0, 0);
type Timeout = (u64, u32);

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

const DT_DIR: u32 = 4;
const DT_REG: u32 = 8;
const DT_LNK: u32 = 10;

const O_RDONLY: u32 = 0;
const O_WRONLY: u32 = 1;
const O_RDWR: u32 = 2;
const O_ACCMODE: u32 = 3;
const O_EXCL: u32 = libc::O_EXCL as u32;
const O_TRUNC: u32 = libc::O_TRUNC as u32;
const O_APPEND: u32 = libc::O_APPEND as u32;

const RENAME_NOREPLACE: u32 = 1;

const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

type Inode = u64;
type Handle = u64;

#[repr(C)]
#[derive(Default)]
struct FileTime {
	low_date_time: u32,
	high_date_time: u32,
}

#[repr(C)]
#[derive(Default)]
struct ByHandleFileInformation {
	file_attributes: u32,
	creation_time: FileTime,
	last_access_time: FileTime,
	last_write_time: FileTime,
	volume_serial_number: u32,
	file_size_high: u32,
	file_size_low: u32,
	number_of_links: u32,
	file_index_high: u32,
	file_index_low: u32,
}

unsafe extern "system" {
	fn GetFileInformationByHandle(
		file: *mut std::ffi::c_void,
		info: *mut ByHandleFileInformation,
	) -> i32;

	fn GetFinalPathNameByHandleW(
		file: *mut std::ffi::c_void,
		path: *mut u16,
		char_count: u32,
		flags: u32,
	) -> u32;

	fn SetFileTime(
		file: *mut std::ffi::c_void,
		creation: *const FileTime,
		last_access: *const FileTime,
		last_write: *const FileTime,
	) -> i32;
}

struct Node {
	file: File,
	path: PathBuf,
	parent: Inode,
	name: OsString,
	lookups: u64,
}

struct RawDirEntry {
	inode: Inode,
	offset: u64,
	kind: u32,
	name: Vec<u8>,
}

enum Resource {
	File(completion::File),
	Dir {
		inode: Inode,
		entries: Vec<OsString>,
	},
}

struct SnapshotPool {
	dir: PathBuf,
	next_id: AtomicU64,
}

impl SnapshotPool {
	fn new(dir: File) -> io::Result<Self> {
		if !dir.metadata()?.is_dir() {
			return Err(errno(libc::ENOTDIR));
		}
		let path = handle_path(&dir)?;
		Ok(Self {
			dir: path,
			next_id: AtomicU64::new(1),
		})
	}

	fn allocate_id(&self) -> u64 {
		self.next_id.fetch_add(1, Ordering::Relaxed)
	}
}

pub(crate) struct FsState {
	read_only: bool,
	snapshots: Option<Arc<SnapshotPool>>,
	nodes: HashMap<Inode, Node>,
	identities: HashMap<(u64, u64), Inode>,
	next_inode: Inode,
	handles: HashMap<Handle, Resource>,
	next_handle: Handle,
}

/// A confined host directory tree rooted at a file descriptor opened before
/// any sandbox transition.
pub struct PassthroughFs {
	pub(crate) state: RefCell<FsState>,
}

impl PassthroughFs {
	pub fn new(root: File, read_only: bool) -> io::Result<Self> {
		let state = FsState::new(root, None, read_only)?;
		Ok(Self {
			state: RefCell::new(state),
		})
	}

	pub fn with_snapshots(root: File, snapshots: File, read_only: bool) -> io::Result<Self> {
		let pool = Arc::new(SnapshotPool::new(snapshots)?);
		let state = FsState::new(root, Some(pool), read_only)?;
		Ok(Self {
			state: RefCell::new(state),
		})
	}

	fn open_file(&self, handle: Handle) -> io::Result<completion::File> {
		match self.state.borrow().handles.get(&handle) {
			Some(Resource::File(file)) => Ok(file.clone()),
			_ => Err(errno(libc::EBADF)),
		}
	}

	pub(crate) fn with<R>(&self, f: impl FnOnce(&mut FsState) -> io::Result<R>) -> io::Result<R> {
		f(&mut self.state.borrow_mut())
	}
}

impl FsState {
	fn new(root: File, snapshots: Option<Arc<SnapshotPool>>, read_only: bool) -> io::Result<Self> {
		let metadata = root.metadata()?;
		if !metadata.is_dir() {
			return Err(errno(libc::ENOTDIR));
		}
		let root_path = handle_path(&root)?;
		let identity = file_identity(&root)?;
		let root_node = inspect_path(&root_path)?;
		let mut nodes = HashMap::new();
		nodes.insert(
			ROOT_ID,
			Node {
				file: root_node,
				path: root_path,
				parent: ROOT_ID,
				name: OsString::from("."),
				lookups: 1,
			},
		);
		let mut identities = HashMap::new();
		identities.insert(identity, ROOT_ID);
		Ok(Self {
			read_only,
			snapshots,
			nodes,
			identities,
			next_inode: ROOT_ID + 1,
			handles: HashMap::new(),
			next_handle: 1,
		})
	}

	fn node(&self, inode: Inode) -> io::Result<&Node> {
		self.nodes.get(&inode).ok_or_else(stale)
	}

	fn writable(&self) -> io::Result<()> {
		if self.read_only {
			Err(errno(libc::EROFS))
		} else {
			Ok(())
		}
	}

	fn allocate_handle(&mut self, resource: Resource) -> io::Result<Handle> {
		let handle = self.next_handle;
		self.next_handle = self
			.next_handle
			.checked_add(1)
			.ok_or_else(|| errno(libc::EOVERFLOW))?;
		self.handles.insert(handle, resource);
		Ok(handle)
	}

	fn intern(
		&mut self,
		parent: Inode,
		name: OsString,
		path: PathBuf,
		file: File,
		lookups: u64,
	) -> io::Result<(Inode, fs::Metadata)> {
		let metadata = file.metadata()?;
		let identity = file_identity(&file)?;
		if let Some(&inode) = self.identities.get(&identity)
			&& let Some(node) = self.nodes.get_mut(&inode)
		{
			node.lookups = node.lookups.saturating_add(lookups);
			return Ok((inode, metadata));
		}
		let inode = self.next_inode;
		self.next_inode = self
			.next_inode
			.checked_add(1)
			.ok_or_else(|| errno(libc::EOVERFLOW))?;
		self.nodes.insert(
			inode,
			Node {
				file,
				path,
				parent,
				name,
				lookups,
			},
		);
		self.identities.insert(identity, inode);
		Ok((inode, metadata))
	}

	fn child_path(&self, parent: Inode, name: &[u8]) -> io::Result<(OsString, PathBuf)> {
		validate_component(name)?;
		let parent_node = self.node(parent)?;
		let parent_meta = parent_node.file.metadata()?;
		if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
			return Err(errno(libc::ENOTDIR));
		}
		let os_name = bytes_to_os(name)?;
		let joined = parent_node.path.join(&os_name);
		Ok((os_name, joined))
	}

	fn lookup_child(&mut self, parent: Inode, name: &[u8]) -> io::Result<(Inode, fs::Metadata)> {
		let (os_name, path) = self.child_path(parent, name)?;
		let file = inspect_path(&path)?;
		self.intern(parent, os_name, path, file, 1)
	}

	fn wire_attr(inode: Inode, metadata: &fs::Metadata, nlink: u32) -> Attr {
		let file_type = if metadata.file_type().is_symlink() {
			S_IFLNK
		} else if metadata.is_dir() {
			S_IFDIR
		} else {
			S_IFREG
		};
		let readonly = metadata.file_attributes() & FILE_ATTRIBUTE_READONLY != 0;
		let perm = if metadata.is_dir() {
			if readonly { 0o555 } else { 0o755 }
		} else if readonly {
			0o444
		} else {
			0o644
		};
		let (atime, atimensec) = win_epoch_to_unix(metadata.last_access_time());
		let (mtime, mtimensec) = win_epoch_to_unix(metadata.last_write_time());
		let (ctime, ctimensec) = win_epoch_to_unix(metadata.creation_time());
		Attr {
			ino: inode,
			size: metadata.file_size(),
			blocks: metadata.file_size().div_ceil(512),
			atime,
			mtime,
			ctime,
			atimensec,
			mtimensec,
			ctimensec,
			mode: file_type | perm,
			nlink,
			uid: 0,
			gid: 0,
			rdev: 0,
			blksize: 4096,
			flags: 0,
		}
	}

	fn entry(&self, inode: Inode, metadata: &fs::Metadata) -> io::Result<Entry> {
		let nlink = self
			.node(inode)
			.and_then(|n| file_nlink(&n.file))
			.unwrap_or(1);
		Ok(Entry {
			inode,
			generation: 0,
			attr: Self::wire_attr(inode, metadata, nlink),
			attr_timeout: NO_CACHE,
			entry_timeout: NO_CACHE,
		})
	}

	fn reopen(&self, inode: Inode, write: bool, append: bool, truncate: bool) -> io::Result<File> {
		let node = self.node(inode)?;
		let meta = node.file.metadata()?;
		if meta.file_type().is_symlink() {
			return Err(errno(libc::ELOOP));
		}
		if !meta.is_file() && !meta.is_dir() {
			return Err(errno(libc::EPERM));
		}
		let pinned = file_identity(&node.file)?;
		let parent = self.node(node.parent)?;
		let path = if inode == ROOT_ID {
			node.path.clone()
		} else {
			parent.path.join(&node.name)
		};
		let reopened = OpenOptions::new()
			.read(true)
			.write(write)
			.append(append)
			.truncate(truncate)
			.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
			.open(path)?;
		if file_identity(&reopened)? != pinned {
			return Err(stale());
		}
		Ok(reopened)
	}

	fn lookup(&mut self, _: &Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
		let (inode, metadata) = self.lookup_child(parent, name.to_bytes())?;
		self.entry(inode, &metadata)
	}

	fn getattr(&self, _: &Context, inode: Inode) -> io::Result<Attr> {
		let node = self.node(inode)?;
		let metadata = node.file.metadata()?;
		let nlink = file_nlink(&node.file).unwrap_or(1);
		Ok(Self::wire_attr(inode, &metadata, nlink))
	}

	fn setattr(&mut self, ctx: &Context, inode: Inode, attr: Attr, valid: u32) -> io::Result<Attr> {
		self.writable()?;
		if valid & (FATTR_ATIME | FATTR_ATIME_NOW) == (FATTR_ATIME | FATTR_ATIME_NOW)
			|| valid & (FATTR_MTIME | FATTR_MTIME_NOW) == (FATTR_MTIME | FATTR_MTIME_NOW)
		{
			return Err(errno(libc::EINVAL));
		}
		let needs_write = valid
			& (FATTR_SIZE | FATTR_ATIME | FATTR_MTIME | FATTR_ATIME_NOW | FATTR_MTIME_NOW)
			!= 0;
		let file = self.reopen(inode, needs_write, false, false)?;
		if valid & FATTR_MODE != 0 {
			let mut perms = file.metadata()?.permissions();
			perms.set_readonly(attr.mode & 0o222 == 0);
			file.set_permissions(perms)?;
		}
		if valid & FATTR_SIZE != 0 {
			file.set_len(attr.size)?;
		}
		if valid & (FATTR_ATIME | FATTR_MTIME | FATTR_ATIME_NOW | FATTR_MTIME_NOW) != 0 {
			let atime = if valid & FATTR_ATIME != 0 {
				Some(unix_to_filetime(attr.atime, attr.atimensec))
			} else {
				None
			};
			let mtime = if valid & FATTR_MTIME != 0 {
				Some(unix_to_filetime(attr.mtime, attr.mtimensec))
			} else {
				None
			};
			set_file_times(&file, atime.as_ref(), mtime.as_ref())?;
		}
		let _ = (FATTR_UID, FATTR_GID);
		self.getattr(ctx, inode)
	}

	fn open(&mut self, _: &Context, inode: Inode, flags: u32) -> io::Result<Handle> {
		let access = flags & O_ACCMODE;
		let write = match access {
			O_RDONLY => false,
			O_WRONLY | O_RDWR => true,
			_ => return Err(errno(libc::EINVAL)),
		};
		if self.read_only && (write || flags & O_TRUNC != 0) {
			return Err(errno(libc::EROFS));
		}
		let file = self.reopen(inode, write, flags & O_APPEND != 0, flags & O_TRUNC != 0)?;
		self.allocate_handle(Resource::File(completion::File::new(file)))
	}

	fn create(
		&mut self,
		_: &Context,
		parent: Inode,
		name: &CStr,
		flags: u32,
		mode: u32,
		umask: u32,
	) -> io::Result<(Entry, Handle)> {
		self.writable()?;
		let (_, path) = self.child_path(parent, name.to_bytes())?;
		let file = OpenOptions::new()
			.read(true)
			.write(true)
			.create(flags & O_EXCL == 0)
			.create_new(flags & O_EXCL != 0)
			.truncate(flags & O_TRUNC != 0)
			.append(flags & O_APPEND != 0)
			.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
			.open(&path)?;
		if (mode & !umask) & 0o222 == 0 {
			let mut perms = file.metadata()?.permissions();
			perms.set_readonly(true);
			drop(file.set_permissions(perms));
		}
		let (inode, metadata) = self.lookup_child(parent, name.to_bytes())?;
		let entry = self.entry(inode, &metadata)?;
		let handle = self.allocate_handle(Resource::File(completion::File::new(file)))?;
		Ok((entry, handle))
	}

	fn mkdir(&mut self, _: &Context, parent: Inode, name: &CStr, _mode: u32) -> io::Result<Entry> {
		self.writable()?;
		let (_, path) = self.child_path(parent, name.to_bytes())?;
		fs::create_dir(&path)?;
		let (inode, metadata) = self.lookup_child(parent, name.to_bytes())?;
		self.entry(inode, &metadata)
	}

	fn mknod(
		&mut self,
		ctx: &Context,
		parent: Inode,
		name: &CStr,
		mode: u32,
		_rdev: u32,
	) -> io::Result<Entry> {
		self.writable()?;
		if mode & S_IFMT != S_IFREG {
			return Err(errno(libc::EPERM));
		}
		let (_, path) = self.child_path(parent, name.to_bytes())?;
		drop(
			OpenOptions::new()
				.write(true)
				.create_new(true)
				.open(&path)?,
		);
		self.lookup(ctx, parent, name)
	}

	fn unlink(
		&mut self,
		_: &Context,
		parent: Inode,
		name: &CStr,
		directory: bool,
	) -> io::Result<()> {
		self.writable()?;
		let (_, path) = self.child_path(parent, name.to_bytes())?;
		if directory {
			fs::remove_dir(path)
		} else {
			fs::remove_file(path)
		}
	}

	fn rename(
		&mut self,
		_: &Context,
		old_parent: Inode,
		old_name: &CStr,
		new_parent: Inode,
		new_name: &CStr,
		flags: u32,
	) -> io::Result<()> {
		self.writable()?;
		if flags & !RENAME_NOREPLACE != 0 {
			return Err(errno(libc::EINVAL));
		}
		let (_, old_path) = self.child_path(old_parent, old_name.to_bytes())?;
		let (_, new_path) = self.child_path(new_parent, new_name.to_bytes())?;
		if flags & RENAME_NOREPLACE != 0 && new_path.symlink_metadata().is_ok() {
			return Err(errno(libc::EEXIST));
		}
		fs::rename(old_path, new_path)
	}

	fn link(&mut self, _: &Context, inode: Inode, parent: Inode, name: &CStr) -> io::Result<Entry> {
		self.writable()?;
		let src_path = self.node(inode)?.path.clone();
		let (_, dst_path) = self.child_path(parent, name.to_bytes())?;
		fs::hard_link(src_path, dst_path)?;
		let (child_ino, metadata) = self.lookup_child(parent, name.to_bytes())?;
		self.entry(child_ino, &metadata)
	}

	fn symlink(
		&mut self,
		_: &Context,
		parent: Inode,
		name: &CStr,
		target: &CStr,
	) -> io::Result<Entry> {
		self.writable()?;
		let (_, dst_path) = self.child_path(parent, name.to_bytes())?;
		let target_os = bytes_to_os(target.to_bytes())?;
		std::os::windows::fs::symlink_file(&target_os, &dst_path)?;
		let (inode, metadata) = self.lookup_child(parent, name.to_bytes())?;
		self.entry(inode, &metadata)
	}

	fn read_link(&self, inode: Inode) -> io::Result<Vec<u8>> {
		let path = &self.node(inode)?.path;
		let target = fs::read_link(path)?;
		Ok(target.as_os_str().as_encoded_bytes().to_vec())
	}

	fn release(&mut self, handle: Handle) -> io::Result<()> {
		match self.handles.remove(&handle) {
			Some(Resource::File(_)) => Ok(()),
			Some(resource) => {
				self.handles.insert(handle, resource);
				Err(errno(libc::EBADF))
			}
			None => Err(errno(libc::EBADF)),
		}
	}

	fn flush_file(&self, handle: Handle) -> io::Result<completion::File> {
		match self.handles.get(&handle) {
			Some(Resource::File(file)) => Ok(file.clone()),
			_ => Err(errno(libc::EBADF)),
		}
	}

	fn sync_file(&self, handle: Handle, directory: bool) -> io::Result<completion::File> {
		match (directory, self.handles.get(&handle)) {
			(false, Some(Resource::File(file))) => Ok(file.clone()),
			_ => Err(errno(libc::EBADF)),
		}
	}

	fn open_dir(&mut self, _: &Context, inode: Inode) -> io::Result<Handle> {
		let path = &self.node(inode)?.path;
		let mut entries = Vec::new();
		for item in fs::read_dir(path)? {
			let item = item?;
			entries.push(item.file_name());
		}
		self.allocate_handle(Resource::Dir { inode, entries })
	}

	fn read_dir(
		&mut self,
		handle: Handle,
		offset: u64,
		max: usize,
	) -> io::Result<Vec<RawDirEntry>> {
		let (directory, names) = match self.handles.get(&handle) {
			Some(Resource::Dir { inode, entries }) => (*inode, entries.clone()),
			_ => return Err(errno(libc::EBADF)),
		};
		let mut out = Vec::new();
		let mut bytes = 0usize;
		for (idx, os_name) in names.into_iter().enumerate().skip(offset as usize) {
			let name = os_name.as_encoded_bytes().to_vec();
			if validate_component(&name).is_err() {
				continue;
			}
			let entry_len = (24 + name.len() + 7) & !7;
			if entry_len > max || bytes + entry_len > max {
				break;
			}
			let Ok((child_ino, meta)) = self.lookup_child(directory, &name) else {
				continue;
			};
			let kind = if meta.file_type().is_symlink() {
				DT_LNK
			} else if meta.is_dir() {
				DT_DIR
			} else {
				DT_REG
			};
			out.push(RawDirEntry {
				inode: child_ino,
				offset: (idx + 1) as u64,
				kind,
				name,
			});
			bytes += entry_len;
		}
		Ok(out)
	}

	fn release_dir(&mut self, handle: Handle) -> io::Result<()> {
		match self.handles.remove(&handle) {
			Some(Resource::Dir { .. }) => Ok(()),
			Some(resource) => {
				self.handles.insert(handle, resource);
				Err(errno(libc::EBADF))
			}
			None => Err(errno(libc::EBADF)),
		}
	}

	fn access(&self, _: &Context, inode: Inode, mask: u32) -> io::Result<()> {
		if mask == 0 {
			return Ok(());
		}
		if self.read_only && mask & 2 != 0 {
			return Err(errno(libc::EROFS));
		}
		let meta = self.node(inode)?.file.metadata()?;
		if mask & 2 != 0 && meta.file_attributes() & FILE_ATTRIBUTE_READONLY != 0 {
			return Err(errno(libc::EACCES));
		}
		Ok(())
	}

	fn forget(&mut self, inode: Inode, count: u64) {
		if inode == ROOT_ID {
			return;
		}
		let remove = match self.nodes.get_mut(&inode) {
			Some(node) => {
				node.lookups = node.lookups.saturating_sub(count);
				node.lookups == 0
			}
			None => false,
		};
		if remove && self.nodes.remove(&inode).is_some() {
			self.identities.retain(|_, mapped| *mapped != inode);
		}
	}

	fn batch_forget(&mut self, requests: Vec<(Inode, u64)>) {
		for (inode, count) in requests {
			self.forget(inode, count);
		}
	}

	fn pool(&self) -> io::Result<&Arc<SnapshotPool>> {
		self.snapshots
			.as_ref()
			.ok_or_else(|| errno(libc::EOPNOTSUPP))
	}

	fn snapshot(&self) -> io::Result<u64> {
		let pool = Arc::clone(self.pool()?);
		let src = &self.node(ROOT_ID)?.path;
		let id = pool.allocate_id();
		let dst = pool.dir.join(format!("snap-{id}"));
		fs::create_dir(&dst)?;
		if let Err(err) = clone_dir_contents(src, &dst) {
			drop(fs::remove_dir_all(&dst));
			return Err(err);
		}
		Ok(id)
	}

	fn branch(&self, id: u64) -> io::Result<PassthroughFs> {
		let pool = Arc::clone(self.pool()?);
		let snap_path = pool.dir.join(format!("snap-{id}"));
		if !snap_path.is_dir() {
			return Err(errno(libc::ENOENT));
		}
		let work_id = pool.allocate_id();
		let work_path = pool.dir.join(format!("work-{work_id}"));
		fs::create_dir(&work_path)?;
		if let Err(err) = clone_dir_contents(&snap_path, &work_path) {
			drop(fs::remove_dir_all(&work_path));
			return Err(err);
		}
		let work_root = inspect_path(&work_path)?;
		let state = FsState::new(work_root, Some(pool), false)?;
		Ok(PassthroughFs {
			state: RefCell::new(state),
		})
	}

	fn restore(&mut self, id: u64) -> io::Result<()> {
		self.writable()?;
		let pool = Arc::clone(self.pool()?);
		let snap_path = pool.dir.join(format!("snap-{id}"));
		if !snap_path.is_dir() {
			return Err(errno(libc::ENOENT));
		}
		let root_path = self.node(ROOT_ID)?.path.clone();
		clear_dir_contents(&root_path)?;
		clone_dir_contents(&snap_path, &root_path)?;
		let root_node = self.nodes.remove(&ROOT_ID).expect("root node exists");
		let identity = file_identity(&root_node.file)?;
		self.nodes.clear();
		self.identities.clear();
		self.nodes.insert(
			ROOT_ID,
			Node {
				file: root_node.file,
				path: root_node.path,
				parent: ROOT_ID,
				name: root_node.name,
				lookups: 1,
			},
		);
		self.identities.insert(identity, ROOT_ID);
		Ok(())
	}

	fn delete_snapshot(&self, id: u64) -> io::Result<()> {
		let pool = Arc::clone(self.pool()?);
		let snap_path = pool.dir.join(format!("snap-{id}"));
		if !snap_path.exists() {
			return Err(errno(libc::ENOENT));
		}
		fs::remove_dir_all(snap_path)
	}

	fn resolve_volume_path(&self, path: &Path) -> io::Result<PathBuf> {
		let mut current = self.node(ROOT_ID)?.path.clone();
		let parts = split_path(path)?;
		for (idx, part) in parts.iter().enumerate() {
			if idx > 0 {
				let meta = fs::symlink_metadata(&current)?;
				if meta.file_type().is_symlink() || !meta.is_dir() {
					return Err(errno(libc::ENOTDIR));
				}
			}
			current.push(part);
		}
		Ok(current)
	}

	fn open_volume_read(&self, path: &Path) -> io::Result<(completion::File, usize)> {
		let resolved = self.resolve_volume_path(path)?;
		let meta = fs::symlink_metadata(&resolved)?;
		if meta.file_type().is_symlink() {
			return Err(errno(libc::ELOOP));
		}
		if meta.is_dir() {
			return Err(errno(libc::EISDIR));
		}
		let file = OpenOptions::new()
			.read(true)
			.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
			.open(resolved)?;
		let len = usize::try_from(meta.file_size()).map_err(|_| errno(libc::EFBIG))?;
		Ok((completion::File::new(file), len))
	}

	fn open_volume_write(&self, path: &Path) -> io::Result<completion::File> {
		self.writable()?;
		let resolved = self.resolve_volume_path(path)?;
		let file = OpenOptions::new()
			.write(true)
			.create(true)
			.truncate(true)
			.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
			.open(resolved)?;
		Ok(completion::File::new(file))
	}
}

impl Fuse for PassthroughFs {
	type Inode = u64;
	type Handle = u64;

	async fn init(&self, capable: u32) -> io::Result<u32> {
		Ok(capable & (FUSE_ASYNC_READ | FUSE_BIG_WRITES))
	}

	async fn lookup(&self, ctx: &Context, parent: u64, name: &CStr) -> io::Result<Entry> {
		self.with(|state| state.lookup(ctx, parent, name))
	}

	async fn forget(&self, _ctx: &Context, inode: u64, count: u64) {
		drop(self.with(|state| {
			state.forget(inode, count);
			Ok(())
		}));
	}

	async fn batch_forget(&self, _ctx: &Context, requests: Vec<(u64, u64)>) {
		drop(self.with(|state| {
			state.batch_forget(requests);
			Ok(())
		}));
	}

	async fn getattr(
		&self,
		ctx: &Context,
		inode: u64,
		_handle: Option<u64>,
	) -> io::Result<(Attr, Timeout)> {
		self.with(|state| state.getattr(ctx, inode).map(|attr| (attr, NO_CACHE)))
	}

	async fn setattr(
		&self,
		ctx: &Context,
		inode: u64,
		attr: Attr,
		_handle: Option<u64>,
		valid: u32,
	) -> io::Result<(Attr, Timeout)> {
		self.with(|state| {
			state
				.setattr(ctx, inode, attr, valid)
				.map(|attr| (attr, NO_CACHE))
		})
	}

	async fn readlink(&self, _ctx: &Context, inode: u64) -> io::Result<Vec<u8>> {
		self.with(|state| state.read_link(inode))
	}

	async fn symlink(
		&self,
		ctx: &Context,
		linkname: &CStr,
		parent: u64,
		name: &CStr,
	) -> io::Result<Entry> {
		self.with(|state| state.symlink(ctx, parent, name, linkname))
	}

	async fn mknod(
		&self,
		ctx: &Context,
		parent: u64,
		name: &CStr,
		mode: u32,
		rdev: u32,
		_umask: u32,
	) -> io::Result<Entry> {
		self.with(|state| state.mknod(ctx, parent, name, mode, rdev))
	}

	async fn mkdir(
		&self,
		ctx: &Context,
		parent: u64,
		name: &CStr,
		mode: u32,
		_umask: u32,
	) -> io::Result<Entry> {
		self.with(|state| state.mkdir(ctx, parent, name, mode))
	}

	async fn unlink(&self, ctx: &Context, parent: u64, name: &CStr) -> io::Result<()> {
		self.with(|state| state.unlink(ctx, parent, name, false))
	}

	async fn rmdir(&self, ctx: &Context, parent: u64, name: &CStr) -> io::Result<()> {
		self.with(|state| state.unlink(ctx, parent, name, true))
	}

	async fn rename(
		&self,
		ctx: &Context,
		olddir: u64,
		oldname: &CStr,
		newdir: u64,
		newname: &CStr,
		flags: u32,
	) -> io::Result<()> {
		self.with(|state| state.rename(ctx, olddir, oldname, newdir, newname, flags))
	}

	async fn link(
		&self,
		ctx: &Context,
		inode: u64,
		newparent: u64,
		newname: &CStr,
	) -> io::Result<Entry> {
		self.with(|state| state.link(ctx, inode, newparent, newname))
	}

	async fn open(&self, ctx: &Context, inode: u64, flags: u32) -> io::Result<(u64, u32)> {
		self.with(|state| {
			state
				.open(ctx, inode, flags)
				.map(|handle| (handle, FOPEN_DIRECT_IO))
		})
	}

	async fn create(
		&self,
		ctx: &Context,
		parent: u64,
		name: &CStr,
		args: CreateArgs,
	) -> io::Result<(Entry, u64, u32)> {
		self.with(|state| {
			state
				.create(ctx, parent, name, args.flags, args.mode, args.umask)
				.map(|(entry, handle)| (entry, handle, FOPEN_DIRECT_IO))
		})
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
		let file = self.open_file(handle)?;
		let written = read_into(&file, out, size as usize, offset).await?;
		out.written(written)?;
		Ok(written)
	}

	async fn write(
		&self,
		_ctx: &Context,
		_inode: u64,
		handle: u64,
		input: &mut dyn ZeroCopyReader,
		size: u32,
		offset: u64,
	) -> io::Result<usize> {
		if self.state.borrow().read_only {
			return Err(errno(libc::EROFS));
		}
		let file = self.open_file(handle)?;
		write_into(&file, input, size as usize, offset).await
	}

	async fn flush(&self, _ctx: &Context, _inode: u64, handle: u64) -> io::Result<()> {
		let file = self.with(|state| state.flush_file(handle))?;
		file.flush().await.map_err(engine_io)
	}

	async fn fsync(
		&self,
		_ctx: &Context,
		_inode: u64,
		_datasync: bool,
		handle: u64,
	) -> io::Result<()> {
		let file = self.with(|state| state.sync_file(handle, false))?;
		file.sync().await.map_err(engine_io)
	}

	async fn release(
		&self,
		_ctx: &Context,
		_inode: u64,
		_flags: u32,
		handle: u64,
	) -> io::Result<()> {
		self.with(|state| state.release(handle))
	}

	async fn statfs(&self, _ctx: &Context, _inode: u64) -> io::Result<Kstatfs> {
		Ok(Kstatfs {
			bsize: 4096,
			namelen: 255,
			frsize: 4096,
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
		Err(errno(libc::EOPNOTSUPP))
	}

	async fn getxattr(
		&self,
		_ctx: &Context,
		_inode: u64,
		_name: &CStr,
		_size: u32,
	) -> io::Result<GetxattrReply> {
		Err(errno(libc::ENODATA))
	}

	async fn listxattr(
		&self,
		_ctx: &Context,
		_inode: u64,
		size: u32,
	) -> io::Result<ListxattrReply> {
		if size == 0 {
			Ok(ListxattrReply::Size(0))
		} else {
			Ok(ListxattrReply::Names(Vec::new()))
		}
	}

	async fn removexattr(&self, _ctx: &Context, _inode: u64, _name: &CStr) -> io::Result<()> {
		Err(errno(libc::EOPNOTSUPP))
	}

	async fn opendir(&self, ctx: &Context, inode: u64) -> io::Result<u64> {
		self.with(|state| state.open_dir(ctx, inode))
	}

	async fn readdir(
		&self,
		_ctx: &Context,
		_inode: u64,
		handle: u64,
		size: u32,
		offset: u64,
	) -> io::Result<Vec<DirEntry>> {
		self.with(|state| {
			let entries = state.read_dir(handle, offset, size as usize)?;
			Ok(entries
				.into_iter()
				.map(|e| DirEntry {
					ino: e.inode,
					offset: e.offset,
					type_: e.kind,
					name: e.name,
				})
				.collect())
		})
	}

	async fn readdirplus(
		&self,
		_ctx: &Context,
		inode: u64,
		handle: u64,
		size: u32,
		offset: u64,
	) -> io::Result<Vec<(Entry, DirentInfo)>> {
		self.with(|state| {
			let entries = state.read_dir(handle, offset, size as usize)?;
			let mut out = Vec::with_capacity(entries.len());
			for entry in entries {
				let Ok((child_ino, meta)) = state.lookup_child(inode, &entry.name) else {
					continue;
				};
				let full = state.entry(child_ino, &meta)?;
				out.push((
					full,
					DirentInfo {
						ino: entry.inode,
						offset: entry.offset,
						type_: entry.kind,
						name: entry.name,
					},
				));
			}
			Ok(out)
		})
	}

	async fn fsyncdir(
		&self,
		_ctx: &Context,
		_inode: u64,
		_datasync: bool,
		_handle: u64,
	) -> io::Result<()> {
		Ok(())
	}

	async fn releasedir(&self, _ctx: &Context, _inode: u64, handle: u64) -> io::Result<()> {
		self.with(|state| state.release_dir(handle))
	}

	async fn access(&self, ctx: &Context, inode: u64, mask: u32) -> io::Result<()> {
		self.with(|state| state.access(ctx, inode, mask))
	}
}

impl Snapshot for PassthroughFs {
	type Id = u64;

	async fn snapshot(&self) -> io::Result<u64> {
		self.with(|state| state.snapshot())
	}

	async fn branch(&self, id: &u64) -> io::Result<Self> {
		self.with(|state| state.branch(*id))
	}

	async fn restore(&self, id: &u64) -> io::Result<()> {
		self.with(|state| state.restore(*id))
	}

	async fn delete(&self, id: &u64) -> io::Result<()> {
		self.with(|state| state.delete_snapshot(*id))
	}
}

impl Volume for PassthroughFs {
	async fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
		let (file, len) = self.with(|state| state.open_volume_read(path))?;
		if len == 0 {
			return Ok(Vec::new());
		}
		let mut buffer = completion::Buffer::zeroed(len);
		let count = read_exact(&file, buffer.clone(), 0).await?;
		Ok(buffer.get_mut().expect("the read landed")[..count].to_vec())
	}

	async fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
		let file = self.with(|state| state.open_volume_write(path))?;
		if data.is_empty() {
			return Ok(());
		}
		let buffer = completion::Buffer::from(data.to_vec());
		file.write_all_at(buffer, 0)
			.await
			.map(|_| ())
			.map_err(engine_io)
	}

	async fn stat(&self, path: &Path) -> io::Result<Attr> {
		self.with(|state| {
			let resolved = state.resolve_volume_path(path)?;
			let file = inspect_path(&resolved)?;
			let meta = file.metadata()?;
			let (_, ino) = file_identity(&file)?;
			let nlink = file_nlink(&file).unwrap_or(1);
			Ok(FsState::wire_attr(ino, &meta, nlink))
		})
	}

	async fn readlink(&self, path: &Path) -> io::Result<Vec<u8>> {
		self.with(|state| {
			let resolved = state.resolve_volume_path(path)?;
			let target = fs::read_link(resolved)?;
			Ok(target.as_os_str().as_encoded_bytes().to_vec())
		})
	}

	async fn symlink(&self, target: &Path, link: &Path) -> io::Result<()> {
		self.with(|state| {
			state.writable()?;
			let resolved = state.resolve_volume_path(link)?;
			std::os::windows::fs::symlink_file(target, resolved)
		})
	}

	async fn list(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
		self.with(|state| {
			let resolved = state.resolve_volume_path(path)?;
			let mut out = Vec::new();
			let mut offset = 1u64;
			for item in fs::read_dir(resolved)? {
				let item = item?;
				let name = item.file_name().as_encoded_bytes().to_vec();
				if validate_component(&name).is_err() {
					continue;
				}
				let meta = item.metadata()?;
				let kind = if meta.file_type().is_symlink() {
					DT_LNK
				} else if meta.is_dir() {
					DT_DIR
				} else {
					DT_REG
				};
				out.push(DirEntry {
					ino: offset,
					offset,
					type_: kind,
					name,
				});
				offset += 1;
			}
			Ok(out)
		})
	}

	async fn create_dir(&self, path: &Path) -> io::Result<()> {
		self.with(|state| {
			state.writable()?;
			let resolved = state.resolve_volume_path(path)?;
			fs::create_dir(resolved)
		})
	}

	async fn create_dir_all(&self, path: &Path) -> io::Result<()> {
		self.with(|state| {
			state.writable()?;
			let mut current = state.node(ROOT_ID)?.path.clone();
			for part in split_path(path)? {
				current.push(part);
				if !current.exists() {
					fs::create_dir(&current)?;
				} else if !fs::symlink_metadata(&current)?.is_dir() {
					return Err(errno(libc::ENOTDIR));
				}
			}
			Ok(())
		})
	}

	async fn remove_file(&self, path: &Path) -> io::Result<()> {
		self.with(|state| {
			state.writable()?;
			let resolved = state.resolve_volume_path(path)?;
			fs::remove_file(resolved)
		})
	}

	async fn remove_dir(&self, path: &Path) -> io::Result<()> {
		self.with(|state| {
			state.writable()?;
			let resolved = state.resolve_volume_path(path)?;
			fs::remove_dir(resolved)
		})
	}

	async fn remove_all(&self, path: &Path) -> io::Result<()> {
		self.with(|state| {
			state.writable()?;
			let parts = split_path(path)?;
			if parts.is_empty() {
				let root_path = state.node(ROOT_ID)?.path.clone();
				return clear_dir_contents(&root_path);
			}
			let resolved = state.resolve_volume_path(path)?;
			remove_path_tree(&resolved)
		})
	}

	async fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
		self.with(|state| {
			state.writable()?;
			let src = state.resolve_volume_path(from)?;
			let dst = state.resolve_volume_path(to)?;
			fs::rename(src, dst)
		})
	}

	async fn copy(&self, from: &Path, to: &Path) -> io::Result<u64> {
		self.with(|state| {
			state.writable()?;
			let src = state.resolve_volume_path(from)?;
			let dst = state.resolve_volume_path(to)?;
			fs::copy(src, dst)
		})
	}
}

pub(crate) fn validate_component(name: &[u8]) -> io::Result<()> {
	if name.is_empty()
		|| name == b"."
		|| name == b".."
		|| name.contains(&0)
		|| name.contains(&b'/')
		|| name.contains(&b'\\')
		|| name.contains(&b':')
	{
		Err(errno(libc::EINVAL))
	} else {
		Ok(())
	}
}

fn split_path(path: &Path) -> io::Result<Vec<OsString>> {
	let mut parts = Vec::new();
	for component in path.components() {
		match component {
			Component::RootDir | Component::CurDir => {}
			Component::Normal(name) => {
				validate_component(name.as_encoded_bytes())?;
				parts.push(name.to_os_string());
			}
			Component::ParentDir | Component::Prefix(_) => {
				return Err(errno(libc::EINVAL));
			}
		}
	}
	Ok(parts)
}

fn bytes_to_os(bytes: &[u8]) -> io::Result<OsString> {
	let s = std::str::from_utf8(bytes).map_err(|_| errno(libc::EINVAL))?;
	Ok(OsString::from(s))
}

fn inspect_path(path: &Path) -> io::Result<File> {
	OpenOptions::new()
		.read(true)
		.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
		.open(path)
}

fn file_info(file: &File) -> io::Result<ByHandleFileInformation> {
	let mut info = ByHandleFileInformation::default();
	let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) };
	if ok == 0 {
		Err(io::Error::last_os_error())
	} else {
		Ok(info)
	}
}

fn file_identity(file: &File) -> io::Result<(u64, u64)> {
	let info = file_info(file)?;
	let ino = (u64::from(info.file_index_high) << 32) | u64::from(info.file_index_low);
	Ok((u64::from(info.volume_serial_number), ino))
}

fn file_nlink(file: &File) -> io::Result<u32> {
	Ok(file_info(file)?.number_of_links)
}

fn handle_path(file: &File) -> io::Result<PathBuf> {
	let needed = unsafe {
		GetFinalPathNameByHandleW(file.as_raw_handle().cast(), std::ptr::null_mut(), 0, 0)
	};
	if needed == 0 {
		return Err(io::Error::last_os_error());
	}
	let mut buf = vec![0u16; needed as usize];
	let written = unsafe {
		GetFinalPathNameByHandleW(
			file.as_raw_handle().cast(),
			buf.as_mut_ptr(),
			buf.len() as u32,
			0,
		)
	};
	if written == 0 || written as usize > buf.len() {
		return Err(io::Error::last_os_error());
	}
	buf.truncate(written as usize);
	Ok(PathBuf::from(OsString::from_wide(&buf)))
}

fn win_epoch_to_unix(ticks: u64) -> (u64, u32) {
	const EPOCH_DIFF_SECS: u64 = 11_644_473_600;
	let total_secs = ticks / 10_000_000;
	let nanos = ((ticks % 10_000_000) * 100) as u32;
	(total_secs.saturating_sub(EPOCH_DIFF_SECS), nanos)
}

fn unix_to_filetime(secs: u64, nanos: u32) -> FileTime {
	const EPOCH_DIFF_SECS: u64 = 11_644_473_600;
	let ticks = secs
		.saturating_add(EPOCH_DIFF_SECS)
		.saturating_mul(10_000_000)
		.saturating_add(u64::from(nanos) / 100);
	FileTime {
		low_date_time: ticks as u32,
		high_date_time: (ticks >> 32) as u32,
	}
}

fn set_file_times(
	file: &File,
	atime: Option<&FileTime>,
	mtime: Option<&FileTime>,
) -> io::Result<()> {
	let atime_ptr = atime.map_or(std::ptr::null(), std::ptr::from_ref);
	let mtime_ptr = mtime.map_or(std::ptr::null(), std::ptr::from_ref);
	let ok = unsafe {
		SetFileTime(
			file.as_raw_handle().cast(),
			std::ptr::null(),
			atime_ptr,
			mtime_ptr,
		)
	};
	if ok == 0 {
		Err(io::Error::last_os_error())
	} else {
		Ok(())
	}
}

fn clone_dir_contents(src: &Path, dst: &Path) -> io::Result<()> {
	for entry in fs::read_dir(src)? {
		let entry = entry?;
		let src_path = entry.path();
		let dst_path = dst.join(entry.file_name());
		let meta = fs::symlink_metadata(&src_path)?;
		if meta.file_type().is_symlink() {
			let target = fs::read_link(&src_path)?;
			std::os::windows::fs::symlink_file(target, &dst_path)?;
		} else if meta.is_dir() {
			fs::create_dir(&dst_path)?;
			clone_dir_contents(&src_path, &dst_path)?;
		} else if meta.is_file() {
			fs::copy(&src_path, &dst_path)?;
		}
	}
	Ok(())
}

fn clear_dir_contents(dir: &Path) -> io::Result<()> {
	for entry in fs::read_dir(dir)? {
		let entry = entry?;
		remove_path_tree(&entry.path())?;
	}
	Ok(())
}

fn remove_path_tree(path: &Path) -> io::Result<()> {
	let meta = fs::symlink_metadata(path)?;
	if meta.is_dir() && !meta.file_type().is_symlink() {
		fs::remove_dir_all(path)
	} else {
		fs::remove_file(path)
	}
}

fn stale() -> io::Error {
	errno(libc::ENOENT)
}

fn errno(code: libc::c_int) -> io::Error {
	io::Error::from_raw_os_error(code)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn rejects_non_component_names() {
		for name in [b"".as_slice(), b".", b"..", b"x/y", b"x\\y", b"C:", b"x\0"] {
			assert!(validate_component(name).is_err());
		}
	}
}
