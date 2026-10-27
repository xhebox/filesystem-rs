//! Linux confined passthrough filesystem and its FUSE protocol surface.
//!
//! [`PassthroughFs`] implements [`api::Fuse`], [`api::Volume`], and
//! [`api::Snapshot`] directly. Request parsing, dispatch, and reply encoding belong to whoever drives the file
//! system; this module holds the confined state (inode table, handles) and
//! performs the host I/O.
//!
//! Every resolution is one atomic `openat2` from the preopened root or an
//! already-confined descendant handle, with:
//!
//! - `RESOLVE_BENEATH` — the final object must stay beneath the handle;
//! - `RESOLVE_NO_SYMLINKS` — no symbolic link traversal at all.
//!
//! `RESOLVE_NO_XDEV` is not used: the volume is defined as a path subtree,
//! and whatever the host mounts beneath it at runtime is part of what it
//! shares. Escape is bounded by `BENEATH` + `NO_SYMLINKS`.
//!
//! There is no procfs dependency anywhere: upgrading a confined handle to a
//! real access mode re-derives it from its `(parent, name)` locator with one
//! atomic `openat2` and verifies the result against the handle's `(st_dev,
//! st_ino)` identity.
//!
//! Caching posture: every returned timeout is zero and every open reply
//! carries `DIRECT_IO` — the guest kernel may cache nothing, so host-side
//! changes are always immediately visible and no notify path is needed.
//!
//! Threading: the back-end lives on the thread that drives it and never
//! leaves it, so the state is a `RefCell`, not a lock. Requests interleave
//! only at awaits, and no borrow of the state is held across one.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{Mode, OFlags, ResolveFlags as Resolve};

use crate::abi::{
	FATTR_ATIME, FATTR_ATIME_NOW, FATTR_CTIME, FATTR_GID, FATTR_MODE, FATTR_MTIME, FATTR_MTIME_NOW,
	FATTR_SIZE, FATTR_UID, FOPEN_DIRECT_IO, FUSE_ASYNC_READ, FUSE_BIG_WRITES, FUSE_MAX_PAGES,
	ROOT_ID,
};
use crate::span::{engine_io, read_exact, read_into, write_into};
use api::{
	Attr, Context, CreateArgs, DirEntry, DirentInfo, Entry, Fuse, GetxattrReply, Kstatfs,
	ListxattrReply, Snapshot, Volume, ZeroCopyReader, ZeroCopyWriter,
};

/// Zero attribute/data timeouts: nothing the guest caches may outlive the
/// request that produced it.
const NO_CACHE: Timeout = (0, 0);

/// Attribute-cache timeout, `(seconds, nanoseconds)`.
type Timeout = (u64, u32);

const FILE_TYPE_MASK: u32 = libc::S_IFMT;
const REGULAR_FILE: u32 = libc::S_IFREG;
const O_PATH: i32 = 0o10_000_000;
const RESOLVE: Resolve = Resolve::BENEATH.union(Resolve::NO_SYMLINKS);

type Inode = u64;
type Handle = u64;

/// A confined handle plus the locator needed to re-derive it by name.
struct Node {
	file: File,
	parent: Inode,
	name: CString,
	lookups: u64,
}

enum Resource {
	File(completion::File),
	Dir {
		file: completion::File,
		inode: Inode,
		cursor: DirCursor,
	},
}

/// One directory handle's cursor.
struct DirCursor(NonNull<libc::DIR>);

impl DirCursor {
	fn new(file: &File) -> io::Result<Self> {
		let fd = unsafe { libc::dup(file.as_raw_fd()) };
		if fd < 0 {
			return Err(io::Error::last_os_error());
		}
		let dir = unsafe { libc::fdopendir(fd) };
		match NonNull::new(dir) {
			Some(dir) => Ok(Self(dir)),
			None => {
				let error = io::Error::last_os_error();
				unsafe { libc::close(fd) };
				Err(error)
			}
		}
	}
}

impl Drop for DirCursor {
	fn drop(&mut self) {
		unsafe { libc::closedir(self.0.as_ptr()) };
	}
}

/// One entry of a directory listing, in the shape the FUSE readdir callbacks
/// consume. Owned because `readdirplus` re-derives full entries (and needs a
/// `&mut self` lookup) while the raw listing is already in hand.
pub(crate) struct RawDirEntry {
	pub(crate) inode: Inode,
	pub(crate) offset: u64,
	pub(crate) kind: u32,
	pub(crate) name: Vec<u8>,
}

/// Confined directory holding snapshots and branched workspaces.
struct SnapshotPool {
	dir: File,
	next_id: AtomicU64,
}

impl SnapshotPool {
	fn new(dir: File) -> io::Result<Self> {
		if !dir.metadata()?.is_dir() {
			return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
		}
		probe(dir.as_raw_fd())?;
		let confined = open_dir_fd(dir.as_raw_fd(), c".")?;
		Ok(Self {
			dir: confined,
			next_id: AtomicU64::new(1),
		})
	}

	fn allocate_id(&self) -> u64 {
		self.next_id.fetch_add(1, Ordering::Relaxed)
	}
}

/// The mutable filesystem state. See [`PassthroughFs`] for the threading
/// model; everything here is confined to the thread that drives the back-end.
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
/// any jail transition.
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

	/// Creates a [`PassthroughFs`] backed by `snapshots` for [`Snapshot`]
	/// operations (`snapshot`, `branch`, `restore`, `delete`).
	pub fn with_snapshots(root: File, snapshots: File, read_only: bool) -> io::Result<Self> {
		let pool = Arc::new(SnapshotPool::new(snapshots)?);
		let state = FsState::new(root, Some(pool), read_only)?;
		Ok(Self {
			state: RefCell::new(state),
		})
	}

	/// Takes the open file behind `handle`, so the state borrow ends before
	/// the caller awaits its I/O: another request runs in the meantime.
	fn open_file(&self, handle: Handle) -> io::Result<completion::File> {
		match self.state.borrow().handles.get(&handle) {
			Some(Resource::File(file) | Resource::Dir { file, .. }) => Ok(file.clone()),
			None => {
				log::warn!("io on unknown handle={handle}");
				Err(io::Error::from_raw_os_error(libc::EBADF))
			}
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
			return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
		}
		// Probe the exact policy used for all later resolution. ENOSYS and
		// filesystems that reject these flags are startup failures, never a
		// reason to weaken the confinement policy.
		probe(root.as_raw_fd())?;
		let root_node = inspect(root.as_raw_fd(), Path::new("."))?;
		let mut nodes = HashMap::new();
		nodes.insert(
			ROOT_ID,
			Node {
				file: root_node,
				parent: ROOT_ID,
				name: CString::new(".").expect("`.` has no NUL"),
				lookups: 1,
			},
		);
		let mut identities = HashMap::new();
		identities.insert((metadata.dev(), metadata.ino()), ROOT_ID);
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

	fn intern(
		&mut self,
		parent: Inode,
		name: &CStr,
		file: File,
		lookups: u64,
	) -> io::Result<(Inode, std::fs::Metadata)> {
		let metadata = file.metadata()?;
		let identity = (metadata.dev(), metadata.ino());
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
			.ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
		self.nodes.insert(
			inode,
			Node {
				file,
				parent,
				name: CString::from(name),
				lookups,
			},
		);
		self.identities.insert(identity, inode);
		Ok((inode, metadata))
	}

	fn lookup_child(
		&mut self,
		parent: Inode,
		name: &CStr,
	) -> io::Result<(Inode, std::fs::Metadata)> {
		validate_component(name.to_bytes())?;
		let file = inspect_name(self.node(parent)?.file.as_raw_fd(), name)?;
		self.intern(parent, name, file, 1)
	}

	fn allocate_handle(&mut self, resource: Resource) -> io::Result<Handle> {
		let handle = self.next_handle;
		self.next_handle = self
			.next_handle
			.checked_add(1)
			.ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
		self.handles.insert(handle, resource);
		Ok(handle)
	}

	/// The guest-visible attribute of an interned object.
	fn wire_attr(inode: Inode, metadata: &std::fs::Metadata) -> Attr {
		Attr {
			ino: inode,
			size: metadata.size(),
			blocks: metadata.blocks(),
			atime: metadata.atime().max(0) as u64,
			mtime: metadata.mtime().max(0) as u64,
			ctime: metadata.ctime().max(0) as u64,
			atimensec: metadata.atime_nsec() as u32,
			mtimensec: metadata.mtime_nsec() as u32,
			ctimensec: 0,
			mode: metadata.mode(),
			nlink: metadata.nlink() as u32,
			uid: metadata.uid(),
			gid: metadata.gid(),
			rdev: metadata.rdev() as u32,
			blksize: metadata.blksize() as u32,
			flags: 0,
		}
	}

	fn entry(&self, inode: Inode, metadata: &std::fs::Metadata) -> Entry {
		Entry {
			inode,
			generation: 0,
			attr: Self::wire_attr(inode, metadata),
			attr_timeout: NO_CACHE,
			entry_timeout: NO_CACHE,
		}
	}

	fn open_resource(&self, inode: Inode, flags: u32, directory: bool) -> io::Result<File> {
		let node = self.node(inode)?;
		let metadata = node.file.metadata()?;
		if metadata.file_type().is_symlink() {
			return Err(io::Error::from_raw_os_error(libc::ELOOP));
		}
		// Special files are host-kernel interfaces: a guest that can mknod a
		// device node into a writable volume must not be able to open it (see
		// QEMU 9pfs CVE-2023-2861). Only regular files and directories are
		// served; everything else is refused regardless of the access mode.
		if !metadata.is_file() && !metadata.is_dir() {
			return Err(io::Error::from_raw_os_error(libc::EPERM));
		}
		let access = flags & libc::O_ACCMODE as u32;
		if self.read_only && access != libc::O_RDONLY as u32 {
			return Err(io::Error::from_raw_os_error(libc::EROFS));
		}
		let mut open_flags = libc::O_CLOEXEC | if directory { libc::O_DIRECTORY } else { 0 };
		open_flags |= match access {
			x if x == libc::O_RDONLY as u32 => libc::O_RDONLY,
			x if x == libc::O_WRONLY as u32 => libc::O_WRONLY,
			x if x == libc::O_RDWR as u32 => libc::O_RDWR,
			_ => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
		};
		let parent = self.node(node.parent)?;
		reopen(&node.file, parent.file.as_raw_fd(), &node.name, open_flags)
	}

	fn create_resource(
		&self,
		parent: Inode,
		name: &CStr,
		flags: u32,
		mode: u32,
		umask: u32,
	) -> io::Result<File> {
		if self.read_only {
			return Err(io::Error::from_raw_os_error(libc::EROFS));
		}
		validate_component(name.to_bytes())?;
		let access = match flags & libc::O_ACCMODE as u32 {
			x if x == libc::O_RDONLY as u32 => libc::O_RDONLY,
			x if x == libc::O_WRONLY as u32 => libc::O_WRONLY,
			x if x == libc::O_RDWR as u32 => libc::O_RDWR,
			_ => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
		};
		let preserved = flags as i32 & (libc::O_EXCL | libc::O_TRUNC | libc::O_APPEND);
		open_name_with_mode(
			self.node(parent)?.file.as_raw_fd(),
			name,
			access | libc::O_CLOEXEC | libc::O_CREAT | libc::O_NOFOLLOW | preserved,
			mode & !umask & 0o7777,
		)
	}

	fn parent_file(&self, inode: Inode) -> io::Result<&File> {
		let node = self.node(inode)?;
		if node.file.metadata()?.is_dir() {
			Ok(&node.file)
		} else {
			Err(io::Error::from_raw_os_error(libc::ENOTDIR))
		}
	}

	fn writable(&self) -> io::Result<()> {
		if self.read_only {
			Err(io::Error::from_raw_os_error(libc::EROFS))
		} else {
			Ok(())
		}
	}

	fn object_file(&self, inode: Inode, flags: i32) -> io::Result<File> {
		let node = self.node(inode)?;
		if node.file.metadata()?.file_type().is_symlink() {
			return Err(io::Error::from_raw_os_error(libc::ELOOP));
		}
		if !node.file.metadata()?.is_file() && !node.file.metadata()?.is_dir() {
			return Err(io::Error::from_raw_os_error(libc::EPERM));
		}
		let parent = self.node(node.parent)?;
		reopen(&node.file, parent.file.as_raw_fd(), &node.name, flags)
	}

	fn read_dir_from(
		&mut self,
		directory: Inode,
		dir: *mut libc::DIR,
		max: usize,
	) -> io::Result<Vec<RawDirEntry>> {
		let mut entries = Vec::new();
		let mut bytes = 0usize;
		loop {
			errno_clear();
			let entry = unsafe { libc::readdir(dir) };
			if entry.is_null() {
				let error = io::Error::last_os_error();
				return if error.raw_os_error() == Some(0) {
					Ok(entries)
				} else {
					Err(error)
				};
			}
			let entry = unsafe { &*entry };
			let name = unsafe { CStr::from_ptr(entry.d_name.as_ptr()) }.to_bytes();
			if name == b"." || name == b".." {
				continue;
			}
			validate_component(name)?;
			let entry_len = 24usize
				.checked_add(name.len())
				.and_then(|len| len.checked_add(7))
				.map(|len| len & !7)
				.ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
			if entry_len > max || bytes.checked_add(entry_len).is_none_or(|total| total > max) {
				return Ok(entries);
			}
			let offset = unsafe { libc::telldir(dir) };
			if offset < 0 {
				return Err(io::Error::last_os_error());
			}
			let c_name = CStr::from_bytes_with_nul(unsafe {
				std::slice::from_raw_parts(entry.d_name.as_ptr().cast(), name.len() + 1)
			})
			.map_err(|_| io::Error::from_raw_os_error(libc::EIO))?;
			let (inode, _) = self.lookup_child(directory, c_name)?;
			entries.push(RawDirEntry {
				inode,
				offset: offset as u64,
				// The FUSE `d_type` values are the libc `DT_*` values.
				kind: u32::from(entry.d_type),
				name: name.to_vec(),
			});
			bytes += entry_len;
		}
	}

	pub(crate) fn lookup(&mut self, _: &Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
		let (inode, metadata) = self.lookup_child(parent, name)?;
		Ok(self.entry(inode, &metadata))
	}

	pub(crate) fn getattr(&mut self, _: &Context, inode: Inode) -> io::Result<Attr> {
		let metadata = self.node(inode)?.file.metadata()?;
		Ok(Self::wire_attr(inode, &metadata))
	}

	pub(crate) fn setattr(
		&mut self,
		_: &Context,
		inode: Inode,
		attr: Attr,
		valid: u32,
	) -> io::Result<Attr> {
		self.writable()?;
		if valid & FATTR_CTIME != 0 {
			return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
		}
		// A request that sets both a timestamp and "use the current time"
		// for it is contradictory; the kernel never sends one.
		if valid & (FATTR_ATIME | FATTR_ATIME_NOW) == (FATTR_ATIME | FATTR_ATIME_NOW)
			|| valid & (FATTR_MTIME | FATTR_MTIME_NOW) == (FATTR_MTIME | FATTR_MTIME_NOW)
		{
			return Err(io::Error::from_raw_os_error(libc::EINVAL));
		}
		let needs_write = valid & (FATTR_SIZE | FATTR_MODE | FATTR_UID | FATTR_GID) != 0;
		let file = self.object_file(
			inode,
			if needs_write {
				libc::O_RDWR
			} else {
				libc::O_RDONLY
			},
		)?;
		if valid & FATTR_MODE != 0 {
			chmod(&file, attr.mode & 0o7777)?;
		}
		if valid & (FATTR_UID | FATTR_GID) != 0 {
			chown(
				&file,
				if valid & FATTR_UID != 0 {
					attr.uid
				} else {
					u32::MAX
				},
				if valid & FATTR_GID != 0 {
					attr.gid
				} else {
					u32::MAX
				},
			)?;
		}
		if valid & FATTR_SIZE != 0 {
			truncate(&file, attr.size)?;
		}
		if valid & (FATTR_ATIME | FATTR_MTIME | FATTR_ATIME_NOW | FATTR_MTIME_NOW) != 0 {
			let now = libc::timespec {
				tv_sec: 0,
				tv_nsec: libc::UTIME_NOW,
			};
			let omit = libc::timespec {
				tv_sec: 0,
				tv_nsec: libc::UTIME_OMIT,
			};
			let atime = if valid & FATTR_ATIME_NOW != 0 {
				now
			} else if valid & FATTR_ATIME != 0 {
				timespec((attr.atime, attr.atimensec))?
			} else {
				omit
			};
			let mtime = if valid & FATTR_MTIME_NOW != 0 {
				now
			} else if valid & FATTR_MTIME != 0 {
				timespec((attr.mtime, attr.mtimensec))?
			} else {
				omit
			};
			timestamps(&file, atime, mtime)?;
		}
		self.getattr(&Context::default(), inode)
	}

	pub(crate) fn open(&mut self, _: &Context, inode: Inode, flags: u32) -> io::Result<Handle> {
		let file = self.open_resource(inode, flags, false)?;
		let handle = self.allocate_handle(Resource::File(completion::File::new(file)))?;
		log::debug!("backend open inode={inode} flags={flags} handle={handle}");
		Ok(handle)
	}

	pub(crate) fn create(
		&mut self,
		_context: &Context,
		parent: Inode,
		name: &CStr,
		flags: u32,
		mode: u32,
		umask: u32,
	) -> io::Result<(Entry, Handle)> {
		let file = self.create_resource(parent, name, flags, mode, umask)?;
		let metadata = file.metadata()?;
		let (inode, inspected) = self.lookup_child(parent, name)?;
		if metadata.dev() != inspected.dev() || metadata.ino() != inspected.ino() {
			return Err(stale());
		}
		let handle = self.allocate_handle(Resource::File(completion::File::new(file)))?;
		let name = String::from_utf8_lossy(name.to_bytes());
		log::debug!("backend create parent={parent} name={name} flags={flags} handle={handle}");
		Ok((self.entry(inode, &metadata), handle))
	}

	pub(crate) fn mkdir(
		&mut self,
		context: &Context,
		parent: Inode,
		name: &CStr,
		mode: u32,
	) -> io::Result<Entry> {
		self.writable()?;
		validate_component(name.to_bytes())?;
		mkdir(
			self.parent_file(parent)?,
			name,
			mode & !context_umask(context) & 0o7777,
		)?;
		let (inode, metadata) = self.lookup_child(parent, name)?;
		Ok(self.entry(inode, &metadata))
	}

	pub(crate) fn mknod(
		&mut self,
		context: &Context,
		parent: Inode,
		name: &CStr,
		mode: u32,
		rdev: u32,
	) -> io::Result<Entry> {
		self.writable()?;
		validate_component(name.to_bytes())?;
		if mode & FILE_TYPE_MASK != REGULAR_FILE {
			return Err(io::Error::from_raw_os_error(libc::EPERM));
		}
		mknod(
			self.parent_file(parent)?,
			name,
			mode & !context_umask(context),
			rdev,
		)?;
		let (inode, metadata) = self.lookup_child(parent, name)?;
		Ok(self.entry(inode, &metadata))
	}

	pub(crate) fn unlink(
		&mut self,
		_: &Context,
		parent: Inode,
		name: &CStr,
		directory: bool,
	) -> io::Result<()> {
		self.writable()?;
		validate_component(name.to_bytes())?;
		unlink(self.parent_file(parent)?, name, directory)
	}

	pub(crate) fn rename(
		&mut self,
		_: &Context,
		old_parent: Inode,
		old_name: &CStr,
		new_parent: Inode,
		new_name: &CStr,
		flags: u32,
	) -> io::Result<()> {
		self.writable()?;
		validate_component(old_name.to_bytes())?;
		validate_component(new_name.to_bytes())?;
		rename(
			self.parent_file(old_parent)?,
			old_name,
			self.parent_file(new_parent)?,
			new_name,
			flags,
		)
	}

	pub(crate) fn link(
		&mut self,
		_: &Context,
		inode: Inode,
		parent: Inode,
		name: &CStr,
	) -> io::Result<Entry> {
		self.writable()?;
		validate_component(name.to_bytes())?;
		link(&self.node(inode)?.file, self.parent_file(parent)?, name)?;
		let (inode, metadata) = self.lookup_child(parent, name)?;
		Ok(self.entry(inode, &metadata))
	}

	pub(crate) fn symlink(
		&mut self,
		_: &Context,
		parent: Inode,
		name: &CStr,
		target: &CStr,
	) -> io::Result<Entry> {
		self.writable()?;
		validate_component(name.to_bytes())?;
		symlink(target, self.parent_file(parent)?, name)?;
		let (inode, metadata) = self.lookup_child(parent, name)?;
		Ok(self.entry(inode, &metadata))
	}

	/// Reads into `out` through the facade, for the tests that move file data:
	/// a file shorter than `out` gives the short count the guest would get.
	#[cfg_attr(not(test), expect(dead_code))]
	pub(crate) async fn read(
		&self,
		handle: Handle,
		offset: u64,
		out: &mut [u8],
	) -> io::Result<usize> {
		let file = match self.handles.get(&handle) {
			Some(Resource::File(file)) => file.clone(),
			_ => {
				log::warn!("backend read on unknown handle={handle}");
				return Err(io::Error::from_raw_os_error(libc::EBADF));
			}
		};
		let mut buffer = completion::Buffer::zeroed(out.len());
		let count = read_exact(&file, buffer.clone(), offset).await?;
		out[..count].copy_from_slice(&buffer.get_mut().expect("the read landed")[0..count]);
		log::debug!(
			"backend read handle={handle} offset={offset} len={} count={count}",
			out.len()
		);
		Ok(count)
	}

	/// Writes `data` through the facade, for the tests that move file data.
	#[cfg_attr(not(test), expect(dead_code))]
	pub(crate) async fn write(
		&self,
		handle: Handle,
		offset: u64,
		data: &[u8],
	) -> io::Result<usize> {
		if self.read_only {
			return Err(io::Error::from_raw_os_error(libc::EROFS));
		}
		let file = match self.handles.get(&handle) {
			Some(Resource::File(file)) => file.clone(),
			_ => {
				log::warn!("backend write on unknown handle={handle}");
				return Err(io::Error::from_raw_os_error(libc::EBADF));
			}
		};
		let buffer = completion::Buffer::from(data.to_vec());
		let result = file.write_all_at(buffer, offset).await.map_err(engine_io);
		log::debug!(
			"backend write handle={handle} offset={offset} len={} result={result:?}",
			data.len()
		);
		result
	}

	pub(crate) fn release(&mut self, handle: Handle) -> io::Result<()> {
		match self.handles.remove(&handle) {
			Some(Resource::File(_)) => Ok(()),
			Some(resource) => {
				self.handles.insert(handle, resource);
				log::warn!("release on a non-file resource handle={handle}");
				Err(io::Error::from_raw_os_error(libc::EBADF))
			}
			None => {
				log::warn!("release on unknown handle={handle}");
				Err(io::Error::from_raw_os_error(libc::EBADF))
			}
		}
	}

	/// The file a FLUSH names, shared so the caller can await the deferred
	/// write-back error outside the state borrow. Only a file handle names a
	/// host close(2) to report through; a directory or unknown handle is
	/// `EBADF`.
	fn flush_file(&self, handle: Handle) -> io::Result<completion::File> {
		match self.handles.get(&handle) {
			Some(Resource::File(file)) => Ok(file.clone()),
			_ => Err(io::Error::from_raw_os_error(libc::EBADF)),
		}
	}

	/// The file a sync names, shared so the caller can await outside the
	/// state borrow.
	fn sync_file(&self, handle: Handle, directory: bool) -> io::Result<completion::File> {
		match (directory, self.handles.get(&handle)) {
			(false, Some(Resource::File(file))) => Ok(file.clone()),
			(true, Some(Resource::Dir { file, .. })) => Ok(file.clone()),
			_ => Err(io::Error::from_raw_os_error(libc::EBADF)),
		}
	}

	pub(crate) fn access(&mut self, context: &Context, inode: Inode, mask: u32) -> io::Result<()> {
		if mask == 0 {
			return Ok(());
		}
		if self.read_only && mask & libc::W_OK as u32 != 0 {
			return Err(io::Error::from_raw_os_error(libc::EROFS));
		}
		let metadata = self.node(inode)?.file.metadata()?;
		let mode = metadata.mode();
		if context.uid == 0 {
			if mask & libc::X_OK as u32 != 0 && !metadata.is_dir() && mode & 0o111 == 0 {
				return Err(io::Error::from_raw_os_error(libc::EACCES));
			}
			return Ok(());
		}
		let bits = if context.uid == metadata.uid() {
			(mode >> 6) & 0o7
		} else if context.gid == metadata.gid() {
			(mode >> 3) & 0o7
		} else {
			mode & 0o7
		};
		if mask & !bits != 0 {
			return Err(io::Error::from_raw_os_error(libc::EACCES));
		}
		Ok(())
	}

	/// Whether the inode is a symlink. Its own attributes are not served:
	/// the only namespace exposed is `user.*`, which Linux does not support on
	/// a symlink, and opening the link to reach them is what `object_file`
	/// refuses with `ELOOP` — an errno a caller that asked `llistxattr` must
	/// not see.
	fn is_symlink(&self, inode: Inode) -> io::Result<bool> {
		Ok(self.node(inode)?.file.metadata()?.file_type().is_symlink())
	}

	pub(crate) fn set_xattr(
		&mut self,
		_: &Context,
		inode: Inode,
		name: &CStr,
		value: &[u8],
		flags: u32,
	) -> io::Result<()> {
		self.writable()?;
		ensure_user_xattr(name)?;
		if self.is_symlink(inode)? {
			return Err(io::Error::from_raw_os_error(libc::EPERM));
		}
		let file = self.object_file(inode, libc::O_RDONLY)?;
		set_xattr(&file, name, value, flags)
	}

	pub(crate) fn get_xattr(
		&mut self,
		_: &Context,
		inode: Inode,
		name: Option<&CStr>,
		size: usize,
	) -> io::Result<Vec<u8>> {
		if let Some(name) = name {
			// Only `user.*` xattrs are served; everything else (including
			// `security.capability`, which execve probes) is hidden — reading it
			// must look like the attribute does not exist, not like a denial.
			if !name.to_bytes().starts_with(b"user.") {
				return Err(io::Error::from_raw_os_error(libc::ENODATA));
			}
		}
		if self.is_symlink(inode)? {
			return match name {
				Some(_) => Err(io::Error::from_raw_os_error(libc::ENODATA)),
				None => Ok(Vec::new()),
			};
		}
		let file = self.object_file(inode, libc::O_RDONLY)?;
		let value = filter_xattr_list(name, get_xattr(&file, name)?)?;
		if size != 0 && value.len() > size {
			return Err(io::Error::from_raw_os_error(libc::ERANGE));
		}
		Ok(value)
	}

	pub(crate) fn remove_xattr(
		&mut self,
		_: &Context,
		inode: Inode,
		name: &CStr,
	) -> io::Result<()> {
		self.writable()?;
		ensure_user_xattr(name)?;
		if self.is_symlink(inode)? {
			return Err(io::Error::from_raw_os_error(libc::EPERM));
		}
		let file = self.object_file(inode, libc::O_RDONLY)?;
		remove_xattr(&file, name)
	}

	pub(crate) fn open_dir(&mut self, _: &Context, inode: Inode, flags: u32) -> io::Result<Handle> {
		let file = self.open_resource(inode, flags, true)?;
		let cursor = DirCursor::new(&file)?;
		self.allocate_handle(Resource::Dir {
			file: completion::File::new(file),
			inode,
			cursor,
		})
	}

	pub(crate) fn read_dir(
		&mut self,
		handle: Handle,
		offset: u64,
		max: usize,
	) -> io::Result<Vec<RawDirEntry>> {
		let (dir, inode) = match self.handles.get(&handle) {
			Some(Resource::Dir { cursor, inode, .. }) => (cursor.0.as_ptr(), *inode),
			_ => return Err(io::Error::from_raw_os_error(libc::EBADF)),
		};
		if offset > libc::c_long::MAX as u64 {
			return Err(io::Error::from_raw_os_error(libc::EINVAL));
		}
		unsafe { libc::seekdir(dir, offset as libc::c_long) };
		self.read_dir_from(inode, dir, max)
	}

	fn release_dir(&mut self, handle: Handle) -> io::Result<()> {
		match self.handles.remove(&handle) {
			Some(Resource::Dir { .. }) => Ok(()),
			Some(resource) => {
				self.handles.insert(handle, resource);
				Err(io::Error::from_raw_os_error(libc::EBADF))
			}
			None => Err(io::Error::from_raw_os_error(libc::EBADF)),
		}
	}

	fn statfs(&mut self, inode: Inode) -> io::Result<Kstatfs> {
		let file = self.open_resource(inode, libc::O_RDONLY as u32, false)?;
		statfs(&file)
	}

	pub(crate) fn read_link(&mut self, inode: Inode) -> io::Result<Vec<u8>> {
		read_link(&self.node(inode)?.file)
	}

	pub(crate) fn forget(&mut self, inode: Inode, count: u64) {
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
			.ok_or_else(|| io::Error::from_raw_os_error(libc::EOPNOTSUPP))
	}

	pub(crate) fn snapshot(&self) -> io::Result<u64> {
		let pool = Arc::clone(self.pool()?);
		let src = open_dir_fd(self.node(ROOT_ID)?.file.as_raw_fd(), c".")?;
		let id = pool.allocate_id();
		let name = snapshot_entry_name("snap", id);
		clone_tree(&src, &pool.dir, &name)?;
		Ok(id)
	}

	pub(crate) fn branch(&self, id: u64) -> io::Result<PassthroughFs> {
		let pool = Arc::clone(self.pool()?);
		let snap_name = snapshot_entry_name("snap", id);
		let src = open_dir_fd(pool.dir.as_raw_fd(), &snap_name)?;
		let work_id = pool.allocate_id();
		let work_name = snapshot_entry_name("work", work_id);
		clone_tree(&src, &pool.dir, &work_name)?;
		let work_root = open_dir_fd(pool.dir.as_raw_fd(), &work_name)?;
		let state = FsState::new(work_root, Some(pool), false)?;
		Ok(PassthroughFs {
			state: RefCell::new(state),
		})
	}

	pub(crate) fn restore(&mut self, id: u64) -> io::Result<()> {
		self.writable()?;
		let pool = Arc::clone(self.pool()?);
		let snap_name = snapshot_entry_name("snap", id);
		let src = open_dir_fd(pool.dir.as_raw_fd(), &snap_name)?;
		let dst = open_dir_fd(self.node(ROOT_ID)?.file.as_raw_fd(), c".")?;
		clear_dir_contents(&dst)?;
		let mut hardlinks = HashMap::new();
		clone_dir_contents(&src, &dst, &mut hardlinks)?;
		copy_xattrs(&src, &dst)?;
		let src_meta = src.metadata()?;
		chmod(&dst, src_meta.mode() & 0o7777)?;
		let root_node = self.nodes.remove(&ROOT_ID).expect("root node is present");
		let root_meta = root_node.file.metadata()?;
		self.nodes.clear();
		self.identities.clear();
		self.nodes.insert(
			ROOT_ID,
			Node {
				file: root_node.file,
				parent: ROOT_ID,
				name: root_node.name,
				lookups: 1,
			},
		);
		self.identities
			.insert((root_meta.dev(), root_meta.ino()), ROOT_ID);
		Ok(())
	}

	pub(crate) fn delete_snapshot(&self, id: u64) -> io::Result<()> {
		let pool = Arc::clone(self.pool()?);
		let snap_name = snapshot_entry_name("snap", id);
		remove_tree(&pool.dir, &snap_name)
	}

	fn resolve_dir(&self, parts: &[CString]) -> io::Result<File> {
		let mut dir = open_dir_fd(self.node(ROOT_ID)?.file.as_raw_fd(), c".")?;
		for part in parts {
			dir = open_dir_fd(dir.as_raw_fd(), part)?;
		}
		Ok(dir)
	}

	fn resolve_parent(&self, path: &Path) -> io::Result<(File, CString)> {
		let mut parts = split_path(path)?;
		let name = parts
			.pop()
			.ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
		let parent = self.resolve_dir(&parts)?;
		Ok((parent, name))
	}

	fn open_volume_read(&self, path: &Path) -> io::Result<(completion::File, usize)> {
		let (parent, name) = self.resolve_parent(path)?;
		let file = open_cstr(
			parent.as_raw_fd(),
			&name,
			libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
			0,
		)?;
		let meta = file.metadata()?;
		if meta.is_dir() {
			return Err(io::Error::from_raw_os_error(libc::EISDIR));
		}
		if !meta.is_file() {
			return Err(io::Error::from_raw_os_error(libc::EPERM));
		}
		let len =
			usize::try_from(meta.size()).map_err(|_| io::Error::from_raw_os_error(libc::EFBIG))?;
		Ok((completion::File::new(file), len))
	}

	fn open_volume_write(&self, path: &Path) -> io::Result<completion::File> {
		self.writable()?;
		let (parent, name) = self.resolve_parent(path)?;
		let file = open_cstr(
			parent.as_raw_fd(),
			&name,
			libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
			0o644,
		)?;
		Ok(completion::File::new(file))
	}

	fn volume_stat(&self, path: &Path) -> io::Result<Attr> {
		let parts = split_path(path)?;
		if parts.is_empty() {
			let meta = self.node(ROOT_ID)?.file.metadata()?;
			return Ok(Self::wire_attr(meta.ino(), &meta));
		}
		let (parent, name) = self.resolve_parent(path)?;
		let file = inspect_name(parent.as_raw_fd(), &name)?;
		let meta = file.metadata()?;
		Ok(Self::wire_attr(meta.ino(), &meta))
	}

	fn volume_readlink(&self, path: &Path) -> io::Result<Vec<u8>> {
		let (parent, name) = self.resolve_parent(path)?;
		let file = inspect_name(parent.as_raw_fd(), &name)?;
		read_link(&file)
	}

	fn volume_symlink(&self, target: &Path, link_path: &Path) -> io::Result<()> {
		self.writable()?;
		let (parent, name) = self.resolve_parent(link_path)?;
		let target_cstr = CString::new(target.as_os_str().as_bytes())
			.map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
		symlink(&target_cstr, &parent, &name)
	}

	fn volume_list(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
		let parts = split_path(path)?;
		let dir = self.resolve_dir(&parts)?;
		let cursor = DirCursor::new(&dir)?;
		let mut entries = Vec::new();
		let mut offset = 1u64;
		loop {
			errno_clear();
			let entry = unsafe { libc::readdir(cursor.0.as_ptr()) };
			if entry.is_null() {
				let error = io::Error::last_os_error();
				return if error.raw_os_error() == Some(0) {
					Ok(entries)
				} else {
					Err(error)
				};
			}
			let entry = unsafe { &*entry };
			let name = unsafe { CStr::from_ptr(entry.d_name.as_ptr()) }.to_bytes();
			if name == b"." || name == b".." {
				continue;
			}
			validate_component(name)?;
			entries.push(DirEntry {
				ino: entry.d_ino,
				offset,
				type_: u32::from(entry.d_type),
				name: name.to_vec(),
			});
			offset += 1;
		}
	}

	fn volume_create_dir(&self, path: &Path) -> io::Result<()> {
		self.writable()?;
		let (parent, name) = self.resolve_parent(path)?;
		mkdir(&parent, &name, 0o755)
	}

	fn volume_create_dir_all(&self, path: &Path) -> io::Result<()> {
		self.writable()?;
		let parts = split_path(path)?;
		let mut dir = open_dir_fd(self.node(ROOT_ID)?.file.as_raw_fd(), c".")?;
		for part in &parts {
			match open_dir_fd(dir.as_raw_fd(), part) {
				Ok(next) => dir = next,
				Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
					mkdir(&dir, part, 0o755)?;
					dir = open_dir_fd(dir.as_raw_fd(), part)?;
				}
				Err(error) => return Err(error),
			}
		}
		Ok(())
	}

	fn volume_remove_file(&self, path: &Path) -> io::Result<()> {
		self.writable()?;
		let (parent, name) = self.resolve_parent(path)?;
		unlink(&parent, &name, false)
	}

	fn volume_remove_dir(&self, path: &Path) -> io::Result<()> {
		self.writable()?;
		let (parent, name) = self.resolve_parent(path)?;
		unlink(&parent, &name, true)
	}

	fn volume_remove_all(&self, path: &Path) -> io::Result<()> {
		self.writable()?;
		let parts = split_path(path)?;
		if parts.is_empty() {
			let root_dir = open_dir_fd(self.node(ROOT_ID)?.file.as_raw_fd(), c".")?;
			return clear_dir_contents(&root_dir);
		}
		let (parent, name) = self.resolve_parent(path)?;
		remove_tree(&parent, &name)
	}

	fn volume_rename(&self, from: &Path, to: &Path) -> io::Result<()> {
		self.writable()?;
		let (old_parent, old_name) = self.resolve_parent(from)?;
		let (new_parent, new_name) = self.resolve_parent(to)?;
		rename(&old_parent, &old_name, &new_parent, &new_name, 0)
	}

	fn volume_copy(&self, from: &Path, to: &Path) -> io::Result<u64> {
		self.writable()?;
		let (src_parent, src_name) = self.resolve_parent(from)?;
		let (dst_parent, dst_name) = self.resolve_parent(to)?;
		let src_file = open_cstr(
			src_parent.as_raw_fd(),
			&src_name,
			libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
			0,
		)?;
		let meta = src_file.metadata()?;
		if meta.is_dir() {
			return Err(io::Error::from_raw_os_error(libc::EISDIR));
		}
		if !meta.is_file() {
			return Err(io::Error::from_raw_os_error(libc::EPERM));
		}
		let dst_file = open_cstr(
			dst_parent.as_raw_fd(),
			&dst_name,
			libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
			meta.mode() & 0o7777,
		)?;
		let size = meta.size();
		clone_file_data(&src_file, &dst_file, size)?;
		Ok(size)
	}
}

/// The guest umask of a request. Only `create` carries one on the wire; every
/// other request sees zero.
fn context_umask(_: &Context) -> u32 {
	0
}

impl Fuse for PassthroughFs {
	type Inode = u64;
	type Handle = u64;

	async fn init(&self, capable: u32) -> io::Result<u32> {
		let want = FUSE_ASYNC_READ | FUSE_BIG_WRITES | FUSE_MAX_PAGES;
		Ok(capable & want)
	}

	async fn lookup(&self, ctx: &Context, parent: u64, name: &CStr) -> io::Result<Entry> {
		self.with(|state| state.lookup(ctx, parent, name))
	}

	async fn forget(&self, _ctx: &Context, inode: u64, count: u64) {
		// The FUSE protocol gives FORGET no reply, so a failure has no
		// channel back to the kernel and is reported here instead.
		if let Err(error) = self.with(|state| {
			state.forget(inode, count);
			Ok(())
		}) {
			log::debug!("forget inode={inode} count={count}: {error}");
		}
	}

	async fn batch_forget(&self, _ctx: &Context, requests: Vec<(u64, u64)>) {
		if let Err(error) = self.with(|state| {
			state.batch_forget(requests);
			Ok(())
		}) {
			log::debug!("batch_forget: {error}");
		}
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
		umask: u32,
	) -> io::Result<Entry> {
		let _ = umask;
		self.with(|state| state.mknod(ctx, parent, name, mode, rdev))
	}

	async fn mkdir(
		&self,
		ctx: &Context,
		parent: u64,
		name: &CStr,
		mode: u32,
		umask: u32,
	) -> io::Result<Entry> {
		let _ = umask;
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
			return Err(io::Error::from_raw_os_error(libc::EROFS));
		}
		let file = self.open_file(handle)?;
		let result = write_into(&file, input, size as usize, offset).await;
		log::debug!("FUSE write handle={handle} offset={offset} size={size} result={result:?}");
		result
	}

	async fn flush(&self, _ctx: &Context, _inode: u64, handle: u64) -> io::Result<()> {
		// FLUSH is the guest's close(2): it reports the write-back error the
		// host deferred, without forcing the data to disk (that is `fsync`).
		// The facade closes a duplicate, so the handle keeps its descriptor.
		let file = self.with(|state| state.flush_file(handle))?;
		let result = file.flush().await;
		log::debug!("FUSE flush handle={handle} result={result:?}");
		result.map_err(engine_io)
	}

	async fn fsync(
		&self,
		_ctx: &Context,
		_inode: u64,
		datasync: bool,
		handle: u64,
	) -> io::Result<()> {
		let file = self.with(|state| state.sync_file(handle, false))?;
		let result = file.sync().await;
		log::debug!("FUSE fsync handle={handle} datasync={datasync} result={result:?}");
		result.map_err(engine_io)
	}

	async fn release(
		&self,
		_ctx: &Context,
		_inode: u64,
		_flags: u32,
		handle: u64,
	) -> io::Result<()> {
		let result = self.with(|state| state.release(handle));
		log::debug!("FUSE release handle={handle} result={result:?}");
		result
	}

	async fn statfs(&self, _ctx: &Context, _inode: u64) -> io::Result<Kstatfs> {
		self.with(|state| state.statfs(0))
	}

	async fn setxattr(
		&self,
		ctx: &Context,
		inode: u64,
		name: &CStr,
		value: &[u8],
		flags: u32,
	) -> io::Result<()> {
		self.with(|state| state.set_xattr(ctx, inode, name, value, flags))
	}

	async fn getxattr(
		&self,
		ctx: &Context,
		inode: u64,
		name: &CStr,
		size: u32,
	) -> io::Result<GetxattrReply> {
		self.with(|state| {
			let value = state.get_xattr(ctx, inode, Some(name), size as usize)?;
			if size == 0 {
				Ok(GetxattrReply::Size(value.len() as u32))
			} else {
				Ok(GetxattrReply::Value(value))
			}
		})
	}

	async fn listxattr(&self, ctx: &Context, inode: u64, size: u32) -> io::Result<ListxattrReply> {
		self.with(|state| {
			let value = state.get_xattr(ctx, inode, None, size as usize)?;
			if size == 0 {
				Ok(ListxattrReply::Size(value.len() as u32))
			} else {
				Ok(ListxattrReply::Names(value))
			}
		})
	}

	async fn removexattr(&self, ctx: &Context, inode: u64, name: &CStr) -> io::Result<()> {
		self.with(|state| state.remove_xattr(ctx, inode, name))
	}

	async fn opendir(&self, ctx: &Context, inode: u64) -> io::Result<u64> {
		self.with(|state| state.open_dir(ctx, inode, libc::O_RDONLY as u32))
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
			let mut out = Vec::with_capacity(entries.len());
			for entry in entries {
				out.push(DirEntry {
					ino: entry.inode,
					offset: entry.offset,
					type_: entry.kind,
					name: entry.name,
				});
			}
			Ok(out)
		})
	}

	async fn readdirplus(
		&self,
		ctx: &Context,
		inode: u64,
		handle: u64,
		size: u32,
		offset: u64,
	) -> io::Result<Vec<(Entry, DirentInfo)>> {
		self.with(|state| {
			let entries = state.read_dir(handle, offset, size as usize)?;
			let mut out = Vec::with_capacity(entries.len());
			for entry in entries {
				// readdirplus promises attributes: re-derive the full entry.
				let name = CStr::from_bytes_until_nul(&entry.name)
					.map_err(|_| io::Error::from_raw_os_error(libc::EIO))?;
				match state.lookup(ctx, inode, name) {
					Ok(full) => out.push((
						full,
						DirentInfo {
							ino: entry.inode,
							offset: entry.offset,
							type_: entry.kind,
							name: entry.name,
						},
					)),
					// The entry vanished between getdents and lookup; skip it.
					Err(error) if error.raw_os_error() == Some(libc::ENOENT) => continue,
					Err(error) => return Err(error),
				}
			}
			Ok(out)
		})
	}

	async fn fsyncdir(
		&self,
		_ctx: &Context,
		_inode: u64,
		_datasync: bool,
		handle: u64,
	) -> io::Result<()> {
		let file = self.with(|state| state.sync_file(handle, true))?;
		file.sync().await.map_err(engine_io)
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
		self.with(|state| state.volume_stat(path))
	}

	async fn readlink(&self, path: &Path) -> io::Result<Vec<u8>> {
		self.with(|state| state.volume_readlink(path))
	}

	async fn symlink(&self, target: &Path, link: &Path) -> io::Result<()> {
		self.with(|state| state.volume_symlink(target, link))
	}

	async fn list(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
		self.with(|state| state.volume_list(path))
	}

	async fn create_dir(&self, path: &Path) -> io::Result<()> {
		self.with(|state| state.volume_create_dir(path))
	}

	async fn create_dir_all(&self, path: &Path) -> io::Result<()> {
		self.with(|state| state.volume_create_dir_all(path))
	}

	async fn remove_file(&self, path: &Path) -> io::Result<()> {
		self.with(|state| state.volume_remove_file(path))
	}

	async fn remove_dir(&self, path: &Path) -> io::Result<()> {
		self.with(|state| state.volume_remove_dir(path))
	}

	async fn remove_all(&self, path: &Path) -> io::Result<()> {
		self.with(|state| state.volume_remove_all(path))
	}

	async fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
		self.with(|state| state.volume_rename(from, to))
	}

	async fn copy(&self, from: &Path, to: &Path) -> io::Result<u64> {
		self.with(|state| state.volume_copy(from, to))
	}
}

fn split_path(path: &Path) -> io::Result<Vec<CString>> {
	let mut parts = Vec::new();
	for component in path.components() {
		match component {
			Component::RootDir | Component::CurDir => {}
			Component::Normal(name) => {
				let bytes = name.as_bytes();
				validate_component(bytes)?;
				parts.push(
					CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?,
				);
			}
			Component::ParentDir | Component::Prefix(_) => {
				return Err(io::Error::from_raw_os_error(libc::EINVAL));
			}
		}
	}
	Ok(parts)
}

pub(crate) fn validate_component(name: &[u8]) -> io::Result<()> {
	if name.is_empty() || name == b"." || name == b".." || name.contains(&0) || name.contains(&b'/')
	{
		Err(io::Error::from_raw_os_error(libc::EINVAL))
	} else {
		Ok(())
	}
}

fn stale() -> io::Error {
	io::Error::from_raw_os_error(libc::ESTALE)
}

fn timespec((seconds, nanos): (u64, u32)) -> io::Result<libc::timespec> {
	if nanos >= 1_000_000_000 {
		return Err(io::Error::from_raw_os_error(libc::EINVAL));
	}
	Ok(libc::timespec {
		tv_sec: seconds
			.try_into()
			.map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?,
		tv_nsec: nanos.into(),
	})
}

fn ensure_user_xattr(name: &CStr) -> io::Result<()> {
	if name.to_bytes().starts_with(b"user.") {
		Ok(())
	} else {
		Err(io::Error::from_raw_os_error(libc::EPERM))
	}
}

fn filter_xattr_list(name: Option<&CStr>, data: Vec<u8>) -> io::Result<Vec<u8>> {
	if name.is_some() {
		return Ok(data);
	}
	let mut filtered = Vec::new();
	for entry in data.split_inclusive(|byte| *byte == 0) {
		let name = CStr::from_bytes_with_nul(entry)
			.map_err(|_| io::Error::from_raw_os_error(libc::EIO))?;
		if name.to_bytes().starts_with(b"user.") {
			filtered.extend_from_slice(entry);
		}
	}
	Ok(filtered)
}

fn probe(root: libc::c_int) -> io::Result<()> {
	drop(open_path(root, Path::new("."), O_PATH | libc::O_DIRECTORY)?);
	Ok(())
}

fn inspect(root: libc::c_int, path: &Path) -> io::Result<File> {
	open_path(root, path, O_PATH | libc::O_NOFOLLOW)
}

fn inspect_name(root: libc::c_int, name: &CStr) -> io::Result<File> {
	open_cstr(root, name, O_PATH | libc::O_NOFOLLOW, 0)
}

fn open_path(root: libc::c_int, path: &Path, flags: libc::c_int) -> io::Result<File> {
	let bytes = if path.as_os_str().is_empty() {
		b".".as_slice()
	} else {
		path.as_os_str().as_bytes()
	};
	let path = CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
	open_cstr(root, &path, flags, 0)
}

fn open_name_with_mode(
	root: libc::c_int,
	name: &CStr,
	flags: libc::c_int,
	mode: u32,
) -> io::Result<File> {
	open_cstr(root, name, flags, mode)
}

fn open_cstr(root: libc::c_int, path: &CStr, flags: libc::c_int, mode: u32) -> io::Result<File> {
	let fd = rustix::fs::openat2(
		unsafe { BorrowedFd::borrow_raw(root) },
		path,
		OFlags::from_bits_retain(flags as u32),
		Mode::from_raw_mode(mode),
		RESOLVE,
	)
	.map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
	Ok(File::from(fd))
}

/// Re-opens a confined handle with new access flags. The handle is
/// re-derived from its `(parent_fd, name)` locator through one atomic
/// `openat2` (`BENEATH|NO_SYMLINKS`) and the result is **verified against
/// the handle's identity**: `(st_dev, st_ino)` must match, or the locator
/// went stale (host-side rename/unlink) and the request fails with `ESTALE`.
fn reopen(
	file: &File,
	parent_fd: libc::c_int,
	name: &CStr,
	flags: libc::c_int,
) -> io::Result<File> {
	let pinned = fstat_identity(file.as_raw_fd())?;
	let reopened = open_cstr(parent_fd, name, flags | libc::O_CLOEXEC, 0)?;
	let identity = fstat_identity(reopened.as_raw_fd())?;
	if identity != pinned {
		log::warn!(
			"reopen identity mismatch: pinned=(dev={},ino={}) reopened=(dev={},ino={}) name={}",
			pinned.0,
			pinned.1,
			identity.0,
			identity.1,
			String::from_utf8_lossy(name.to_bytes())
		);
		return Err(io::Error::from_raw_os_error(libc::ESTALE));
	}
	Ok(reopened)
}

fn fstat_identity(fd: libc::c_int) -> io::Result<(u64, u64)> {
	let mut stat: libc::stat = unsafe { std::mem::zeroed() };
	if unsafe { libc::fstat(fd, &mut stat) } < 0 {
		return Err(io::Error::last_os_error());
	}
	Ok((stat.st_dev, stat.st_ino))
}

fn mkdir(parent: &File, name: &CStr, mode: u32) -> io::Result<()> {
	cvt(unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode) })
}

fn mknod(parent: &File, name: &CStr, mode: u32, rdev: u32) -> io::Result<()> {
	cvt(unsafe { libc::mknodat(parent.as_raw_fd(), name.as_ptr(), mode, u64::from(rdev)) })
}

fn unlink(parent: &File, name: &CStr, directory: bool) -> io::Result<()> {
	cvt(unsafe {
		libc::unlinkat(
			parent.as_raw_fd(),
			name.as_ptr(),
			if directory { libc::AT_REMOVEDIR } else { 0 },
		)
	})
}

fn symlink(target: &CStr, parent: &File, name: &CStr) -> io::Result<()> {
	cvt(unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr()) })
}

fn chmod(file: &File, mode: u32) -> io::Result<()> {
	cvt(unsafe { libc::fchmod(file.as_raw_fd(), mode) })
}

fn chown(file: &File, uid: u32, gid: u32) -> io::Result<()> {
	cvt(unsafe { libc::fchown(file.as_raw_fd(), uid, gid) })
}

fn truncate(file: &File, size: u64) -> io::Result<()> {
	let size =
		libc::off_t::try_from(size).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
	cvt(unsafe { libc::ftruncate(file.as_raw_fd(), size) })
}

fn timestamps(file: &File, atime: libc::timespec, mtime: libc::timespec) -> io::Result<()> {
	let times = [atime, mtime];
	cvt(unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) })
}

fn read_link(file: &File) -> io::Result<Vec<u8>> {
	let mut target = vec![0; libc::PATH_MAX as usize];
	let length = unsafe {
		libc::readlinkat(
			file.as_raw_fd(),
			c"".as_ptr(),
			target.as_mut_ptr().cast(),
			target.len(),
		)
	};
	if length < 0 {
		return Err(io::Error::last_os_error());
	}
	target.truncate(length as usize);
	Ok(target)
}

fn rename(
	old_parent: &File,
	old_name: &CStr,
	new_parent: &File,
	new_name: &CStr,
	flags: u32,
) -> io::Result<()> {
	cvt_long(unsafe {
		libc::syscall(
			libc::SYS_renameat2,
			old_parent.as_raw_fd(),
			old_name.as_ptr(),
			new_parent.as_raw_fd(),
			new_name.as_ptr(),
			flags,
		)
	})
}

fn link(file: &File, parent: &File, name: &CStr) -> io::Result<()> {
	cvt(unsafe {
		libc::linkat(
			file.as_raw_fd(),
			c"".as_ptr(),
			parent.as_raw_fd(),
			name.as_ptr(),
			libc::AT_EMPTY_PATH,
		)
	})
}

fn get_xattr(file: &File, name: Option<&CStr>) -> io::Result<Vec<u8>> {
	let name = name.map(|name| name.as_ptr()).unwrap_or(std::ptr::null());
	let size = if name.is_null() {
		unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0) }
	} else {
		unsafe { libc::fgetxattr(file.as_raw_fd(), name, std::ptr::null_mut(), 0) }
	};
	if size < 0 {
		return Err(io::Error::last_os_error());
	}
	let mut value = vec![0; size as usize];
	let result = if name.is_null() {
		unsafe { libc::flistxattr(file.as_raw_fd(), value.as_mut_ptr().cast(), value.len()) }
	} else {
		unsafe {
			libc::fgetxattr(
				file.as_raw_fd(),
				name,
				value.as_mut_ptr().cast(),
				value.len(),
			)
		}
	};
	if result < 0 {
		return Err(io::Error::last_os_error());
	}
	value.truncate(result as usize);
	Ok(value)
}

fn set_xattr(file: &File, name: &CStr, value: &[u8], flags: u32) -> io::Result<()> {
	cvt(unsafe {
		libc::fsetxattr(
			file.as_raw_fd(),
			name.as_ptr(),
			value.as_ptr().cast(),
			value.len(),
			flags as libc::c_int,
		)
	})
}

fn remove_xattr(file: &File, name: &CStr) -> io::Result<()> {
	cvt(unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr()) })
}

fn errno_clear() {
	#[cfg(target_os = "linux")]
	unsafe {
		*libc::__errno_location() = 0;
	}
	#[cfg(target_os = "android")]
	unsafe {
		*libc::__errno() = 0;
	}
}

fn statfs(file: &File) -> io::Result<Kstatfs> {
	let mut stat = unsafe { std::mem::zeroed::<libc::statfs>() };
	if unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } < 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(Kstatfs {
		blocks: stat.f_blocks,
		bfree: stat.f_bfree,
		bavail: stat.f_bavail,
		files: stat.f_files,
		ffree: stat.f_ffree,
		bsize: stat.f_bsize as u32,
		namelen: stat.f_namelen as u32,
		frsize: stat.f_frsize as u32,
		..Kstatfs::default()
	})
}

fn cvt(result: libc::c_int) -> io::Result<()> {
	if result == 0 {
		Ok(())
	} else {
		Err(io::Error::last_os_error())
	}
}

fn cvt_long(result: libc::c_long) -> io::Result<()> {
	if result == 0 {
		Ok(())
	} else {
		Err(io::Error::last_os_error())
	}
}

const FICLONE: libc::c_ulong = 0x4004_9409;
const BTRFS_SUBVOL_NAME_MAX: usize = 4039;
const BTRFS_IOC_SNAP_CREATE_V2: libc::c_ulong = 0x5000_9417;
const BTRFS_IOC_SNAP_DESTROY_V2: libc::c_ulong = 0x5000_943f;

#[repr(C)]
struct BtrfsIoctlVolArgsV2 {
	fd: i64,
	transid: u64,
	flags: u64,
	unused: [u64; 4],
	name: [libc::c_char; BTRFS_SUBVOL_NAME_MAX + 1],
}

fn snapshot_entry_name(prefix: &str, id: u64) -> CString {
	CString::new(format!("{prefix}-{id}")).expect("formatted name has no NUL")
}

fn open_dir_fd(root: libc::c_int, name: &CStr) -> io::Result<File> {
	open_cstr(
		root,
		name,
		libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
		0,
	)
}

fn btrfs_snapshot(src: &File, dst_parent: &File, dst_name: &CStr) -> io::Result<()> {
	let bytes = dst_name.to_bytes_with_nul();
	if bytes.len() > BTRFS_SUBVOL_NAME_MAX + 1 {
		return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
	}
	let mut args = BtrfsIoctlVolArgsV2 {
		fd: i64::from(src.as_raw_fd()),
		transid: 0,
		flags: 0,
		unused: [0; 4],
		name: [0; BTRFS_SUBVOL_NAME_MAX + 1],
	};
	for (dst, &byte) in args.name.iter_mut().zip(bytes) {
		*dst = byte as libc::c_char;
	}
	cvt_long(unsafe {
		libc::syscall(
			libc::SYS_ioctl,
			dst_parent.as_raw_fd(),
			BTRFS_IOC_SNAP_CREATE_V2,
			&mut args,
		)
	})
}

fn btrfs_destroy_subvol(parent: &File, name: &CStr) -> io::Result<()> {
	let bytes = name.to_bytes_with_nul();
	if bytes.len() > BTRFS_SUBVOL_NAME_MAX + 1 {
		return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
	}
	let mut args = BtrfsIoctlVolArgsV2 {
		fd: 0,
		transid: 0,
		flags: 0,
		unused: [0; 4],
		name: [0; BTRFS_SUBVOL_NAME_MAX + 1],
	};
	for (dst, &byte) in args.name.iter_mut().zip(bytes) {
		*dst = byte as libc::c_char;
	}
	cvt_long(unsafe {
		libc::syscall(
			libc::SYS_ioctl,
			parent.as_raw_fd(),
			BTRFS_IOC_SNAP_DESTROY_V2,
			&mut args,
		)
	})
}

fn clone_tree(src: &File, dst_parent: &File, dst_name: &CStr) -> io::Result<()> {
	if btrfs_snapshot(src, dst_parent, dst_name).is_ok() {
		return Ok(());
	}
	let src_meta = src.metadata()?;
	mkdir(dst_parent, dst_name, src_meta.mode() & 0o7777)?;
	let dst = match open_dir_fd(dst_parent.as_raw_fd(), dst_name) {
		Ok(dir) => dir,
		Err(error) => {
			drop(unlink(dst_parent, dst_name, true));
			return Err(error);
		}
	};
	let mut hardlinks = HashMap::new();
	if let Err(error) = clone_dir_contents(src, &dst, &mut hardlinks)
		.and_then(|()| copy_xattrs(src, &dst))
		.and_then(|()| copy_dir_metadata(&src_meta, &dst))
	{
		drop(dst);
		drop(remove_tree(dst_parent, dst_name));
		return Err(error);
	}
	Ok(())
}

fn list_dir_names(dir: &File) -> io::Result<Vec<CString>> {
	let cursor = DirCursor::new(dir)?;
	let mut names = Vec::new();
	loop {
		errno_clear();
		let entry = unsafe { libc::readdir(cursor.0.as_ptr()) };
		if entry.is_null() {
			let error = io::Error::last_os_error();
			return if error.raw_os_error() == Some(0) {
				Ok(names)
			} else {
				Err(error)
			};
		}
		let entry = unsafe { &*entry };
		let name = unsafe { CStr::from_ptr(entry.d_name.as_ptr()) };
		let bytes = name.to_bytes();
		if bytes == b"." || bytes == b".." {
			continue;
		}
		validate_component(bytes)?;
		names.push(CString::from(name));
	}
}

fn clone_dir_contents(
	src: &File,
	dst: &File,
	hardlinks: &mut HashMap<(u64, u64), File>,
) -> io::Result<()> {
	for name in list_dir_names(src)? {
		let child = inspect_name(src.as_raw_fd(), &name)?;
		let meta = child.metadata()?;
		let file_type = meta.file_type();
		if file_type.is_dir() {
			mkdir(dst, &name, meta.mode() & 0o7777)?;
			let child_src = open_dir_fd(src.as_raw_fd(), &name)?;
			let child_dst = open_dir_fd(dst.as_raw_fd(), &name)?;
			clone_dir_contents(&child_src, &child_dst, hardlinks)?;
			copy_xattrs(&child_src, &child_dst)?;
			copy_dir_metadata(&meta, &child_dst)?;
		} else if file_type.is_file() {
			let identity = (meta.dev(), meta.ino());
			if meta.nlink() > 1
				&& let Some(existing) = hardlinks.get(&identity)
			{
				link(existing, dst, &name)?;
				continue;
			}
			let src_file = open_cstr(
				src.as_raw_fd(),
				&name,
				libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
				0,
			)?;
			let dst_file = open_cstr(
				dst.as_raw_fd(),
				&name,
				libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
				meta.mode() & 0o7777,
			)?;
			clone_file_data(&src_file, &dst_file, meta.size())?;
			copy_xattrs(&src_file, &dst_file)?;
			chmod(&dst_file, meta.mode() & 0o7777)?;
			timestamps(&dst_file, meta_atime(&meta), meta_mtime(&meta))?;
			if meta.nlink() > 1 {
				hardlinks.insert(identity, inspect_name(dst.as_raw_fd(), &name)?);
			}
		} else if file_type.is_symlink() {
			let target = CString::new(read_link(&child)?)
				.map_err(|_| io::Error::from_raw_os_error(libc::EIO))?;
			symlink(&target, dst, &name)?;
			symlink_timestamps(dst, &name, meta_atime(&meta), meta_mtime(&meta))?;
		}
	}
	Ok(())
}

fn clone_file_data(src: &File, dst: &File, len: u64) -> io::Result<()> {
	if len == 0 {
		return Ok(());
	}
	// Prefer a CoW reflink (Btrfs, XFS, bcachefs); fall back to in-kernel copy
	// when the underlying filesystem does not support block cloning.
	if cvt_long(unsafe {
		libc::syscall(libc::SYS_ioctl, dst.as_raw_fd(), FICLONE, src.as_raw_fd())
	})
	.is_ok()
	{
		return Ok(());
	}
	let mut remaining = len;
	while remaining > 0 {
		let chunk = remaining.min(1 << 30) as usize;
		let Ok(copied) = rustix::fs::copy_file_range(src, None, dst, None, chunk) else {
			return copy_file_fallback(src, dst, len);
		};
		if copied == 0 {
			break;
		}
		remaining = remaining.saturating_sub(copied as u64);
	}
	Ok(())
}

fn copy_file_fallback(src: &File, dst: &File, len: u64) -> io::Result<()> {
	let mut buf = vec![0u8; 64 * 1024];
	let mut offset = 0i64;
	let mut remaining = len;
	while remaining > 0 {
		let ask = buf.len().min(remaining as usize);
		let read = unsafe { libc::pread(src.as_raw_fd(), buf.as_mut_ptr().cast(), ask, offset) };
		if read < 0 {
			return Err(io::Error::last_os_error());
		}
		if read == 0 {
			break;
		}
		let mut written = 0usize;
		while written < read as usize {
			let n = unsafe {
				libc::pwrite(
					dst.as_raw_fd(),
					buf[written..].as_ptr().cast(),
					read as usize - written,
					offset + written as i64,
				)
			};
			if n < 0 {
				return Err(io::Error::last_os_error());
			}
			written += n as usize;
		}
		offset += read as i64;
		remaining = remaining.saturating_sub(read as u64);
	}
	Ok(())
}

fn copy_xattrs(src: &File, dst: &File) -> io::Result<()> {
	let list = match get_xattr(src, None) {
		Ok(list) => list,
		Err(error) if error.raw_os_error() == Some(libc::EOPNOTSUPP) => return Ok(()),
		Err(error) => return Err(error),
	};
	for entry in filter_xattr_list(None, list)?.split_inclusive(|byte| *byte == 0) {
		let name = CStr::from_bytes_with_nul(entry)
			.map_err(|_| io::Error::from_raw_os_error(libc::EIO))?;
		let value = get_xattr(src, Some(name))?;
		set_xattr(dst, name, &value, 0)?;
	}
	Ok(())
}

fn copy_dir_metadata(meta: &std::fs::Metadata, dst: &File) -> io::Result<()> {
	chmod(dst, meta.mode() & 0o7777)?;
	timestamps(dst, meta_atime(meta), meta_mtime(meta))
}

fn meta_atime(meta: &std::fs::Metadata) -> libc::timespec {
	libc::timespec {
		tv_sec: meta.atime(),
		tv_nsec: meta.atime_nsec(),
	}
}

fn meta_mtime(meta: &std::fs::Metadata) -> libc::timespec {
	libc::timespec {
		tv_sec: meta.mtime(),
		tv_nsec: meta.mtime_nsec(),
	}
}

fn symlink_timestamps(
	parent: &File,
	name: &CStr,
	atime: libc::timespec,
	mtime: libc::timespec,
) -> io::Result<()> {
	let times = [atime, mtime];
	cvt(unsafe {
		libc::utimensat(
			parent.as_raw_fd(),
			name.as_ptr(),
			times.as_ptr(),
			libc::AT_SYMLINK_NOFOLLOW,
		)
	})
}

fn clear_dir_contents(dir: &File) -> io::Result<()> {
	for name in list_dir_names(dir)? {
		remove_tree(dir, &name)?;
	}
	Ok(())
}

fn remove_tree(parent: &File, name: &CStr) -> io::Result<()> {
	let child = inspect_name(parent.as_raw_fd(), name)?;
	let meta = child.metadata()?;
	if meta.is_dir() {
		let dir = open_dir_fd(parent.as_raw_fd(), name)?;
		clear_dir_contents(&dir)?;
		drop(dir);
		if let Err(error) = unlink(parent, name, true) {
			if btrfs_destroy_subvol(parent, name).is_ok() {
				return Ok(());
			}
			return Err(error);
		}
		Ok(())
	} else {
		unlink(parent, name, false)
	}
}
