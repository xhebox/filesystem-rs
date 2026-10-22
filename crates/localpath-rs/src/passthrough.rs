//! The confined passthrough filesystem and its FUSE protocol surface.
//!
//! There is a single abstraction here: [`PassthroughFs`] implements
//! [`fuse_api::FileSystem`] directly. Request parsing, dispatch, and reply
//! encoding belong to whoever drives the file system; this module holds the
//! confined state (inode table, handles) and performs the host I/O. The
//! security posture lives entirely in this module: the preopened root
//! directory is the sole authority, every resolution is a single validated
//! component against a confined handle, and the per-OS resolution code lives
//! in the `linux`/`macos` submodules (`stub` marks the surface for platforms
//! that have no implementation).
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
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::ptr::NonNull;
use std::sync::Arc;

/// The engine's failure as an I/O error: a failed call carries the `io::Error`
/// behind it, and a cancelled or stopped one has none.
fn engine_io(error: completion::Error) -> io::Error {
	io::Error::try_from(error).unwrap_or_else(io::Error::other)
}

std::cfg_select! {
	target_os = "linux" => {
		#[path = "linux.rs"]
		mod linux;
		use linux as imp;
	}
	target_os = "macos" => {
		#[path = "macos.rs"]
		mod macos;
		use macos as imp;
	}
	_ => {
		#[path = "stub.rs"]
		mod stub;
		use stub as imp;
	}
}

use crate::abi::{
	FATTR_ATIME, FATTR_ATIME_NOW, FATTR_GID, FATTR_MODE, FATTR_MTIME, FATTR_MTIME_NOW, FATTR_SIZE,
	FATTR_UID, FOPEN_DIRECT_IO, FUSE_ASYNC_READ, FUSE_BIG_WRITES, ROOT_ID,
};
#[cfg(target_os = "linux")]
use crate::abi::{FATTR_CTIME, FUSE_MAX_PAGES};
use crate::span::Span;
use fuse_api::{
	Attr, Context, CreateArgs, DirEntry, DirentInfo, Entry, FileSystem, GetxattrReply, Kstatfs,
	ListxattrReply, ZeroCopyReader, ZeroCopyWriter,
};

/// Zero attribute/data timeouts: nothing the guest caches may outlive the
/// request that produced it.
const NO_CACHE: Timeout = (0, 0);

/// Attribute-cache timeout, `(seconds, nanoseconds)`.
type Timeout = (u64, u32);

/// The file-type bits of a mode, and the regular-file type, as `u32`. Darwin
/// spells them `u16`, Linux `u32`: the cast widens the one and is a no-op on the
/// other.
#[allow(
	clippy::unnecessary_cast,
	reason = "the cast widens Darwin's u16 values"
)]
const FILE_TYPE_MASK: u32 = libc::S_IFMT as u32;
#[allow(
	clippy::unnecessary_cast,
	reason = "the cast widens Darwin's u16 values"
)]
const REGULAR_FILE: u32 = libc::S_IFREG as u32;

/// `FUSE_RENAME2` flags; the same values as the Linux `RENAME_*` constants.
/// The Linux `imp` forwards them verbatim to `renameat2`; Darwin maps them
/// to `renameatx_np`.
#[cfg_attr(target_os = "linux", allow(dead_code))]
const RENAME_NOREPLACE: u32 = 1;
#[cfg_attr(target_os = "linux", allow(dead_code))]
const RENAME_EXCHANGE: u32 = 2;

pub(super) type Inode = u64;
pub(super) type Handle = u64;

/// A confined handle plus the locator needed to re-derive it by name.
///
/// Platforms without an atomic fd-upgrade primitive (macOS now, Windows
/// later) re-open `(parent, name)` with the requested flags and verify the
/// identity of the result against `file`; platforms with `openat2` upgrade
/// `file` directly and ignore the locator. `file` is the authority for the
/// object's identity — the locator is a hint that may go stale after
/// host-side renames/unlinks, which surfaces to the guest as `ESTALE`.
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
///
/// A `telldir` cookie only means something to the stream that minted it:
/// Darwin counts from where its stream started, so a stream opened per call
/// renumbers the same directory and `seekdir` lands elsewhere. The guest's
/// continuation offsets are these cookies, so the stream lives as long as the
/// handle.
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
struct RawDirEntry {
	inode: Inode,
	offset: u64,
	kind: u32,
	name: Vec<u8>,
}

/// The mutable filesystem state. See [`PassthroughFs`] for the threading
/// model; everything here is confined to the thread that drives the back-end.
struct FsState {
	read_only: bool,
	nodes: HashMap<Inode, Node>,
	identities: HashMap<(u64, u64), Inode>,
	next_inode: Inode,
	handles: HashMap<Handle, Resource>,
	next_handle: Handle,
}

/// A confined host directory tree rooted at a file descriptor opened before
/// any jail transition.
pub struct PassthroughFs {
	state: RefCell<FsState>,
}

impl PassthroughFs {
	pub fn new(root: File, read_only: bool) -> io::Result<Self> {
		let state = FsState::new(root, read_only)?;
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

	fn with<R>(&self, f: impl FnOnce(&mut FsState) -> io::Result<R>) -> io::Result<R> {
		f(&mut self.state.borrow_mut())
	}
}

impl FsState {
	fn new(root: File, read_only: bool) -> io::Result<Self> {
		let metadata = root.metadata()?;
		if !metadata.is_dir() {
			return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
		}
		// Probe the exact policy used for all later resolution.  ENOSYS and
		// filesystems that reject these flags are startup failures, never a
		// reason to weaken the confinement policy.
		imp::probe(root.as_raw_fd())?;
		let root_node = imp::inspect(root.as_raw_fd(), Path::new("."))?;
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
		let file = imp::inspect_name(self.node(parent)?.file.as_raw_fd(), name)?;
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
		imp::reopen(&node.file, parent.file.as_raw_fd(), &node.name, open_flags)
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
		imp::open_name_with_mode(
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
		imp::reopen(&node.file, parent.file.as_raw_fd(), &node.name, flags)
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
			imp::errno_clear();
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
				kind: entry.d_type as u32,
				name: name.to_vec(),
			});
			bytes += entry_len;
		}
	}
}

impl FsState {
	fn lookup(&mut self, _: &Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
		let (inode, metadata) = self.lookup_child(parent, name)?;
		Ok(self.entry(inode, &metadata))
	}

	fn getattr(&mut self, _: &Context, inode: Inode) -> io::Result<Attr> {
		let metadata = self.node(inode)?.file.metadata()?;
		Ok(Self::wire_attr(inode, &metadata))
	}

	fn setattr(&mut self, _: &Context, inode: Inode, attr: Attr, valid: u32) -> io::Result<Attr> {
		self.writable()?;
		#[cfg(target_os = "linux")]
		if valid & (FATTR_CTIME) != 0 {
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
		if valid & (FATTR_MODE) != 0 {
			imp::chmod(&file, attr.mode & 0o7777)?;
		}
		if valid & (FATTR_UID | FATTR_GID) != 0 {
			imp::chown(
				&file,
				if valid & (FATTR_UID) != 0 {
					attr.uid
				} else {
					u32::MAX
				},
				if valid & (FATTR_GID) != 0 {
					attr.gid
				} else {
					u32::MAX
				},
			)?;
		}
		if valid & (FATTR_SIZE) != 0 {
			imp::truncate(&file, attr.size)?;
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
			let atime = if valid & (FATTR_ATIME_NOW) != 0 {
				now
			} else if valid & (FATTR_ATIME) != 0 {
				timespec((attr.atime, attr.atimensec))?
			} else {
				omit
			};
			let mtime = if valid & (FATTR_MTIME_NOW) != 0 {
				now
			} else if valid & (FATTR_MTIME) != 0 {
				timespec((attr.mtime, attr.mtimensec))?
			} else {
				omit
			};
			imp::timestamps(&file, atime, mtime)?;
		}
		self.getattr(&Context::default(), inode)
	}

	fn open(&mut self, _: &Context, inode: Inode, flags: u32) -> io::Result<Handle> {
		let file = self.open_resource(inode, flags, false)?;
		let handle = self.allocate_handle(Resource::File(completion::File::new(file)))?;
		log::debug!("backend open inode={inode} flags={flags} handle={handle}");
		Ok(handle)
	}

	fn create(
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

	fn mkdir(
		&mut self,
		context: &Context,
		parent: Inode,
		name: &CStr,
		mode: u32,
	) -> io::Result<Entry> {
		self.writable()?;
		validate_component(name.to_bytes())?;
		imp::mkdir(
			self.parent_file(parent)?,
			name,
			mode & !context_umask(context) & 0o7777,
		)?;
		let (inode, metadata) = self.lookup_child(parent, name)?;
		Ok(self.entry(inode, &metadata))
	}

	fn mknod(
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
		imp::mknod(
			self.parent_file(parent)?,
			name,
			mode & !context_umask(context),
			rdev,
		)?;
		let (inode, metadata) = self.lookup_child(parent, name)?;
		Ok(self.entry(inode, &metadata))
	}

	fn unlink(
		&mut self,
		_: &Context,
		parent: Inode,
		name: &CStr,
		directory: bool,
	) -> io::Result<()> {
		self.writable()?;
		validate_component(name.to_bytes())?;
		imp::unlink(self.parent_file(parent)?, name, directory)
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
		validate_component(old_name.to_bytes())?;
		validate_component(new_name.to_bytes())?;
		imp::rename(
			self.parent_file(old_parent)?,
			old_name,
			self.parent_file(new_parent)?,
			new_name,
			flags,
		)
	}

	fn link(&mut self, _: &Context, inode: Inode, parent: Inode, name: &CStr) -> io::Result<Entry> {
		self.writable()?;
		validate_component(name.to_bytes())?;
		imp::link(&self.node(inode)?.file, self.parent_file(parent)?, name)?;
		let (inode, metadata) = self.lookup_child(parent, name)?;
		Ok(self.entry(inode, &metadata))
	}

	fn symlink(
		&mut self,
		_: &Context,
		parent: Inode,
		name: &CStr,
		target: &CStr,
	) -> io::Result<Entry> {
		self.writable()?;
		validate_component(name.to_bytes())?;
		imp::symlink(target, self.parent_file(parent)?, name)?;
		let (inode, metadata) = self.lookup_child(parent, name)?;
		Ok(self.entry(inode, &metadata))
	}

	/// Reads into `out` through the facade, for the tests that move file data:
	/// a file shorter than `out` gives the short count the guest would get.
	#[cfg_attr(not(test), expect(dead_code))]
	async fn read(&self, handle: Handle, offset: u64, out: &mut [u8]) -> io::Result<usize> {
		let file = match self.handles.get(&handle) {
			Some(Resource::File(file)) => file.clone(),
			_ => {
				log::warn!("backend read on unknown handle={handle}");
				return Err(io::Error::from_raw_os_error(libc::EBADF));
			}
		};
		let mut buffer = completion::Buffer::zeroed(out.len());
		let outcome = file.read_exact_at(buffer.clone(), offset).await;
		let count = match outcome.result.map_err(engine_io) {
			Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => outcome.value,
			result => result.map(|()| outcome.value)?,
		};
		out[..count].copy_from_slice(&buffer.get_mut().expect("the read landed")[0..count]);
		log::debug!(
			"backend read handle={handle} offset={offset} len={} count={count}",
			out.len()
		);
		Ok(count)
	}

	/// Writes `data` through the facade, for the tests that move file data.
	#[cfg_attr(not(test), expect(dead_code))]
	async fn write(&self, handle: Handle, offset: u64, data: &[u8]) -> io::Result<usize> {
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
		let result = file
			.write_all_at(buffer, offset)
			.await
			.into_result()
			.map_err(engine_io);
		log::debug!(
			"backend write handle={handle} offset={offset} len={} result={result:?}",
			data.len()
		);
		result
	}

	fn release(&mut self, handle: Handle) -> io::Result<()> {
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

	fn access(&mut self, context: &Context, inode: Inode, mask: u32) -> io::Result<()> {
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
	/// the only namespace exposed is `user.*`, which neither Darwin nor
	/// Linux supports on a symlink, and opening the link to reach them is
	/// what `object_file` refuses with `ELOOP` — an errno a caller that
	/// asked `llistxattr` must not see.
	fn is_symlink(&self, inode: Inode) -> io::Result<bool> {
		Ok(self.node(inode)?.file.metadata()?.file_type().is_symlink())
	}

	fn set_xattr(
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
		imp::set_xattr(&file, name, value, flags)
	}

	fn get_xattr(
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
		let value = filter_xattr_list(name, imp::get_xattr(&file, name)?)?;
		if size != 0 && value.len() > size {
			return Err(io::Error::from_raw_os_error(libc::ERANGE));
		}
		Ok(value)
	}

	fn remove_xattr(&mut self, _: &Context, inode: Inode, name: &CStr) -> io::Result<()> {
		self.writable()?;
		ensure_user_xattr(name)?;
		if self.is_symlink(inode)? {
			return Err(io::Error::from_raw_os_error(libc::EPERM));
		}
		let file = self.object_file(inode, libc::O_RDONLY)?;
		imp::remove_xattr(&file, name)
	}

	fn open_dir(&mut self, _: &Context, inode: Inode, flags: u32) -> io::Result<Handle> {
		let file = self.open_resource(inode, flags, true)?;
		let cursor = DirCursor::new(&file)?;
		self.allocate_handle(Resource::Dir {
			file: completion::File::new(file),
			inode,
			cursor,
		})
	}

	fn read_dir(
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
		imp::statfs(&file)
	}

	fn read_link(&mut self, inode: Inode) -> io::Result<Vec<u8>> {
		imp::read_link(&self.node(inode)?.file)
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
}

/// The guest umask of a request. Only `create` carries one on the wire; every
/// other request sees zero.
fn context_umask(_: &Context) -> u32 {
	0
}

impl FileSystem for PassthroughFs {
	type Inode = u64;
	type Handle = u64;

	async fn init(&self, capable: u32) -> io::Result<u32> {
		// Asynchronous reads, big writes, and page-based limits. Caching is
		// refused via the zero timeouts and DIRECT_IO on every open.
		#[cfg(target_os = "linux")]
		let want = FUSE_ASYNC_READ | FUSE_BIG_WRITES | FUSE_MAX_PAGES;
		#[cfg(not(target_os = "linux"))]
		let want = FUSE_ASYNC_READ | FUSE_BIG_WRITES;
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
		// The state layer derives the umask from the guest context, which
		// carries the guest's own umask convention.
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

/// Reads up to `size` bytes of `file` at `offset` into the reply body.
///
/// One call moves one extent: the engine's span resolves to one pointer, and
/// the reply's ranges are not contiguous. The calls go out together and are
/// waited in order, so the file is read once and the reply's ranges are filled
/// in the order the guest named them; the end of the file ends it, and the
/// bytes moved by then are a short read, not a failure.
async fn read_into(
	file: &completion::File,
	out: &dyn ZeroCopyWriter,
	size: usize,
	offset: u64,
) -> io::Result<usize> {
	let memory = out.memory();
	let mut room = size;
	let mut at = offset;
	let mut calls = Vec::new();
	for extent in out.extents() {
		let len = extent.len.min(room);
		if len == 0 {
			break;
		}
		let Ok(span) = Span::new(Arc::clone(&memory), extent.offset as usize, len) else {
			break;
		};
		calls.push(file.read_exact_at(span, at));
		at += len as u64;
		room -= len;
		if room == 0 {
			break;
		}
	}
	// A call that stops early reports what it did read beside its failure, and
	// the end of the file is such a stop: the reply is a short read, and the
	// range the call did not fill stays unwritten.
	let mut read = 0;
	for call in calls {
		let outcome = call.await;
		read += outcome.value;
		match outcome.result.map_err(engine_io) {
			Ok(()) => {}
			Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(read),
			Err(error) => return Err(error),
		}
	}
	Ok(read)
}

/// Writes up to `size` request bytes into `file` at `offset`.
///
/// One call moves one extent, for the reason [`read_into`] gives; a call that
/// writes nothing stops it with the failure the guest must see.
async fn write_into(
	file: &completion::File,
	input: &dyn ZeroCopyReader,
	size: usize,
	offset: u64,
) -> io::Result<usize> {
	let memory = input.memory();
	let mut written = 0;
	let mut at = offset;
	// An empty extent carries no bytes: it is skipped rather than submitted.
	for extent in input
		.extents(size)
		.into_iter()
		.filter(|extent| extent.len != 0)
	{
		let Ok(span) = Span::new(Arc::clone(&memory), extent.offset as usize, extent.len) else {
			break;
		};
		match file.write_all_at(span, at).await.into_result() {
			Ok(count) => written += count,
			Err(error) => return Err(engine_io(error)),
		}
		at += extent.len as u64;
	}
	Ok(written)
}

fn validate_component(name: &[u8]) -> io::Result<()> {
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

#[cfg(test)]
#[allow(
	clippy::await_holding_refcell_ref,
	reason = "the tests drive one request at a time on this thread, and nothing else borrows the state meanwhile"
)]
mod tests {
	use std::fs::{self, OpenOptions};
	use std::os::unix::fs::symlink;
	use std::os::unix::fs::{MetadataExt, PermissionsExt};

	use std::path::{Path, PathBuf};
	use std::sync::Arc;
	use std::sync::atomic::{AtomicUsize, Ordering};

	use completion::AsIoVec;
	use fuse_api::{Attr, Memory, MemoryRange};

	use super::*;

	/// A scratch directory under the workspace's `target/`, removed when it is
	/// dropped. Tests keep their trees there: the system temp directory is off
	/// limits in this workspace.
	struct Scratch(PathBuf);

	impl Scratch {
		fn new() -> Scratch {
			static NEXT: AtomicUsize = AtomicUsize::new(0);
			let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-tmp");
			let path = base.join(format!(
				"localpath-{}-{}",
				std::process::id(),
				NEXT.fetch_add(1, Ordering::Relaxed)
			));
			fs::create_dir_all(&path).unwrap();
			Scratch(path)
		}

		fn path(&self) -> &Path {
			&self.0
		}
	}

	impl Drop for Scratch {
		fn drop(&mut self) {
			drop(fs::remove_dir_all(&self.0));
		}
	}

	/// A filesystem on this thread's global executor. The tests that move file
	/// bytes drive it with [`completion::block_on`], which turns the reactor
	/// while it waits.
	fn filesystem(root: File, read_only: bool) -> PassthroughFs {
		PassthroughFs::new(root, read_only).unwrap()
	}

	/// The returned `Scratch` owns the tree; the caller keeps it alive for the
	/// whole test, and it is removed when the test ends.
	fn root() -> (Scratch, PathBuf, File) {
		let dir = Scratch::new();
		let path = dir.path().join("root");
		fs::create_dir(&path).unwrap();
		let file = OpenOptions::new().read(true).open(&path).unwrap();
		(dir, path, file)
	}

	#[test]
	fn rejects_non_component_names() {
		for name in [b"".as_slice(), b".", b"..", b"x/y", b"x\0"] {
			assert!(validate_component(name).is_err());
		}
	}

	#[test]
	fn constrained_lookup_cannot_escape_the_root() {
		let (_dir, path, root) = root();
		fs::write(path.join("inside"), b"ok").unwrap();
		symlink("/etc", path.join("escape")).unwrap();
		let fs = filesystem(root, false);
		let context = Context::default();
		let inside = fs.with(|state| state.lookup(&context, ROOT_ID, c"inside"));
		assert!(inside.is_ok(), "{inside:?}");
		assert!(
			fs.with(|state| { state.lookup(&context, ROOT_ID, c"../etc",) })
				.is_err()
		);
		// Kernels/filesystems may reject this escaping symlink during lookup or
		// return the link itself. In the latter case, opening it must still be
		// rejected by the same openat2 policy.
		let escape = fs.with(|state| state.lookup(&context, ROOT_ID, c"escape"));
		if let Ok(escape) = escape {
			assert!(
				fs.with(|state| state.open_dir(&context, escape.inode, libc::O_RDONLY as u32))
					.is_err()
			);
		}
	}

	#[test]
	fn file_handles_read_write_and_enforce_read_only() {
		let (_dir, path, root) = root();
		fs::write(path.join("file"), b"old").unwrap();
		let context = Context::default();
		let fs = filesystem(root, false);
		let entry = fs
			.with(|state| state.lookup(&context, ROOT_ID, c"file"))
			.unwrap();
		let handle = fs
			.with(|state| state.open(&context, entry.inode, libc::O_RDWR as u32))
			.unwrap();
		let written = completion::block_on(async {
			let state = fs.state.borrow();
			state.write(handle, 0, b"new").await
		})
		.unwrap()
		.unwrap();
		assert_eq!(written, 3);
		let mut data = [0; 3];
		let read = completion::block_on(async {
			let state = fs.state.borrow();
			state.read(handle, 0, &mut data).await
		})
		.unwrap()
		.unwrap();
		assert_eq!(read, 3);
		assert_eq!(&data, b"new");
		fs.with(|state| state.release(handle)).unwrap();

		let root = OpenOptions::new().read(true).open(&path).unwrap();
		let read_only = filesystem(root, true);
		let entry = read_only
			.with(|state| state.lookup(&context, ROOT_ID, c"file"))
			.unwrap();
		assert_eq!(
			read_only
				.with(|state| state.open(&context, entry.inode, libc::O_RDWR as u32))
				.unwrap_err()
				.raw_os_error(),
			Some(libc::EROFS)
		);
	}

	#[test]
	fn flush_on_a_closed_handle_is_an_error() {
		let (_dir, path, root) = root();
		fs::write(path.join("file"), b"old").unwrap();
		let context = Context::default();
		let fs = filesystem(root, false);
		let entry = fs
			.with(|state| state.lookup(&context, ROOT_ID, c"file"))
			.unwrap();
		let handle = fs
			.with(|state| state.open(&context, entry.inode, libc::O_RDWR as u32))
			.unwrap();
		// The handle is gone and its descriptor with it: a FLUSH that still
		// reports success is the no-op this replaces.
		fs.with(|state| state.release(handle)).unwrap();
		assert_eq!(
			completion::block_on(fs.flush(&context, entry.inode, handle))
				.unwrap()
				.unwrap_err()
				.raw_os_error(),
			Some(libc::EBADF)
		);
	}

	#[test]
	fn flush_leaves_the_handle_usable() {
		let (_dir, path, root) = root();
		fs::write(path.join("file"), b"old").unwrap();
		let context = Context::default();
		let fs = filesystem(root, false);
		let entry = fs
			.with(|state| state.lookup(&context, ROOT_ID, c"file"))
			.unwrap();
		let handle = fs
			.with(|state| state.open(&context, entry.inode, libc::O_RDWR as u32))
			.unwrap();
		completion::block_on(async {
			let state = fs.state.borrow();
			state.write(handle, 0, b"data").await
		})
		.unwrap()
		.unwrap();
		// FLUSH closes a duplicate of the handle's descriptor: the handle's own
		// descriptor must survive, or closing it would take the handle with it.
		completion::block_on(fs.flush(&context, entry.inode, handle))
			.unwrap()
			.unwrap();
		completion::block_on(async {
			let state = fs.state.borrow();
			state.write(handle, 4, b"more").await
		})
		.unwrap()
		.unwrap();
		let mut data = [0u8; 8];
		let read = completion::block_on(async {
			let state = fs.state.borrow();
			state.read(handle, 0, &mut data).await
		})
		.unwrap()
		.unwrap();
		assert_eq!(&data[..read], b"datamore");
		fs.with(|state| state.release(handle)).unwrap();
	}

	#[test]
	fn reads_a_symlink_through_its_confined_descriptor() {
		let (_dir, path, root) = root();
		symlink("/bin/busybox", path.join("sh")).unwrap();
		let context = Context::default();
		let fs = filesystem(root, false);
		let entry = fs
			.with(|state| state.lookup(&context, ROOT_ID, c"sh"))
			.unwrap();
		assert_eq!(
			fs.with(|state| state.read_link(entry.inode)).unwrap(),
			b"/bin/busybox"
		);
	}

	#[test]
	fn a_symlinks_own_xattrs_read_as_empty_not_eloop() {
		let (_dir, path, root) = root();
		symlink("/bin/busybox", path.join("sh")).unwrap();
		let context = Context::default();
		let fs = filesystem(root, false);
		let entry = fs
			.with(|state| state.lookup(&context, ROOT_ID, c"sh"))
			.unwrap();
		// `llistxattr` asks about the link itself: answering `ELOOP` (what
		// reaching its own attributes through an open would give) fails the
		// caller, which is how `mke2fs -d` stopped on a source with links.
		assert_eq!(
			fs.with(|state| state.get_xattr(&context, entry.inode, None, 0))
				.unwrap(),
			Vec::<u8>::new()
		);
		assert_eq!(
			fs.with(|state| { state.get_xattr(&context, entry.inode, Some(c"user.demo"), 0,) })
				.unwrap_err()
				.raw_os_error(),
			Some(libc::ENODATA)
		);
	}

	#[test]
	fn creates_files_with_the_guest_umask() {
		let (_dir, path, root) = root();
		let context = Context::default();
		let fs = filesystem(root, false);
		let (entry, handle) = fs
			.with(|state| {
				state.create(
					&context,
					ROOT_ID,
					c"created",
					libc::O_WRONLY as u32 | libc::O_CREAT as u32,
					0o666,
					0o022,
				)
			})
			.unwrap();
		let written = completion::block_on(async {
			let state = fs.state.borrow();
			state.write(handle, 0, b"ok").await
		})
		.unwrap()
		.unwrap();
		assert_eq!(written, 2);
		fs.with(|state| state.release(handle)).unwrap();
		assert_eq!(fs::read(path.join("created")).unwrap(), b"ok");
		assert_eq!(
			fs.with(|state| state.getattr(&context, entry.inode))
				.unwrap()
				.mode
				& 0o777,
			0o644
		);
	}

	#[test]
	fn mutates_the_namespace_without_reconstructing_paths() {
		let (_dir, path, root) = root();
		let context = Context::default();
		let fs = filesystem(root, false);
		let name = c"dir";
		let directory = fs
			.with(|state| state.mkdir(&context, ROOT_ID, name, 0o777))
			.unwrap();
		let file_name = c"file";
		let (file, handle) = fs
			.with(|state| {
				state.create(
					&context,
					directory.inode,
					file_name,
					libc::O_WRONLY as u32,
					0o666,
					0o022,
				)
			})
			.unwrap();
		completion::block_on(async {
			let state = fs.state.borrow();
			state.write(handle, 0, b"data").await
		})
		.unwrap()
		.unwrap();
		fs.with(|state| {
			state.rename(
				&context,
				directory.inode,
				file_name,
				directory.inode,
				c"renamed",
				0,
			)
		})
		.unwrap();
		fs.with(|state| state.release(handle)).unwrap();
		fs.with(|state| state.link(&context, file.inode, directory.inode, c"hard"))
			.unwrap();
		fs.with(|state| state.symlink(&context, directory.inode, c"sym", c"renamed"))
			.unwrap();
		fs.with(|state| state.unlink(&context, directory.inode, c"hard", false))
			.unwrap();
		fs.with(|state| state.unlink(&context, directory.inode, c"sym", false))
			.unwrap();
		fs.with(|state| state.unlink(&context, directory.inode, c"renamed", false))
			.unwrap();
		fs.with(|state| state.unlink(&context, ROOT_ID, name, true))
			.unwrap();
		assert!(!path.join("dir").exists());
	}

	#[test]
	fn setattr_updates_size_mode_and_timestamps() {
		let (_dir, path, root) = root();
		fs::write(path.join("file"), b"hello").unwrap();
		let context = Context::default();
		let fs = filesystem(root, false);
		let entry = fs
			.with(|state| state.lookup(&context, ROOT_ID, c"file"))
			.unwrap();
		let attr = Attr {
			size: 1,
			atime: 123,
			mtime: 456,
			mtimensec: 7,
			mode: 0o600,
			..Attr::default()
		};
		let attr = fs
			.with(|state| {
				state.setattr(
					&context,
					entry.inode,
					attr,
					FATTR_SIZE | FATTR_MODE | FATTR_ATIME | FATTR_MTIME,
				)
			})
			.unwrap();
		assert_eq!(fs::read(path.join("file")).unwrap(), b"h");
		assert_eq!(attr.mode & 0o7777, 0o600);
		assert_eq!(attr.atime, 123);
		assert_eq!(attr.mtime, 456);
		assert_eq!(attr.mtimensec, 7);
	}

	#[test]
	fn access_checks_mode_bits_and_read_only_writes() {
		let (_dir, path, root) = root();
		fs::write(path.join("file"), b"ok").unwrap();
		fs::set_permissions(path.join("file"), fs::Permissions::from_mode(0o640)).unwrap();
		let context = Context::default();
		let fs = filesystem(root, false);
		let entry = fs
			.with(|state| state.lookup(&context, ROOT_ID, c"file"))
			.unwrap();
		let metadata = fs::metadata(path.join("file")).unwrap();
		let owner = Context {
			uid: metadata.uid(),
			gid: metadata.gid(),
			..Context::default()
		};
		fs.with(|state| state.access(&owner, entry.inode, libc::R_OK as u32))
			.unwrap();
		assert_eq!(
			fs.with(|state| state.access(&owner, entry.inode, libc::X_OK as u32))
				.unwrap_err()
				.raw_os_error(),
			Some(libc::EACCES)
		);

		let root = OpenOptions::new().read(true).open(&path).unwrap();
		let read_only = filesystem(root, true);
		let entry = read_only
			.with(|state| state.lookup(&owner, ROOT_ID, c"file"))
			.unwrap();
		assert_eq!(
			read_only
				.with(|state| state.access(&owner, entry.inode, libc::W_OK as u32))
				.unwrap_err()
				.raw_os_error(),
			Some(libc::EROFS)
		);
	}

	#[test]
	fn user_xattrs_are_supported_and_filtered() {
		let (_dir, path, root) = root();
		fs::write(path.join("file"), b"ok").unwrap();
		let context = Context::default();
		let fs = filesystem(root, false);
		let entry = fs
			.with(|state| state.lookup(&context, ROOT_ID, c"file"))
			.unwrap();
		let user_name = c"user.demo";
		fs.with(|state| state.set_xattr(&context, entry.inode, user_name, b"value", 0))
			.unwrap();
		assert_eq!(
			fs.with(|state| state.get_xattr(&context, entry.inode, Some(user_name), 0))
				.unwrap(),
			b"value"
		);
		assert_eq!(
			fs.with(|state| state.get_xattr(&context, entry.inode, Some(user_name), 3))
				.unwrap_err()
				.raw_os_error(),
			Some(libc::ERANGE)
		);
		assert_eq!(
			fs.with(|state| { state.set_xattr(&context, entry.inode, c"security.demo", b"x", 0,) })
				.unwrap_err()
				.raw_os_error(),
			Some(libc::EPERM)
		);
		// Hidden namespaces read as absent: execve probes security.capability
		// and must not be told EPERM, or executables fail to start.
		assert_eq!(
			fs.with(|state| {
				state.get_xattr(&context, entry.inode, Some(c"security.capability"), 0)
			})
			.unwrap_err()
			.raw_os_error(),
			Some(libc::ENODATA)
		);
		assert_eq!(
			fs.with(|state| state.get_xattr(&context, entry.inode, None, 0))
				.unwrap(),
			b"user.demo\0"
		);
		fs.with(|state| state.remove_xattr(&context, entry.inode, user_name))
			.unwrap();
		assert_eq!(
			fs.with(|state| state.get_xattr(&context, entry.inode, None, 0))
				.unwrap(),
			b""
		);
	}

	/// A listing reaches the guest in batches: it takes the offset of the last
	/// entry it was handed and asks again from there. Every entry must come
	/// back, however the batch boundary falls.
	#[test]
	fn a_directory_lists_every_entry_across_batches() {
		let (_dir, path, file) = root();
		let names: Vec<String> = (0..300).map(|index| format!("entry-{index:03}")).collect();
		for name in &names {
			fs::write(path.join(name), b"x").unwrap();
		}
		let fs = filesystem(file, false);
		let mut state = fs.state.borrow_mut();
		let ctx = Context::new(0, 0, 0);
		let handle = state
			.open_dir(&ctx, ROOT_ID, libc::O_RDONLY as u32)
			.expect("open the root");

		let mut seen = Vec::new();
		let mut offset = 0u64;
		loop {
			let batch = state.read_dir(handle, offset, 4096).unwrap();
			let Some(last) = batch.last() else { break };
			assert!(
				last.offset > offset,
				"an entry's offset must move the stream forward: {offset} -> {}",
				last.offset
			);
			offset = last.offset;
			for entry in batch {
				seen.push(String::from_utf8_lossy(&entry.name).into_owned());
				// The guest kernel forgets an inode once it drops its last
				// reference, which is what closes the server's per-inode
				// descriptor; a test that lists without forgetting would hold
				// one descriptor per entry and run out.
				state.forget(entry.inode, 1);
			}
		}
		seen.sort();
		assert_eq!(seen, names, "the listing dropped entries");
	}

	/// A completion-owned allocation that is its own guest memory, so the
	/// back-end's reads land in it.
	struct Bytes(completion::Buffer);

	// SAFETY: the buffer owns one allocation that never moves, and `resolve`
	// bounds-checks every range against it.
	unsafe impl Memory for Bytes {
		fn resolve(&self, offset: usize, len: usize) -> io::Result<MemoryRange> {
			let whole = self.0.as_iovec();
			if offset.checked_add(len).is_none_or(|end| end > whole.len) {
				return Err(io::Error::new(
					io::ErrorKind::InvalidInput,
					"range outside the buffer",
				));
			}
			Ok(MemoryRange {
				// SAFETY: the range was just checked to lie inside the allocation.
				ptr: unsafe { whole.ptr.add(offset) },
				len,
			})
		}
	}

	/// A reply body over a plain buffer, the shape the back-end writes into.
	struct Buffer {
		memory: Arc<Bytes>,
		written: usize,
	}

	impl Buffer {
		fn new(len: usize) -> Buffer {
			Buffer {
				memory: Arc::new(Bytes(completion::Buffer::zeroed(len))),
				written: 0,
			}
		}

		fn bytes(&self) -> Vec<u8> {
			let whole = self.memory.0.as_iovec();
			// SAFETY: the allocation is `whole.len` zeroed bytes that `self` owns,
			// and `written` never exceeds that.
			unsafe { std::slice::from_raw_parts(whole.ptr, self.written) }.to_vec()
		}
	}

	impl ZeroCopyWriter for Buffer {
		fn memory(&self) -> Arc<dyn Memory> {
			self.memory.clone()
		}

		fn extents(&self) -> Vec<fuse_api::Extent> {
			vec![fuse_api::Extent {
				offset: 0,
				len: self.memory.0.len(),
			}]
		}

		fn written(&mut self, count: usize) -> io::Result<()> {
			self.written = count;
			Ok(())
		}
	}

	/// A read that runs past the end of the file is a short READ, not an error:
	/// the guest takes the count and the bytes the file had.
	#[test]
	fn a_read_past_the_end_of_a_file_is_a_short_count() {
		let (_dir, path, root) = root();
		fs::write(path.join("file"), b"four").unwrap();
		let fs = filesystem(root, false);
		let context = Context::default();
		let entry = completion::block_on(fs.lookup(&context, ROOT_ID, c"file"))
			.unwrap()
			.unwrap();
		let handle = completion::block_on(fs.open(&context, entry.inode, libc::O_RDONLY as u32))
			.unwrap()
			.unwrap()
			.0;
		let mut out = Buffer::new(16);
		let count = completion::block_on(fs.read(&context, entry.inode, handle, &mut out, 16, 0))
			.unwrap()
			.unwrap();
		assert_eq!(count, 4);
		assert_eq!(out.bytes(), b"four");
	}
}
