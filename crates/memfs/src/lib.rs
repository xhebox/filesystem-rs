//! An in-memory file system with structural-sharing Copy-on-Write snapshots.
//!
//! [`MemFs`] implements [`api::Fuse`], [`api::Volume`], and [`api::Snapshot`]
//! over persistent [`imbl`] trees:
//!
//! - The inode table is an [`imbl::HashMap`], so [`Snapshot::snapshot`],
//!   [`Snapshot::branch`], and [`Snapshot::restore`] are $O(1)$ pointer clones.
//! - Directories and extended attributes are [`imbl::OrdMap`]s, sharing
//!   unchanged subtrees across snapshots.
//! - Regular file data is stored as an [`imbl::Vector`] of 4 KiB pages
//!   (`Option<Arc<[u8; PAGE_SIZE]>>`, where `None` represents a sparse zero
//!   page), so a small edit to a large file after a snapshot copies only the
//!   touched 4 KiB pages.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::CStr;
use std::io;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use api::{
	Attr, Context, CreateArgs, DirEntry, DirentInfo, Entry, Fuse, GetxattrReply, Kstatfs,
	ListxattrReply, Snapshot, Volume, ZeroCopyReader, ZeroCopyWriter,
};
use imbl::{HashMap as ImHashMap, OrdMap, Vector};

const PAGE_SIZE: usize = 4096;
const ROOT_ID: u64 = 1;
const NO_CACHE: (u64, u32) = (0, 0);

const FATTR_MODE: u32 = 1 << 0;
const FATTR_UID: u32 = 1 << 1;
const FATTR_GID: u32 = 1 << 2;
const FATTR_SIZE: u32 = 1 << 3;
const FATTR_ATIME: u32 = 1 << 4;
const FATTR_MTIME: u32 = 1 << 5;
const FATTR_ATIME_NOW: u32 = 1 << 7;
const FATTR_MTIME_NOW: u32 = 1 << 8;
const FATTR_CTIME: u32 = 1 << 10;

const FOPEN_DIRECT_IO: u32 = 1 << 0;
const FUSE_ASYNC_READ: u32 = 1 << 0;
const FUSE_BIG_WRITES: u32 = 1 << 5;

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

const DT_DIR: u32 = 4;
const DT_REG: u32 = 8;
const DT_LNK: u32 = 10;

const O_RDONLY: u32 = 0;
const O_WRONLY: u32 = 1;
const O_ACCMODE: u32 = 3;
const O_EXCL: u32 = libc::O_EXCL as u32;
const O_TRUNC: u32 = libc::O_TRUNC as u32;
const O_APPEND: u32 = libc::O_APPEND as u32;

const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;

const XATTR_CREATE: u32 = 1;
const XATTR_REPLACE: u32 = 2;

type Inode = u64;
type Handle = u64;
type Page = Arc<[u8; PAGE_SIZE]>;

#[derive(Clone)]
enum NodeKind {
	Dir {
		parent: Inode,
		entries: OrdMap<Vec<u8>, Inode>,
	},
	File {
		pages: Vector<Option<Page>>,
	},
	Symlink {
		target: Vec<u8>,
	},
}

#[derive(Clone)]
struct Node {
	attr: Attr,
	xattrs: OrdMap<Vec<u8>, Vec<u8>>,
	kind: NodeKind,
}

impl Node {
	fn is_dir(&self) -> bool {
		matches!(self.kind, NodeKind::Dir { .. })
	}

	fn is_file(&self) -> bool {
		matches!(self.kind, NodeKind::File { .. })
	}

	fn is_symlink(&self) -> bool {
		matches!(self.kind, NodeKind::Symlink { .. })
	}

	fn dt_type(&self) -> u32 {
		match self.kind {
			NodeKind::Dir { .. } => DT_DIR,
			NodeKind::File { .. } => DT_REG,
			NodeKind::Symlink { .. } => DT_LNK,
		}
	}
}

/// The persistent, structural-sharing filesystem tree. Cloning this struct is
/// $O(1)$.
#[derive(Clone)]
struct TreeState {
	nodes: ImHashMap<Inode, Node>,
	next_inode: Inode,
}

impl TreeState {
	fn new() -> Self {
		let mut nodes = ImHashMap::new();
		nodes.insert(
			ROOT_ID,
			Node {
				attr: Attr {
					ino: ROOT_ID,
					size: 0,
					blocks: 0,
					atime: 0,
					mtime: 0,
					ctime: 0,
					atimensec: 0,
					mtimensec: 0,
					ctimensec: 0,
					mode: S_IFDIR | 0o755,
					nlink: 2,
					uid: 0,
					gid: 0,
					rdev: 0,
					blksize: PAGE_SIZE as u32,
					flags: 0,
				},
				xattrs: OrdMap::new(),
				kind: NodeKind::Dir {
					parent: ROOT_ID,
					entries: OrdMap::new(),
				},
			},
		);
		Self {
			nodes,
			next_inode: ROOT_ID + 1,
		}
	}

	fn node(&self, ino: Inode) -> io::Result<&Node> {
		self.nodes.get(&ino).ok_or_else(|| errno(libc::ENOENT))
	}

	fn node_mut(&mut self, ino: Inode) -> io::Result<&mut Node> {
		self.nodes.get_mut(&ino).ok_or_else(|| errno(libc::ENOENT))
	}

	fn allocate_inode(&mut self) -> io::Result<Inode> {
		let ino = self.next_inode;
		self.next_inode = self
			.next_inode
			.checked_add(1)
			.ok_or_else(|| errno(libc::EOVERFLOW))?;
		Ok(ino)
	}
}

struct OpenHandle {
	inode: Inode,
	flags: u32,
	directory: bool,
}

struct SnapshotStore {
	snapshots: Mutex<ImHashMap<u64, TreeState>>,
	next_id: AtomicU64,
}

impl SnapshotStore {
	fn new() -> Self {
		Self {
			snapshots: Mutex::new(ImHashMap::new()),
			next_id: AtomicU64::new(1),
		}
	}
}

struct FsState {
	read_only: bool,
	tree: TreeState,
	handles: HashMap<Handle, OpenHandle>,
	next_handle: Handle,
	store: Arc<SnapshotStore>,
}

/// An in-memory file system with $O(1)$ Copy-on-Write snapshots and page-level
/// data sharing.
pub struct MemFs {
	state: RefCell<FsState>,
}

impl Default for MemFs {
	fn default() -> Self {
		Self::new(false)
	}
}

impl MemFs {
	/// Creates a new empty in-memory file system.
	pub fn new(read_only: bool) -> Self {
		Self {
			state: RefCell::new(FsState {
				read_only,
				tree: TreeState::new(),
				handles: HashMap::new(),
				next_handle: 1,
				store: Arc::new(SnapshotStore::new()),
			}),
		}
	}

	fn with<R>(&self, f: impl FnOnce(&mut FsState) -> io::Result<R>) -> io::Result<R> {
		f(&mut self.state.borrow_mut())
	}
}

impl FsState {
	fn writable(&self) -> io::Result<()> {
		if self.read_only {
			Err(errno(libc::EROFS))
		} else {
			Ok(())
		}
	}

	fn allocate_handle(&mut self, handle: OpenHandle) -> io::Result<Handle> {
		let id = self.next_handle;
		self.next_handle = self
			.next_handle
			.checked_add(1)
			.ok_or_else(|| errno(libc::EOVERFLOW))?;
		self.handles.insert(id, handle);
		Ok(id)
	}

	fn entry(node: &Node) -> Entry {
		Entry {
			inode: node.attr.ino,
			generation: 0,
			attr: node.attr,
			attr_timeout: NO_CACHE,
			entry_timeout: NO_CACHE,
		}
	}

	fn lookup_child(&self, parent: Inode, name: &[u8]) -> io::Result<Inode> {
		validate_component(name)?;
		let dir = self.tree.node(parent)?;
		match &dir.kind {
			NodeKind::Dir { entries, .. } => entries
				.get(name)
				.copied()
				.ok_or_else(|| errno(libc::ENOENT)),
			_ => Err(errno(libc::ENOTDIR)),
		}
	}

	fn lookup(&self, parent: Inode, name: &CStr) -> io::Result<Entry> {
		let child_ino = self.lookup_child(parent, name.to_bytes())?;
		let node = self.tree.node(child_ino)?;
		Ok(Self::entry(node))
	}

	fn getattr(&self, inode: Inode) -> io::Result<Attr> {
		Ok(self.tree.node(inode)?.attr)
	}

	fn setattr(&mut self, inode: Inode, attr: Attr, valid: u32) -> io::Result<Attr> {
		self.writable()?;
		if valid & FATTR_CTIME != 0 {
			return Err(errno(libc::EOPNOTSUPP));
		}
		if valid & (FATTR_ATIME | FATTR_ATIME_NOW) == (FATTR_ATIME | FATTR_ATIME_NOW)
			|| valid & (FATTR_MTIME | FATTR_MTIME_NOW) == (FATTR_MTIME | FATTR_MTIME_NOW)
		{
			return Err(errno(libc::EINVAL));
		}
		let node = self.tree.node_mut(inode)?;
		if node.is_symlink() {
			return Err(errno(libc::ELOOP));
		}
		if valid & FATTR_MODE != 0 {
			let file_type = node.attr.mode & S_IFMT;
			node.attr.mode = file_type | (attr.mode & 0o7777);
		}
		if valid & FATTR_UID != 0 {
			node.attr.uid = attr.uid;
		}
		if valid & FATTR_GID != 0 {
			node.attr.gid = attr.gid;
		}
		if valid & FATTR_SIZE != 0 {
			truncate_node(node, attr.size)?;
		}
		if valid & FATTR_ATIME != 0 {
			node.attr.atime = attr.atime;
			node.attr.atimensec = attr.atimensec;
		}
		if valid & FATTR_MTIME != 0 {
			node.attr.mtime = attr.mtime;
			node.attr.mtimensec = attr.mtimensec;
		}
		Ok(node.attr)
	}

	fn read_link(&self, inode: Inode) -> io::Result<Vec<u8>> {
		match &self.tree.node(inode)?.kind {
			NodeKind::Symlink { target } => Ok(target.clone()),
			_ => Err(errno(libc::EINVAL)),
		}
	}

	fn create_node(
		&mut self,
		ctx: &Context,
		parent: Inode,
		name: &[u8],
		mode: u32,
		rdev: u32,
		kind: NodeKind,
	) -> io::Result<Entry> {
		self.writable()?;
		validate_component(name)?;
		let dir = self.tree.node(parent)?;
		let NodeKind::Dir { entries, .. } = &dir.kind else {
			return Err(errno(libc::ENOTDIR));
		};
		if entries.contains_key(name) {
			return Err(errno(libc::EEXIST));
		}
		let is_dir = matches!(kind, NodeKind::Dir { .. });
		let ino = self.tree.allocate_inode()?;
		let node = Node {
			attr: Attr {
				ino,
				size: match &kind {
					NodeKind::Symlink { target } => target.len() as u64,
					_ => 0,
				},
				blocks: 0,
				atime: 0,
				mtime: 0,
				ctime: 0,
				atimensec: 0,
				mtimensec: 0,
				ctimensec: 0,
				mode,
				nlink: if is_dir { 2 } else { 1 },
				uid: ctx.uid,
				gid: ctx.gid,
				rdev,
				blksize: PAGE_SIZE as u32,
				flags: 0,
			},
			xattrs: OrdMap::new(),
			kind,
		};
		let entry = Self::entry(&node);
		self.tree.nodes.insert(ino, node);
		let parent_node = self.tree.node_mut(parent)?;
		if let NodeKind::Dir { entries, .. } = &mut parent_node.kind {
			entries.insert(name.to_vec(), ino);
		}
		if is_dir {
			parent_node.attr.nlink = parent_node.attr.nlink.saturating_add(1);
		}
		Ok(entry)
	}

	fn mkdir(
		&mut self,
		ctx: &Context,
		parent: Inode,
		name: &[u8],
		mode: u32,
		umask: u32,
	) -> io::Result<Entry> {
		self.create_node(
			ctx,
			parent,
			name,
			S_IFDIR | (mode & !umask & 0o7777),
			0,
			NodeKind::Dir {
				parent,
				entries: OrdMap::new(),
			},
		)
	}

	fn mknod(
		&mut self,
		ctx: &Context,
		parent: Inode,
		name: &[u8],
		mode: u32,
		rdev: u32,
		umask: u32,
	) -> io::Result<Entry> {
		if mode & S_IFMT != S_IFREG {
			return Err(errno(libc::EPERM));
		}
		self.create_node(
			ctx,
			parent,
			name,
			S_IFREG | (mode & !umask & 0o7777),
			rdev,
			NodeKind::File {
				pages: Vector::new(),
			},
		)
	}

	fn symlink(
		&mut self,
		ctx: &Context,
		parent: Inode,
		name: &[u8],
		target: &[u8],
	) -> io::Result<Entry> {
		self.create_node(
			ctx,
			parent,
			name,
			S_IFLNK | 0o777,
			0,
			NodeKind::Symlink {
				target: target.to_vec(),
			},
		)
	}

	fn link(&mut self, inode: Inode, new_parent: Inode, new_name: &[u8]) -> io::Result<Entry> {
		self.writable()?;
		validate_component(new_name)?;
		if self.tree.node(inode)?.is_dir() {
			return Err(errno(libc::EPERM));
		}
		let parent_dir = self.tree.node(new_parent)?;
		let NodeKind::Dir { entries, .. } = &parent_dir.kind else {
			return Err(errno(libc::ENOTDIR));
		};
		if entries.contains_key(new_name) {
			return Err(errno(libc::EEXIST));
		}
		let parent_mut = self.tree.node_mut(new_parent)?;
		if let NodeKind::Dir { entries, .. } = &mut parent_mut.kind {
			entries.insert(new_name.to_vec(), inode);
		}
		let target = self.tree.node_mut(inode)?;
		target.attr.nlink = target.attr.nlink.saturating_add(1);
		Ok(Self::entry(target))
	}

	fn unlink(&mut self, parent: Inode, name: &[u8], directory: bool) -> io::Result<()> {
		self.writable()?;
		validate_component(name)?;
		let child_ino = self.lookup_child(parent, name)?;
		let child = self.tree.node(child_ino)?;
		if directory {
			let NodeKind::Dir { entries, .. } = &child.kind else {
				return Err(errno(libc::ENOTDIR));
			};
			if !entries.is_empty() {
				return Err(errno(libc::ENOTEMPTY));
			}
		} else if child.is_dir() {
			return Err(errno(libc::EISDIR));
		}

		let parent_node = self.tree.node_mut(parent)?;
		if let NodeKind::Dir { entries, .. } = &mut parent_node.kind {
			entries.remove(name);
		}
		if directory {
			parent_node.attr.nlink = parent_node.attr.nlink.saturating_sub(1);
			self.tree.nodes.remove(&child_ino);
		} else {
			let remove = {
				let node = self.tree.node_mut(child_ino)?;
				node.attr.nlink = node.attr.nlink.saturating_sub(1);
				node.attr.nlink == 0
					&& !self
						.handles
						.values()
						.any(|handle| handle.inode == child_ino)
			};
			if remove {
				self.tree.nodes.remove(&child_ino);
			}
		}
		Ok(())
	}

	fn is_ancestor(&self, ancestor: Inode, mut current: Inode) -> bool {
		while current != ROOT_ID {
			if current == ancestor {
				return true;
			}
			let Some(node) = self.tree.nodes.get(&current) else {
				break;
			};
			match node.kind {
				NodeKind::Dir { parent, .. } => current = parent,
				_ => break,
			}
		}
		ancestor == ROOT_ID
	}

	fn rename(
		&mut self,
		old_parent: Inode,
		old_name: &[u8],
		new_parent: Inode,
		new_name: &[u8],
		flags: u32,
	) -> io::Result<()> {
		self.writable()?;
		validate_component(old_name)?;
		validate_component(new_name)?;
		if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE) != 0 {
			return Err(errno(libc::EINVAL));
		}
		let src_ino = self.lookup_child(old_parent, old_name)?;
		let dst_ino = self.lookup_child(new_parent, new_name).ok();

		if flags & RENAME_EXCHANGE != 0 {
			let Some(dst_ino) = dst_ino else {
				return Err(errno(libc::ENOENT));
			};
			if self.is_ancestor(src_ino, new_parent) || self.is_ancestor(dst_ino, old_parent) {
				return Err(errno(libc::EINVAL));
			}
			let src_is_dir = self.tree.node(src_ino)?.is_dir();
			let dst_is_dir = self.tree.node(dst_ino)?.is_dir();
			if let NodeKind::Dir { entries, .. } = &mut self.tree.node_mut(old_parent)?.kind {
				entries.insert(old_name.to_vec(), dst_ino);
			}
			if let NodeKind::Dir { entries, .. } = &mut self.tree.node_mut(new_parent)?.kind {
				entries.insert(new_name.to_vec(), src_ino);
			}
			if src_is_dir
				&& let NodeKind::Dir { parent, .. } = &mut self.tree.node_mut(src_ino)?.kind
			{
				*parent = new_parent;
			}
			if dst_is_dir
				&& let NodeKind::Dir { parent, .. } = &mut self.tree.node_mut(dst_ino)?.kind
			{
				*parent = old_parent;
			}
			return Ok(());
		}

		if flags & RENAME_NOREPLACE != 0 && dst_ino.is_some() {
			return Err(errno(libc::EEXIST));
		}
		if old_parent == new_parent && old_name == new_name {
			return Ok(());
		}
		if self.is_ancestor(src_ino, new_parent) {
			return Err(errno(libc::EINVAL));
		}

		let src_is_dir = self.tree.node(src_ino)?.is_dir();
		if let Some(dst_ino) = dst_ino {
			if dst_ino == src_ino {
				if let NodeKind::Dir { entries, .. } = &mut self.tree.node_mut(old_parent)?.kind {
					entries.remove(old_name);
				}
				let target = self.tree.node_mut(src_ino)?;
				target.attr.nlink = target.attr.nlink.saturating_sub(1);
				return Ok(());
			}
			let dst = self.tree.node(dst_ino)?;
			if src_is_dir {
				let NodeKind::Dir { entries, .. } = &dst.kind else {
					return Err(errno(libc::ENOTDIR));
				};
				if !entries.is_empty() {
					return Err(errno(libc::ENOTEMPTY));
				}
			} else if dst.is_dir() {
				return Err(errno(libc::EISDIR));
			}
			self.unlink(new_parent, new_name, src_is_dir)?;
		}

		let old_dir = self.tree.node_mut(old_parent)?;
		if let NodeKind::Dir { entries, .. } = &mut old_dir.kind {
			entries.remove(old_name);
		}
		if src_is_dir {
			old_dir.attr.nlink = old_dir.attr.nlink.saturating_sub(1);
		}

		let new_dir = self.tree.node_mut(new_parent)?;
		if let NodeKind::Dir { entries, .. } = &mut new_dir.kind {
			entries.insert(new_name.to_vec(), src_ino);
		}
		if src_is_dir {
			new_dir.attr.nlink = new_dir.attr.nlink.saturating_add(1);
			if let NodeKind::Dir { parent, .. } = &mut self.tree.node_mut(src_ino)?.kind {
				*parent = new_parent;
			}
		}
		Ok(())
	}

	fn open(&mut self, inode: Inode, flags: u32, directory: bool) -> io::Result<Handle> {
		let access = flags & O_ACCMODE;
		if self.read_only && (access != O_RDONLY || flags & O_TRUNC != 0) {
			return Err(errno(libc::EROFS));
		}
		let node = self.tree.node_mut(inode)?;
		if node.is_symlink() {
			return Err(errno(libc::ELOOP));
		}
		if directory {
			if !node.is_dir() {
				return Err(errno(libc::ENOTDIR));
			}
		} else if node.is_dir() {
			return Err(errno(libc::EISDIR));
		}
		if !directory && flags & O_TRUNC != 0 {
			truncate_node(node, 0)?;
		}
		self.allocate_handle(OpenHandle {
			inode,
			flags,
			directory,
		})
	}

	fn create(
		&mut self,
		ctx: &Context,
		parent: Inode,
		name: &[u8],
		flags: u32,
		mode: u32,
		umask: u32,
	) -> io::Result<(Entry, Handle)> {
		self.writable()?;
		validate_component(name)?;
		if let Ok(existing_ino) = self.lookup_child(parent, name) {
			if flags & O_EXCL != 0 {
				return Err(errno(libc::EEXIST));
			}
			let handle = self.open(existing_ino, flags, false)?;
			let entry = Self::entry(self.tree.node(existing_ino)?);
			return Ok((entry, handle));
		}
		let entry = self.create_node(
			ctx,
			parent,
			name,
			S_IFREG | (mode & !umask & 0o7777),
			0,
			NodeKind::File {
				pages: Vector::new(),
			},
		)?;
		let handle = self.allocate_handle(OpenHandle {
			inode: entry.inode,
			flags,
			directory: false,
		})?;
		Ok((entry, handle))
	}

	fn release(&mut self, handle: Handle, directory: bool) -> io::Result<()> {
		let Some(open) = self.handles.get(&handle) else {
			return Err(errno(libc::EBADF));
		};
		if open.directory != directory {
			return Err(errno(libc::EBADF));
		}
		let ino = open.inode;
		self.handles.remove(&handle);
		if !directory
			&& let Some(node) = self.tree.nodes.get(&ino)
			&& node.attr.nlink == 0
			&& !self.handles.values().any(|h| h.inode == ino)
		{
			self.tree.nodes.remove(&ino);
		}
		Ok(())
	}

	fn read_bytes(
		&self,
		inode: Inode,
		offset: u64,
		size: usize,
		mut visit: impl FnMut(&[u8]) -> io::Result<()>,
	) -> io::Result<usize> {
		let node = self.tree.node(inode)?;
		let NodeKind::File { pages } = &node.kind else {
			return Err(errno(libc::EISDIR));
		};
		if offset >= node.attr.size || size == 0 {
			return Ok(0);
		}
		let avail = (node.attr.size - offset).min(size as u64) as usize;
		let zero_page = [0u8; PAGE_SIZE];
		let mut read = 0usize;
		while read < avail {
			let pos = offset as usize + read;
			let page_idx = pos / PAGE_SIZE;
			let page_off = pos % PAGE_SIZE;
			let chunk = (PAGE_SIZE - page_off).min(avail - read);
			let slice = match pages.get(page_idx).and_then(|page| page.as_deref()) {
				Some(page) => &page[page_off..page_off + chunk],
				None => &zero_page[..chunk],
			};
			visit(slice)?;
			read += chunk;
		}
		Ok(read)
	}

	fn write_slice(&mut self, inode: Inode, offset: u64, data: &[u8]) -> io::Result<usize> {
		self.writable()?;
		let node = self.tree.node_mut(inode)?;
		write_into_node(node, offset, data)
	}

	fn set_xattr(&mut self, inode: Inode, name: &CStr, value: &[u8], flags: u32) -> io::Result<()> {
		self.writable()?;
		ensure_user_xattr(name)?;
		let node = self.tree.node_mut(inode)?;
		if node.is_symlink() {
			return Err(errno(libc::EPERM));
		}
		let key = name.to_bytes().to_vec();
		let exists = node.xattrs.contains_key(&key);
		if flags & XATTR_CREATE != 0 && exists {
			return Err(errno(libc::EEXIST));
		}
		if flags & XATTR_REPLACE != 0 && !exists {
			return Err(errno(libc::ENODATA));
		}
		node.xattrs.insert(key, value.to_vec());
		Ok(())
	}

	fn get_xattr(&self, inode: Inode, name: Option<&CStr>, size: usize) -> io::Result<Vec<u8>> {
		if let Some(name) = name
			&& !name.to_bytes().starts_with(b"user.")
		{
			return Err(errno(libc::ENODATA));
		}
		let node = self.tree.node(inode)?;
		if node.is_symlink() {
			return match name {
				Some(_) => Err(errno(libc::ENODATA)),
				None => Ok(Vec::new()),
			};
		}
		let data = match name {
			Some(name) => node
				.xattrs
				.get(name.to_bytes())
				.cloned()
				.ok_or_else(|| errno(libc::ENODATA))?,
			None => {
				let mut list = Vec::new();
				for key in node.xattrs.keys() {
					list.extend_from_slice(key);
					list.push(0);
				}
				list
			}
		};
		if size != 0 && data.len() > size {
			return Err(errno(libc::ERANGE));
		}
		Ok(data)
	}

	fn remove_xattr(&mut self, inode: Inode, name: &CStr) -> io::Result<()> {
		self.writable()?;
		ensure_user_xattr(name)?;
		let node = self.tree.node_mut(inode)?;
		if node.is_symlink() {
			return Err(errno(libc::EPERM));
		}
		node.xattrs
			.remove(name.to_bytes())
			.ok_or_else(|| errno(libc::ENODATA))?;
		Ok(())
	}

	fn access(&self, ctx: &Context, inode: Inode, mask: u32) -> io::Result<()> {
		if mask == 0 {
			return Ok(());
		}
		if self.read_only && mask & 2 != 0 {
			return Err(errno(libc::EROFS));
		}
		let node = self.tree.node(inode)?;
		let mode = node.attr.mode;
		if ctx.uid == 0 {
			if mask & 1 != 0 && !node.is_dir() && mode & 0o111 == 0 {
				return Err(errno(libc::EACCES));
			}
			return Ok(());
		}
		let bits = if ctx.uid == node.attr.uid {
			(mode >> 6) & 0o7
		} else if ctx.gid == node.attr.gid {
			(mode >> 3) & 0o7
		} else {
			mode & 0o7
		};
		if mask & !bits != 0 {
			return Err(errno(libc::EACCES));
		}
		Ok(())
	}

	fn read_dir(
		&self,
		handle: Handle,
		offset: u64,
		max: usize,
	) -> io::Result<(Inode, Vec<DirEntry>)> {
		let Some(open) = self.handles.get(&handle) else {
			return Err(errno(libc::EBADF));
		};
		if !open.directory {
			return Err(errno(libc::EBADF));
		}
		let dir = self.tree.node(open.inode)?;
		let NodeKind::Dir { entries, .. } = &dir.kind else {
			return Err(errno(libc::ENOTDIR));
		};
		let mut out = Vec::new();
		let mut bytes = 0usize;
		for (index, (name, &child_ino)) in entries.iter().enumerate().skip(offset as usize) {
			let entry_len = (24 + name.len() + 7) & !7;
			if entry_len > max || bytes + entry_len > max {
				break;
			}
			let kind = self
				.tree
				.nodes
				.get(&child_ino)
				.map(Node::dt_type)
				.unwrap_or(DT_REG);
			out.push(DirEntry {
				ino: child_ino,
				offset: (index + 1) as u64,
				type_: kind,
				name: name.clone(),
			});
			bytes += entry_len;
		}
		Ok((open.inode, out))
	}

	fn resolve_dir(&self, parts: &[Vec<u8>]) -> io::Result<Inode> {
		let mut current = ROOT_ID;
		for part in parts {
			current = self.lookup_child(current, part)?;
			if !self.tree.node(current)?.is_dir() {
				return Err(errno(libc::ENOTDIR));
			}
		}
		Ok(current)
	}

	fn resolve_parent(&self, path: &Path) -> io::Result<(Inode, Vec<u8>)> {
		let mut parts = split_path(path)?;
		let name = parts.pop().ok_or_else(|| errno(libc::EINVAL))?;
		let parent = self.resolve_dir(&parts)?;
		Ok((parent, name))
	}

	fn remove_subtree(&mut self, parent: Inode, name: &[u8]) -> io::Result<()> {
		let child_ino = self.lookup_child(parent, name)?;
		if self.tree.node(child_ino)?.is_dir() {
			let names: Vec<Vec<u8>> = match &self.tree.node(child_ino)?.kind {
				NodeKind::Dir { entries, .. } => entries.keys().cloned().collect(),
				_ => Vec::new(),
			};
			for sub in names {
				self.remove_subtree(child_ino, &sub)?;
			}
			self.unlink(parent, name, true)
		} else {
			self.unlink(parent, name, false)
		}
	}
}

fn truncate_node(node: &mut Node, size: u64) -> io::Result<()> {
	let NodeKind::File { pages } = &mut node.kind else {
		return Err(errno(libc::EISDIR));
	};
	let needed_pages = (size as usize).div_ceil(PAGE_SIZE);
	if pages.len() > needed_pages {
		pages.truncate(needed_pages);
	}
	let tail = (size as usize) % PAGE_SIZE;
	if tail != 0
		&& let Some(Some(last)) = pages.get_mut(needed_pages - 1)
	{
		let buf = Arc::make_mut(last);
		buf[tail..].fill(0);
	}
	node.attr.size = size;
	node.attr.blocks = size.div_ceil(512);
	Ok(())
}

fn write_into_node(node: &mut Node, offset: u64, data: &[u8]) -> io::Result<usize> {
	let NodeKind::File { pages } = &mut node.kind else {
		return Err(errno(libc::EISDIR));
	};
	if data.is_empty() {
		return Ok(0);
	}
	let end = offset
		.checked_add(data.len() as u64)
		.ok_or_else(|| errno(libc::EFBIG))?;
	let needed_pages = (end as usize).div_ceil(PAGE_SIZE);
	while pages.len() < needed_pages {
		pages.push_back(None);
	}
	let mut written = 0usize;
	while written < data.len() {
		let pos = offset as usize + written;
		let page_idx = pos / PAGE_SIZE;
		let page_off = pos % PAGE_SIZE;
		let chunk = (PAGE_SIZE - page_off).min(data.len() - written);
		let slot = pages.get_mut(page_idx).expect("page allocated");
		let page = slot.get_or_insert_with(|| Arc::new([0u8; PAGE_SIZE]));
		let buf = Arc::make_mut(page);
		buf[page_off..page_off + chunk].copy_from_slice(&data[written..written + chunk]);
		written += chunk;
	}
	if end > node.attr.size {
		node.attr.size = end;
		node.attr.blocks = end.div_ceil(512);
	}
	Ok(written)
}

impl Fuse for MemFs {
	type Inode = u64;
	type Handle = u64;

	async fn init(&self, capable: u32) -> io::Result<u32> {
		Ok(capable & (FUSE_ASYNC_READ | FUSE_BIG_WRITES))
	}

	async fn lookup(&self, _ctx: &Context, parent: u64, name: &CStr) -> io::Result<Entry> {
		self.with(|state| state.lookup(parent, name))
	}

	async fn forget(&self, _ctx: &Context, _inode: u64, _count: u64) {}

	async fn batch_forget(&self, _ctx: &Context, _requests: Vec<(u64, u64)>) {}

	async fn getattr(
		&self,
		_ctx: &Context,
		inode: u64,
		_handle: Option<u64>,
	) -> io::Result<(Attr, (u64, u32))> {
		self.with(|state| state.getattr(inode).map(|attr| (attr, NO_CACHE)))
	}

	async fn setattr(
		&self,
		_ctx: &Context,
		inode: u64,
		attr: Attr,
		_handle: Option<u64>,
		valid: u32,
	) -> io::Result<(Attr, (u64, u32))> {
		self.with(|state| {
			state
				.setattr(inode, attr, valid)
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
		self.with(|state| state.symlink(ctx, parent, name.to_bytes(), linkname.to_bytes()))
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
		self.with(|state| state.mknod(ctx, parent, name.to_bytes(), mode, rdev, umask))
	}

	async fn mkdir(
		&self,
		ctx: &Context,
		parent: u64,
		name: &CStr,
		mode: u32,
		umask: u32,
	) -> io::Result<Entry> {
		self.with(|state| state.mkdir(ctx, parent, name.to_bytes(), mode, umask))
	}

	async fn unlink(&self, _ctx: &Context, parent: u64, name: &CStr) -> io::Result<()> {
		self.with(|state| state.unlink(parent, name.to_bytes(), false))
	}

	async fn rmdir(&self, _ctx: &Context, parent: u64, name: &CStr) -> io::Result<()> {
		self.with(|state| state.unlink(parent, name.to_bytes(), true))
	}

	async fn rename(
		&self,
		_ctx: &Context,
		olddir: u64,
		oldname: &CStr,
		newdir: u64,
		newname: &CStr,
		flags: u32,
	) -> io::Result<()> {
		self.with(|state| {
			state.rename(
				olddir,
				oldname.to_bytes(),
				newdir,
				newname.to_bytes(),
				flags,
			)
		})
	}

	async fn link(
		&self,
		_ctx: &Context,
		inode: u64,
		newparent: u64,
		newname: &CStr,
	) -> io::Result<Entry> {
		self.with(|state| state.link(inode, newparent, newname.to_bytes()))
	}

	async fn open(&self, _ctx: &Context, inode: u64, flags: u32) -> io::Result<(u64, u32)> {
		self.with(|state| {
			state
				.open(inode, flags, false)
				.map(|h| (h, FOPEN_DIRECT_IO))
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
				.create(
					ctx,
					parent,
					name.to_bytes(),
					args.flags,
					args.mode,
					args.umask,
				)
				.map(|(entry, h)| (entry, h, FOPEN_DIRECT_IO))
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
		let written = self.with(|state| {
			let Some(open) = state.handles.get(&handle) else {
				return Err(errno(libc::EBADF));
			};
			if open.directory || open.flags & O_ACCMODE == O_WRONLY {
				return Err(errno(libc::EBADF));
			}
			let memory = out.memory();
			let extents = out.extents();
			let mut ext_idx = 0usize;
			let mut ext_off = 0usize;
			state.read_bytes(open.inode, offset, size as usize, |mut src| {
				while !src.is_empty() && ext_idx < extents.len() {
					let extent = extents[ext_idx];
					let rem = extent.len.saturating_sub(ext_off);
					if rem == 0 {
						ext_idx += 1;
						ext_off = 0;
						continue;
					}
					let take = src.len().min(rem);
					let range = memory.resolve(extent.offset as usize + ext_off, take)?;
					unsafe {
						std::ptr::copy_nonoverlapping(src.as_ptr(), range.ptr, take);
					}
					src = &src[take..];
					ext_off += take;
				}
				Ok(())
			})
		})?;
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
		self.with(|state| {
			state.writable()?;
			let Some(open) = state.handles.get(&handle) else {
				return Err(errno(libc::EBADF));
			};
			if open.directory || open.flags & O_ACCMODE == O_RDONLY {
				return Err(errno(libc::EBADF));
			}
			let ino = open.inode;
			let append = open.flags & O_APPEND != 0;
			let memory = input.memory();
			let extents = input.extents(size as usize);
			let node = state.tree.node_mut(ino)?;
			let mut at = if append { node.attr.size } else { offset };
			let mut total = 0usize;
			for extent in extents {
				if extent.len == 0 {
					continue;
				}
				let range = memory.resolve(extent.offset as usize, extent.len)?;
				let slice = unsafe { std::slice::from_raw_parts(range.ptr, range.len) };
				let n = write_into_node(node, at, slice)?;
				at += n as u64;
				total += n;
			}
			Ok(total)
		})
	}

	async fn flush(&self, _ctx: &Context, _inode: u64, handle: u64) -> io::Result<()> {
		self.with(|state| match state.handles.get(&handle) {
			Some(open) if !open.directory => Ok(()),
			_ => Err(errno(libc::EBADF)),
		})
	}

	async fn fsync(
		&self,
		_ctx: &Context,
		_inode: u64,
		_datasync: bool,
		handle: u64,
	) -> io::Result<()> {
		self.with(|state| match state.handles.get(&handle) {
			Some(open) if !open.directory => Ok(()),
			_ => Err(errno(libc::EBADF)),
		})
	}

	async fn release(
		&self,
		_ctx: &Context,
		_inode: u64,
		_flags: u32,
		handle: u64,
	) -> io::Result<()> {
		self.with(|state| state.release(handle, false))
	}

	async fn statfs(&self, _ctx: &Context, _inode: u64) -> io::Result<Kstatfs> {
		self.with(|state| {
			Ok(Kstatfs {
				blocks: 1 << 20,
				bfree: 1 << 20,
				bavail: 1 << 20,
				files: state.tree.nodes.len() as u64,
				ffree: 1 << 20,
				bsize: PAGE_SIZE as u32,
				namelen: 255,
				frsize: PAGE_SIZE as u32,
				..Kstatfs::default()
			})
		})
	}

	async fn setxattr(
		&self,
		_ctx: &Context,
		inode: u64,
		name: &CStr,
		value: &[u8],
		flags: u32,
	) -> io::Result<()> {
		self.with(|state| state.set_xattr(inode, name, value, flags))
	}

	async fn getxattr(
		&self,
		_ctx: &Context,
		inode: u64,
		name: &CStr,
		size: u32,
	) -> io::Result<GetxattrReply> {
		self.with(|state| {
			let value = state.get_xattr(inode, Some(name), size as usize)?;
			if size == 0 {
				Ok(GetxattrReply::Size(value.len() as u32))
			} else {
				Ok(GetxattrReply::Value(value))
			}
		})
	}

	async fn listxattr(&self, _ctx: &Context, inode: u64, size: u32) -> io::Result<ListxattrReply> {
		self.with(|state| {
			let value = state.get_xattr(inode, None, size as usize)?;
			if size == 0 {
				Ok(ListxattrReply::Size(value.len() as u32))
			} else {
				Ok(ListxattrReply::Names(value))
			}
		})
	}

	async fn removexattr(&self, _ctx: &Context, inode: u64, name: &CStr) -> io::Result<()> {
		self.with(|state| state.remove_xattr(inode, name))
	}

	async fn opendir(&self, _ctx: &Context, inode: u64) -> io::Result<u64> {
		self.with(|state| state.open(inode, O_RDONLY, true))
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
			state
				.read_dir(handle, offset, size as usize)
				.map(|(_, entries)| entries)
		})
	}

	async fn readdirplus(
		&self,
		_ctx: &Context,
		_inode: u64,
		handle: u64,
		size: u32,
		offset: u64,
	) -> io::Result<Vec<(Entry, DirentInfo)>> {
		self.with(|state| {
			let (_, entries) = state.read_dir(handle, offset, size as usize)?;
			let mut out = Vec::with_capacity(entries.len());
			for item in entries {
				if let Ok(node) = state.tree.node(item.ino) {
					out.push((
						FsState::entry(node),
						DirentInfo {
							ino: item.ino,
							offset: item.offset,
							type_: item.type_,
							name: item.name,
						},
					));
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
		self.with(|state| match state.handles.get(&handle) {
			Some(open) if open.directory => Ok(()),
			_ => Err(errno(libc::EBADF)),
		})
	}

	async fn releasedir(&self, _ctx: &Context, _inode: u64, handle: u64) -> io::Result<()> {
		self.with(|state| state.release(handle, true))
	}

	async fn access(&self, ctx: &Context, inode: u64, mask: u32) -> io::Result<()> {
		self.with(|state| state.access(ctx, inode, mask))
	}
}

impl Volume for MemFs {
	async fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
		self.with(|state| {
			let (parent, name) = state.resolve_parent(path)?;
			let ino = state.lookup_child(parent, &name)?;
			let node = state.tree.node(ino)?;
			if node.is_dir() {
				return Err(errno(libc::EISDIR));
			}
			if !node.is_file() {
				return Err(errno(libc::EPERM));
			}
			let len = node.attr.size as usize;
			let mut out = Vec::with_capacity(len);
			state.read_bytes(ino, 0, len, |slice| {
				out.extend_from_slice(slice);
				Ok(())
			})?;
			Ok(out)
		})
	}

	async fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
		self.with(|state| {
			state.writable()?;
			let (parent, name) = state.resolve_parent(path)?;
			let ino = match state.lookup_child(parent, &name) {
				Ok(ino) => {
					let node = state.tree.node_mut(ino)?;
					if node.is_dir() {
						return Err(errno(libc::EISDIR));
					}
					if !node.is_file() {
						return Err(errno(libc::EPERM));
					}
					truncate_node(node, 0)?;
					ino
				}
				Err(_) => {
					state
						.create_node(
							&Context::default(),
							parent,
							&name,
							S_IFREG | 0o644,
							0,
							NodeKind::File {
								pages: Vector::new(),
							},
						)?
						.inode
				}
			};
			state.write_slice(ino, 0, data)?;
			Ok(())
		})
	}

	async fn stat(&self, path: &Path) -> io::Result<Attr> {
		self.with(|state| {
			let parts = split_path(path)?;
			if parts.is_empty() {
				return state.getattr(ROOT_ID);
			}
			let (parent, name) = state.resolve_parent(path)?;
			let ino = state.lookup_child(parent, &name)?;
			state.getattr(ino)
		})
	}

	async fn readlink(&self, path: &Path) -> io::Result<Vec<u8>> {
		self.with(|state| {
			let (parent, name) = state.resolve_parent(path)?;
			let ino = state.lookup_child(parent, &name)?;
			state.read_link(ino)
		})
	}

	async fn symlink(&self, target: &Path, link: &Path) -> io::Result<()> {
		self.with(|state| {
			let (parent, name) = state.resolve_parent(link)?;
			let target_bytes = path_bytes(target)?;
			state.symlink(&Context::default(), parent, &name, &target_bytes)?;
			Ok(())
		})
	}

	async fn list(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
		self.with(|state| {
			let parts = split_path(path)?;
			let ino = state.resolve_dir(&parts)?;
			let dir = state.tree.node(ino)?;
			let NodeKind::Dir { entries, .. } = &dir.kind else {
				return Err(errno(libc::ENOTDIR));
			};
			let mut out = Vec::with_capacity(entries.len());
			for (idx, (name, &child_ino)) in entries.iter().enumerate() {
				let kind = state
					.tree
					.nodes
					.get(&child_ino)
					.map(Node::dt_type)
					.unwrap_or(DT_REG);
				out.push(DirEntry {
					ino: child_ino,
					offset: (idx + 1) as u64,
					type_: kind,
					name: name.clone(),
				});
			}
			Ok(out)
		})
	}

	async fn create_dir(&self, path: &Path) -> io::Result<()> {
		self.with(|state| {
			let (parent, name) = state.resolve_parent(path)?;
			state.mkdir(&Context::default(), parent, &name, 0o755, 0)?;
			Ok(())
		})
	}

	async fn create_dir_all(&self, path: &Path) -> io::Result<()> {
		self.with(|state| {
			state.writable()?;
			let parts = split_path(path)?;
			let mut current = ROOT_ID;
			for part in parts {
				match state.lookup_child(current, &part) {
					Ok(next) => {
						if !state.tree.node(next)?.is_dir() {
							return Err(errno(libc::ENOTDIR));
						}
						current = next;
					}
					Err(_) => {
						current = state
							.mkdir(&Context::default(), current, &part, 0o755, 0)?
							.inode;
					}
				}
			}
			Ok(())
		})
	}

	async fn remove_file(&self, path: &Path) -> io::Result<()> {
		self.with(|state| {
			let (parent, name) = state.resolve_parent(path)?;
			state.unlink(parent, &name, false)
		})
	}

	async fn remove_dir(&self, path: &Path) -> io::Result<()> {
		self.with(|state| {
			let (parent, name) = state.resolve_parent(path)?;
			state.unlink(parent, &name, true)
		})
	}

	async fn remove_all(&self, path: &Path) -> io::Result<()> {
		self.with(|state| {
			state.writable()?;
			let parts = split_path(path)?;
			if parts.is_empty() {
				let names: Vec<Vec<u8>> = match &state.tree.node(ROOT_ID)?.kind {
					NodeKind::Dir { entries, .. } => entries.keys().cloned().collect(),
					_ => Vec::new(),
				};
				for name in names {
					state.remove_subtree(ROOT_ID, &name)?;
				}
				return Ok(());
			}
			let (parent, name) = state.resolve_parent(path)?;
			state.remove_subtree(parent, &name)
		})
	}

	async fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
		self.with(|state| {
			let (old_parent, old_name) = state.resolve_parent(from)?;
			let (new_parent, new_name) = state.resolve_parent(to)?;
			state.rename(old_parent, &old_name, new_parent, &new_name, 0)
		})
	}

	async fn copy(&self, from: &Path, to: &Path) -> io::Result<u64> {
		self.with(|state| {
			state.writable()?;
			let (src_parent, src_name) = state.resolve_parent(from)?;
			let src_ino = state.lookup_child(src_parent, &src_name)?;
			let (pages, size, mode) = {
				let src = state.tree.node(src_ino)?;
				let NodeKind::File { pages } = &src.kind else {
					return Err(if src.is_dir() {
						errno(libc::EISDIR)
					} else {
						errno(libc::EINVAL)
					});
				};
				(pages.clone(), src.attr.size, src.attr.mode)
			};

			let (dst_parent, dst_name) = state.resolve_parent(to)?;
			match state.lookup_child(dst_parent, &dst_name) {
				Ok(dst_ino) => {
					let dst = state.tree.node_mut(dst_ino)?;
					if dst.is_dir() {
						return Err(errno(libc::EISDIR));
					}
					dst.kind = NodeKind::File { pages };
					dst.attr.size = size;
					dst.attr.blocks = size.div_ceil(512);
				}
				Err(_) => {
					let entry = state.create_node(
						&Context::default(),
						dst_parent,
						&dst_name,
						mode,
						0,
						NodeKind::File { pages },
					)?;
					let dst = state.tree.node_mut(entry.inode)?;
					dst.attr.size = size;
					dst.attr.blocks = size.div_ceil(512);
				}
			}
			Ok(size)
		})
	}
}

impl Snapshot for MemFs {
	type Id = u64;

	async fn snapshot(&self) -> io::Result<u64> {
		self.with(|state| {
			let id = state.store.next_id.fetch_add(1, Ordering::Relaxed);
			state
				.store
				.snapshots
				.lock()
				.unwrap_or_else(|e| e.into_inner())
				.insert(id, state.tree.clone());
			Ok(id)
		})
	}

	async fn branch(&self, id: &u64) -> io::Result<Self> {
		self.with(|state| {
			let tree = state
				.store
				.snapshots
				.lock()
				.unwrap_or_else(|e| e.into_inner())
				.get(id)
				.cloned()
				.ok_or_else(|| errno(libc::ENOENT))?;
			Ok(Self {
				state: RefCell::new(FsState {
					read_only: false,
					tree,
					handles: HashMap::new(),
					next_handle: 1,
					store: Arc::clone(&state.store),
				}),
			})
		})
	}

	async fn restore(&self, id: &u64) -> io::Result<()> {
		self.with(|state| {
			state.writable()?;
			let tree = state
				.store
				.snapshots
				.lock()
				.unwrap_or_else(|e| e.into_inner())
				.get(id)
				.cloned()
				.ok_or_else(|| errno(libc::ENOENT))?;
			state.tree = tree;
			Ok(())
		})
	}

	async fn delete(&self, id: &u64) -> io::Result<()> {
		self.with(|state| {
			state
				.store
				.snapshots
				.lock()
				.unwrap_or_else(|e| e.into_inner())
				.remove(id)
				.map(|_| ())
				.ok_or_else(|| errno(libc::ENOENT))
		})
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

fn split_path(path: &Path) -> io::Result<Vec<Vec<u8>>> {
	let mut parts = Vec::new();
	for component in path.components() {
		match component {
			Component::RootDir | Component::CurDir => {}
			Component::Normal(name) => {
				let bytes = name.as_encoded_bytes();
				validate_component(bytes)?;
				parts.push(bytes.to_vec());
			}
			Component::ParentDir | Component::Prefix(_) => {
				return Err(errno(libc::EINVAL));
			}
		}
	}
	Ok(parts)
}

fn path_bytes(path: &Path) -> io::Result<Vec<u8>> {
	let bytes = path.as_os_str().as_encoded_bytes();
	if bytes.is_empty() || bytes.contains(&0) {
		return Err(errno(libc::EINVAL));
	}
	Ok(bytes.to_vec())
}

fn ensure_user_xattr(name: &CStr) -> io::Result<()> {
	if name.to_bytes().starts_with(b"user.") {
		Ok(())
	} else {
		Err(errno(libc::EPERM))
	}
}

fn errno(code: libc::c_int) -> io::Error {
	io::Error::from_raw_os_error(code)
}

#[cfg(test)]
mod tests {
	use std::future::Future;
	use std::path::Path;
	use std::sync::Arc;
	use std::task::{Context as TaskContext, Poll, Waker};

	use api::{
		Context, CreateArgs, Extent, Fuse, Memory, MemoryRange, Snapshot, Volume, ZeroCopyReader,
		ZeroCopyWriter,
	};

	use super::*;

	const O_RDWR: u32 = 2;

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
		fn new(data: Vec<u8>) -> Self {
			Self {
				mem: Arc::new(TestMem(Mutex::new(data))),
				written: 0,
			}
		}

		fn bytes(&self) -> Vec<u8> {
			self.mem.0.lock().unwrap()[..self.written].to_vec()
		}
	}

	impl ZeroCopyReader for TestBuf {
		fn memory(&self) -> Arc<dyn Memory> {
			self.mem.clone()
		}

		fn extents(&self, count: usize) -> Vec<Extent> {
			let len = self.mem.0.lock().unwrap().len().min(count);
			vec![Extent { offset: 0, len }]
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

	#[test]
	fn volume_and_cow_snapshots_share_pages() {
		let fs = MemFs::new(false);
		block_on(fs.create_dir_all(Path::new("/project/src"))).unwrap();

		// Write an 8 KiB file (2 pages) and take a snapshot.
		let mut initial = vec![b'A'; PAGE_SIZE];
		initial.extend_from_slice(&[b'B'; PAGE_SIZE]);
		block_on(Volume::write(
			&fs,
			Path::new("/project/src/lib.rs"),
			&initial,
		))
		.unwrap();
		block_on(Volume::symlink(
			&fs,
			Path::new("src/lib.rs"),
			Path::new("/project/current.rs"),
		))
		.unwrap();

		let snap1 = block_on(fs.snapshot()).unwrap();

		// Modify only the second page in `fs`; the first page stays shared with `snap1`.
		let ctx = Context::default();
		let proj = block_on(fs.lookup(&ctx, ROOT_ID, c"project")).unwrap();
		let src = block_on(fs.lookup(&ctx, proj.inode, c"src")).unwrap();
		let file = block_on(fs.lookup(&ctx, src.inode, c"lib.rs")).unwrap();
		let (fh, _) = block_on(fs.open(&ctx, file.inode, O_RDWR)).unwrap();
		let mut writer = TestBuf::new(b"PATCHED".to_vec());
		block_on(Fuse::write(
			&fs,
			&ctx,
			file.inode,
			fh,
			&mut writer,
			7,
			PAGE_SIZE as u64,
		))
		.unwrap();
		block_on(fs.release(&ctx, file.inode, 0, fh)).unwrap();

		// Verify page 0 pointer identity is still shared between live `fs` and `snap1`,
		// while page 1 was CoW-cloned.
		{
			let state = fs.state.borrow();
			let live_pages = match &state.tree.node(file.inode).unwrap().kind {
				NodeKind::File { pages } => pages.clone(),
				_ => panic!("expected file"),
			};
			let snaps = state.store.snapshots.lock().unwrap();
			let snap_pages = match &snaps.get(&snap1).unwrap().node(file.inode).unwrap().kind {
				NodeKind::File { pages } => pages.clone(),
				_ => panic!("expected file"),
			};
			assert!(Arc::ptr_eq(
				live_pages[0].as_ref().unwrap(),
				snap_pages[0].as_ref().unwrap()
			));
			assert!(!Arc::ptr_eq(
				live_pages[1].as_ref().unwrap(),
				snap_pages[1].as_ref().unwrap()
			));
		}

		// Branching from `snap1` yields the untouched original bytes.
		let branched = block_on(fs.branch(&snap1)).unwrap();
		assert_eq!(
			block_on(Volume::read(&branched, Path::new("/project/src/lib.rs"))).unwrap(),
			initial
		);

		// Restore `fs` back to `snap1`.
		block_on(fs.restore(&snap1)).unwrap();
		assert_eq!(
			block_on(Volume::read(&fs, Path::new("/project/src/lib.rs"))).unwrap(),
			initial
		);

		block_on(fs.delete(&snap1)).unwrap();
		assert!(block_on(fs.branch(&snap1)).is_err());
	}

	#[test]
	fn fuse_operations_and_hardlinks() {
		let fs = MemFs::new(false);
		let ctx = Context::default();
		let (entry, fh, _) = block_on(fs.create(
			&ctx,
			ROOT_ID,
			c"a.txt",
			CreateArgs {
				flags: O_RDWR,
				mode: 0o644,
				umask: 0o022,
			},
		))
		.unwrap();
		let mut input = TestBuf::new(b"hello".to_vec());
		assert_eq!(
			block_on(Fuse::write(&fs, &ctx, entry.inode, fh, &mut input, 5, 0)).unwrap(),
			5
		);
		block_on(fs.release(&ctx, entry.inode, 0, fh)).unwrap();

		let linked = block_on(fs.link(&ctx, entry.inode, ROOT_ID, c"b.txt")).unwrap();
		assert_eq!(linked.inode, entry.inode);
		assert_eq!(linked.attr.nlink, 2);

		block_on(fs.setxattr(&ctx, entry.inode, c"user.k", b"v", 0)).unwrap();
		match block_on(fs.getxattr(&ctx, entry.inode, c"user.k", 10)).unwrap() {
			GetxattrReply::Value(v) => assert_eq!(v, b"v"),
			GetxattrReply::Size(_) => panic!("expected value"),
		}

		block_on(fs.unlink(&ctx, ROOT_ID, c"a.txt")).unwrap();
		let (fh2, _) = block_on(fs.open(&ctx, linked.inode, O_RDONLY)).unwrap();
		let mut out = TestBuf::new(vec![0u8; 8]);
		let n = block_on(Fuse::read(&fs, &ctx, linked.inode, fh2, &mut out, 8, 0)).unwrap();
		assert_eq!(n, 5);
		assert_eq!(out.bytes(), b"hello");
		block_on(fs.release(&ctx, linked.inode, 0, fh2)).unwrap();
	}
}
