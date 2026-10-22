//! The JuiceFS volume as a [`FileSystem`].
//!
//! Each operation is one call into the Go VFS through the volume's [`Session`],
//! which runs it on the pool's threads. This module translates between the
//! FUSE types and the C ABI, and nothing else.

use std::ffi::CStr;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use fuse_api::{
	Attr, Context, CreateArgs, DirEntry, DirentInfo, Entry, Extent, FileSystem, GetxattrReply,
	Kstatfs, ListxattrReply, Memory, ZeroCopyReader, ZeroCopyWriter,
};

use crate::{Attr as RawAttr, Ctx, Dirent as RawDirent, IoVec, ListXattr, Session, Xattr};

/// The wire ABI lives in the VMM (`devices/fs/abi.rs`), which this crate must
/// not depend on, so the few facts a reply needs are spelled out here: they
/// are `include/uapi/linux/fuse.h`, and `the_layouts_are_the_kernels` below
/// checks the record sizes against it.
///
/// `fuse_dirent`: the record headers, without any name.
const DIRENT_SIZE: usize = 24;
/// `fuse_direntplus`: an entry before the dirent.
const DIRENTPLUS_SIZE: usize = 152;
/// Dirents are padded so the next one starts 8-byte aligned.
const DIRENT_ALIGN: usize = 8;

// `fuse_open_out.open_flags` (FOPEN_*).
const FOPEN_DIRECT_IO: u32 = 1 << 0;
const FOPEN_KEEP_CACHE: u32 = 1 << 1;

// `fuse_init_in` / `fuse_init_out` capability bits.
const FUSE_ASYNC_READ: u32 = 1 << 0;
const FUSE_BIG_WRITES: u32 = 1 << 5;
/// The kernel may batch a READDIRPLUS (the `DO_READDIRPLUS` name avoids the
/// opcode's).
const FUSE_DO_READDIRPLUS: u32 = 1 << 13;
/// The kernel decides per directory whether to ask for READDIRPLUS.
const FUSE_READDIRPLUS_AUTO: u32 = 1 << 14;
#[cfg(target_os = "linux")]
const FUSE_MAX_PAGES: u32 = 1 << 22;

// Inode type bits (`S_IFMT` and friends), as the kernel's `stat` reports them.
const S_IFMT: u32 = 0o170000;

/// How many bytes one READDIR record takes, name and alignment included.
/// The VMM's dispatcher packs its own reply and must agree with this.
fn dirent_len(name_len: usize) -> usize {
	let raw = DIRENT_SIZE + name_len;
	(raw + DIRENT_ALIGN - 1) & !(DIRENT_ALIGN - 1)
}

/// As [`dirent_len`], for a READDIRPLUS record: the dirent plus its entry.
fn direntplus_len(name_len: usize) -> usize {
	let raw = DIRENTPLUS_SIZE + name_len;
	(raw + DIRENT_ALIGN - 1) & !(DIRENT_ALIGN - 1)
}

/// How many bytes one READDIR record takes, name and alignment included, as
/// the dispatcher that packs the final reply counts it. It is exposed so the
/// VMM's own copy of this arithmetic can be checked against it.
pub fn reply_len(name_len: usize, plus: bool) -> usize {
	if plus {
		direntplus_len(name_len)
	} else {
		dirent_len(name_len)
	}
}

/// The shortest READDIR record, used to size a batch before any name is
/// known: a plain dirent with an empty name, padded to the alignment.
const MIN_DIRENT: usize = DIRENT_SIZE + 8;
/// The same for READDIRPLUS, which puts an entry before every dirent.
const MIN_DIRENTPLUS: usize = DIRENTPLUS_SIZE + 8;
/// The most records one reply may be built from: more only costs the caller
/// memory, since the reply buffer decides how many are used anyway.
const MAX_DIRENTS: usize = 512;

/// One JuiceFS volume: the VFS behind a [`Session`].
pub struct Volume {
	session: Session,
}

impl Volume {
	pub fn new(session: Session) -> Self {
		Volume { session }
	}
}

/// The credentials a request carries, in the shape the C ABI takes them.
fn credentials(context: &Context) -> Ctx {
	Ctx {
		uid: context.uid,
		gid: context.gid,
		pid: context.pid,
	}
}

/// Does the guest see this record as a plain file, a directory, and so on?
/// The kernel's `DT_*` tags are exactly the `S_IFMT` bits shifted down.
fn dirent_type(mode: u32) -> u32 {
	(mode & S_IFMT) >> 12
}

/// A duration the FUSE reply carries as whole seconds plus nanoseconds.
fn timeout(duration: Duration) -> (u64, u32) {
	(duration.as_secs(), duration.subsec_nanos())
}

/// The C attributes as the guest's kernel reads them.
fn attr(raw: RawAttr) -> Attr {
	Attr {
		ino: raw.ino,
		size: raw.size,
		blocks: raw.blocks,
		atime: raw.atime,
		mtime: raw.mtime,
		ctime: raw.ctime,
		atimensec: raw.atimensec,
		mtimensec: raw.mtimensec,
		ctimensec: raw.ctimensec,
		mode: raw.mode,
		nlink: raw.nlink,
		uid: raw.uid,
		gid: raw.gid,
		rdev: raw.rdev,
		blksize: raw.blksize,
		flags: raw.flags,
	}
}

/// The ranges a request names, as the C ABI takes them, truncated to `size`.
fn iovecs(memory: &dyn Memory, extents: Vec<Extent>, size: usize) -> io::Result<Vec<IoVec>> {
	let mut out = Vec::with_capacity(extents.len());
	let mut left = size;
	for extent in extents {
		if left == 0 {
			break;
		}
		let len = extent.len.min(left);
		let range = memory.resolve(extent.offset as usize, len)?;
		out.push(IoVec {
			base: range.ptr.cast(),
			len,
		});
		left -= len;
	}
	Ok(out)
}

impl Volume {
	fn entry(&self, raw: crate::Entry) -> Entry {
		Entry {
			inode: raw.ino,
			// The VFS's inode numbers are stable for the volume's lifetime;
			// the kernel's generation only guards reuse, which cannot happen.
			generation: 1,
			attr: attr(raw.attr),
			attr_timeout: timeout(self.session.attr_ttl()),
			entry_timeout: timeout(self.session.entry_ttl()),
		}
	}

	fn name(record: &RawDirent) -> Vec<u8> {
		let name_len = (record.namelen as usize).min(record.name.len());
		record.name[..name_len]
			.iter()
			.map(|byte| *byte as u8)
			.collect()
	}
}

/// The indices of the records one READDIR reply can hold in `size` bytes.
///
/// The server packs the returned entries with the same padded-length math, so
/// what comes back here is exactly what fits; the offsets are entry indices,
/// the scheme the VFS itself uses, so the next request resumes at the first
/// record not returned.
fn pack(records: &[RawDirent], size: u32, plus: bool) -> Vec<usize> {
	let limit = size as usize;
	let mut fitted = Vec::with_capacity(records.len());
	let mut used = 0usize;
	for (index, record) in records.iter().enumerate() {
		let name_len = (record.namelen as usize).min(record.name.len());
		let len = if plus {
			direntplus_len(name_len)
		} else {
			dirent_len(name_len)
		};
		if used + len > limit {
			break;
		}
		used += len;
		fitted.push(index);
	}
	fitted
}

impl FileSystem for Volume {
	type Inode = u64;
	type Handle = u64;

	async fn init(&self, capable: u32) -> io::Result<u32> {
		#[cfg(target_os = "linux")]
		let want = FUSE_ASYNC_READ
			| FUSE_BIG_WRITES
			| FUSE_MAX_PAGES
			| FUSE_DO_READDIRPLUS
			| FUSE_READDIRPLUS_AUTO;
		#[cfg(not(target_os = "linux"))]
		let want = FUSE_ASYNC_READ | FUSE_BIG_WRITES | FUSE_DO_READDIRPLUS | FUSE_READDIRPLUS_AUTO;
		Ok(capable & want)
	}

	async fn lookup(&self, ctx: &Context, parent: u64, name: &CStr) -> io::Result<Entry> {
		self.session
			.lookup(credentials(ctx), parent, name)
			.await
			.map(|entry| self.entry(entry))
	}

	// FORGET and BATCH_FORGET keep the trait's no-op: inode state lives in the
	// metadata store, and there is nothing to release locally.

	async fn getattr(
		&self,
		ctx: &Context,
		inode: u64,
		handle: Option<u64>,
	) -> io::Result<(Attr, (u64, u32))> {
		let raw = self
			.session
			.getattr(credentials(ctx), inode, handle.is_some())
			.await?;
		Ok((attr(raw), timeout(self.session.attr_ttl())))
	}

	async fn setattr(
		&self,
		ctx: &Context,
		inode: u64,
		values: Attr,
		handle: Option<u64>,
		valid: u32,
	) -> io::Result<(Attr, (u64, u32))> {
		let raw = self
			.session
			.setattr(
				credentials(ctx),
				inode,
				valid,
				handle.unwrap_or(0),
				values.mode,
				values.uid,
				values.gid,
				values.atime as i64,
				values.mtime as i64,
				values.atimensec,
				values.mtimensec,
				values.size,
			)
			.await?;
		Ok((attr(raw), timeout(self.session.attr_ttl())))
	}

	async fn readlink(&self, ctx: &Context, inode: u64) -> io::Result<Vec<u8>> {
		self.session.readlink(credentials(ctx), inode).await
	}

	async fn symlink(
		&self,
		ctx: &Context,
		linkname: &CStr,
		parent: u64,
		name: &CStr,
	) -> io::Result<Entry> {
		self.session
			.symlink(credentials(ctx), linkname, parent, name)
			.await
			.map(|entry| self.entry(entry))
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
		self.session
			.mknod(credentials(ctx), parent, name, mode, rdev, umask)
			.await
			.map(|entry| self.entry(entry))
	}

	async fn mkdir(
		&self,
		ctx: &Context,
		parent: u64,
		name: &CStr,
		mode: u32,
		umask: u32,
	) -> io::Result<Entry> {
		self.session
			.mkdir(credentials(ctx), parent, name, mode, umask)
			.await
			.map(|entry| self.entry(entry))
	}

	async fn unlink(&self, ctx: &Context, parent: u64, name: &CStr) -> io::Result<()> {
		self.session.unlink(credentials(ctx), parent, name).await
	}

	async fn rmdir(&self, ctx: &Context, parent: u64, name: &CStr) -> io::Result<()> {
		self.session.rmdir(credentials(ctx), parent, name).await
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
		self.session
			.rename(credentials(ctx), olddir, oldname, newdir, newname, flags)
			.await
	}

	async fn link(
		&self,
		ctx: &Context,
		inode: u64,
		newparent: u64,
		newname: &CStr,
	) -> io::Result<Entry> {
		self.session
			.link(credentials(ctx), inode, newparent, newname)
			.await
			.map(|entry| self.entry(entry))
	}

	async fn open(&self, ctx: &Context, inode: u64, flags: u32) -> io::Result<(u64, u32)> {
		let (handle, keep_cache) = self
			.session
			.open_file(credentials(ctx), inode, flags)
			.await?;
		// Direct I/O unless the VFS asked for cached pages: the front-end has
		// no kernel-initiated invalidation, so a cache it cannot invalidate is
		// only safe when the VFS knows the file will not change underneath it.
		let open_flags = if keep_cache {
			FOPEN_KEEP_CACHE
		} else {
			FOPEN_DIRECT_IO
		};
		Ok((handle, open_flags))
	}

	async fn create(
		&self,
		ctx: &Context,
		parent: u64,
		name: &CStr,
		args: CreateArgs,
	) -> io::Result<(Entry, u64, u32)> {
		let (raw, handle, keep_cache) = self
			.session
			.create(
				credentials(ctx),
				parent,
				name,
				args.mode,
				args.umask,
				args.flags,
			)
			.await?;
		let open_flags = if keep_cache {
			FOPEN_KEEP_CACHE
		} else {
			FOPEN_DIRECT_IO
		};
		Ok((self.entry(raw), handle, open_flags))
	}

	async fn read(
		&self,
		ctx: &Context,
		inode: u64,
		handle: u64,
		w: &mut dyn ZeroCopyWriter,
		size: u32,
		offset: u64,
	) -> io::Result<usize> {
		let memory = w.memory();
		let iov = iovecs(&*memory, w.extents(), size as usize)?;
		// SAFETY: the ranges are the reply's own guest memory, and the `Arc`
		// passed alongside keeps it alive in the pool job until the blocking
		// call returns, even if this future is dropped first.
		let written = unsafe {
			self.session
				.read(
					credentials(ctx),
					inode,
					handle,
					offset,
					&iov,
					Arc::clone(&memory),
				)
				.await?
		};
		w.written(written)?;
		Ok(written)
	}

	async fn write(
		&self,
		ctx: &Context,
		inode: u64,
		handle: u64,
		r: &mut dyn ZeroCopyReader,
		size: u32,
		offset: u64,
	) -> io::Result<usize> {
		let memory = r.memory();
		let iov = iovecs(&*memory, r.extents(size as usize), size as usize)?;
		// SAFETY: the ranges are the request's own guest memory, and the `Arc`
		// passed alongside keeps it alive until the copy into Go returns.
		unsafe {
			self.session
				.write(
					credentials(ctx),
					inode,
					handle,
					offset,
					&iov,
					Arc::clone(&memory),
				)
				.await?;
		}
		Ok(size as usize)
	}

	async fn fallocate(
		&self,
		ctx: &Context,
		inode: u64,
		handle: u64,
		offset: u64,
		length: u64,
		mode: u32,
	) -> io::Result<()> {
		self.session
			.fallocate(
				credentials(ctx),
				inode,
				handle,
				mode,
				offset as i64,
				length as i64,
			)
			.await
	}

	async fn flush(&self, ctx: &Context, inode: u64, handle: u64) -> io::Result<()> {
		// The wire's `lock_owner` never reaches the file system trait; the VFS
		// reads zero as "no lock to release".
		self.session.flush(credentials(ctx), inode, handle, 0).await
	}

	async fn fsync(
		&self,
		ctx: &Context,
		inode: u64,
		datasync: bool,
		handle: u64,
	) -> io::Result<()> {
		self.session
			.fsync(credentials(ctx), inode, handle, datasync)
			.await
	}

	async fn release(&self, ctx: &Context, inode: u64, _flags: u32, handle: u64) -> io::Result<()> {
		self.session.release(credentials(ctx), inode, handle).await
	}

	async fn statfs(&self, ctx: &Context, inode: u64) -> io::Result<Kstatfs> {
		let raw = self.session.statfs(credentials(ctx), inode).await?;
		Ok(Kstatfs {
			blocks: raw.blocks,
			bfree: raw.bfree,
			bavail: raw.bavail,
			files: raw.files,
			ffree: raw.ffree,
			bsize: raw.bsize,
			namelen: raw.namelen,
			frsize: raw.frsize,
			padding: 0,
			spare: [0; 6],
		})
	}

	async fn setxattr(
		&self,
		ctx: &Context,
		inode: u64,
		name: &CStr,
		value: &[u8],
		flags: u32,
	) -> io::Result<()> {
		self.session
			.setxattr(credentials(ctx), inode, name, value, flags)
			.await
	}

	async fn getxattr(
		&self,
		ctx: &Context,
		inode: u64,
		name: &CStr,
		size: u32,
	) -> io::Result<GetxattrReply> {
		match self
			.session
			.getxattr(credentials(ctx), inode, name, size)
			.await?
		{
			Xattr::Value(value) => Ok(GetxattrReply::Value(value)),
			Xattr::Size(size) => Ok(GetxattrReply::Size(size)),
		}
	}

	async fn listxattr(&self, ctx: &Context, inode: u64, size: u32) -> io::Result<ListxattrReply> {
		match self
			.session
			.listxattr(credentials(ctx), inode, size)
			.await?
		{
			ListXattr::Names(names) => Ok(ListxattrReply::Names(names)),
			ListXattr::Size(size) => Ok(ListxattrReply::Size(size)),
		}
	}

	async fn removexattr(&self, ctx: &Context, inode: u64, name: &CStr) -> io::Result<()> {
		self.session
			.removexattr(credentials(ctx), inode, name)
			.await
	}

	async fn opendir(&self, ctx: &Context, inode: u64) -> io::Result<u64> {
		// The trait carries no open flags, and the kernel's OPENDIR flags only
		// matter for a permission check; read access is the one it implies.
		self.session.opendir(credentials(ctx), inode, 0).await
	}

	async fn readdir(
		&self,
		ctx: &Context,
		inode: u64,
		handle: u64,
		size: u32,
		offset: u64,
	) -> io::Result<Vec<DirEntry>> {
		let capacity = (size as usize / MIN_DIRENT).min(MAX_DIRENTS);
		let (records, more) = self
			.session
			.readdir(credentials(ctx), inode, handle, offset, false, capacity)
			.await?;
		let fitted = pack(&records, size, false);
		if fitted.len() < records.len() || more {
			self.session
				.readdir_offset(
					credentials(ctx),
					inode,
					handle,
					offset + fitted.len() as u64,
				)
				.await?;
		}
		Ok(fitted
			.into_iter()
			.map(|index| {
				let record = &records[index];
				DirEntry {
					ino: record.ino,
					offset: offset + index as u64 + 1,
					type_: dirent_type(record.attr.mode),
					name: Self::name(record),
				}
			})
			.collect())
	}

	async fn readdirplus(
		&self,
		ctx: &Context,
		inode: u64,
		handle: u64,
		size: u32,
		offset: u64,
	) -> io::Result<Vec<(Entry, DirentInfo)>> {
		let capacity = (size as usize / MIN_DIRENTPLUS).min(MAX_DIRENTS);
		let (records, more) = self
			.session
			.readdir(credentials(ctx), inode, handle, offset, true, capacity)
			.await?;
		let fitted = pack(&records, size, true);
		if fitted.len() < records.len() || more {
			self.session
				.readdir_offset(
					credentials(ctx),
					inode,
					handle,
					offset + fitted.len() as u64,
				)
				.await?;
		}
		Ok(fitted
			.into_iter()
			.map(|index| {
				let record = &records[index];
				let entry = Entry {
					inode: record.ino,
					generation: 1,
					attr: attr(record.attr),
					attr_timeout: timeout(self.session.attr_ttl()),
					entry_timeout: timeout(self.session.entry_ttl()),
				};
				let info = DirentInfo {
					ino: record.ino,
					offset: offset + index as u64 + 1,
					type_: dirent_type(record.attr.mode),
					name: Self::name(record),
				};
				(entry, info)
			})
			.collect())
	}

	async fn fsyncdir(
		&self,
		ctx: &Context,
		inode: u64,
		datasync: bool,
		handle: u64,
	) -> io::Result<()> {
		self.session
			.fsync(credentials(ctx), inode, handle, datasync)
			.await
	}

	async fn releasedir(&self, ctx: &Context, inode: u64, handle: u64) -> io::Result<()> {
		self.session
			.releasedir(credentials(ctx), inode, handle)
			.await
	}

	async fn access(&self, ctx: &Context, inode: u64, mask: u32) -> io::Result<()> {
		self.session.access(credentials(ctx), inode, mask).await
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn record(name: &[u8]) -> RawDirent {
		let mut raw = RawDirent {
			namelen: name.len() as u32,
			..RawDirent::default()
		};
		for (slot, byte) in raw.name.iter_mut().zip(name) {
			*slot = *byte as std::ffi::c_char;
		}
		raw
	}

	/// The C layouts are the contract with the Go side: an `Attr` that is one
	/// field short would shift every attribute the guest reads.
	#[test]
	fn the_c_layouts_are_the_kernels() {
		assert_eq!(size_of::<crate::Attr>(), 88);
		assert_eq!(size_of::<crate::Entry>(), 96);
		assert_eq!(size_of::<Ctx>(), 12);
		assert_eq!(size_of::<IoVec>(), 16);
		assert_eq!(size_of::<crate::Dirent>(), 360);
		assert_eq!(size_of::<crate::Statfs>(), 56);
	}

	#[test]
	fn the_type_bits_are_the_kernels_dirent_tags() {
		assert_eq!(dirent_type(0o040755), 4, "a directory");
		assert_eq!(dirent_type(0o100644), 8, "a regular file");
		assert_eq!(dirent_type(0o120777), 10, "a symlink");
		assert_eq!(dirent_type(0), 0, "an unknown type");
	}

	/// A reply takes the records whose padded length still fits, and never
	/// splits one across the limit.
	#[test]
	fn a_reply_takes_only_the_records_that_fit() {
		let records: Vec<_> = (0..10).map(|_| record(b"abcd")).collect();
		// 24-byte dirent + 4-byte name, padded to 32.
		assert_eq!(pack(&records, 64, false), [0, 1]);
		assert_eq!(pack(&records, 96, false), [0, 1, 2]);
		// One byte short of the third record.
		assert_eq!(pack(&records, 95, false), [0, 1]);
	}

	/// READDIRPLUS records carry an entry, so fewer of them fit.
	#[test]
	fn a_plus_reply_pays_for_its_entries() {
		let records: Vec<_> = (0..10).map(|_| record(b"abcd")).collect();
		let record_len = direntplus_len(4);
		assert!(record_len > dirent_len(4));
		assert_eq!(pack(&records, (record_len * 2) as u32, true), [0, 1]);
		assert_eq!(
			pack(&records, (record_len * 2 - 1) as u32, true),
			[0],
			"one byte short must drop the second record"
		);
	}

	/// Names are copied out byte for byte, and a name that would overrun the
	/// record is cut at the array's bound.
	#[test]
	fn names_are_bytes_not_text() {
		let raw = record(b"a\xffz");
		assert_eq!(Volume::name(&raw), b"a\xffz");
		let overlong = RawDirent {
			namelen: u32::MAX,
			..RawDirent::default()
		};
		assert_eq!(Volume::name(&overlong).len(), overlong.name.len());
	}
}
