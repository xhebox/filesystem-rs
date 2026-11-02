#![allow(
	clippy::await_holding_refcell_ref,
	reason = "the tests drive one request at a time on this thread, and nothing else borrows the state meanwhile"
)]

use std::fs::{self, File, FileTimes, OpenOptions};
use std::future::Future;
use std::io;
use std::os::unix::fs::symlink;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use api::{Attr, Context, DiffKind, Fuse, Memory, MemoryRange, Snapshot, Volume, ZeroCopyWriter};
use completion::AsIoVec;

use crate::PassthroughFs;
use crate::abi::{FATTR_ATIME, FATTR_MODE, FATTR_MTIME, FATTR_SIZE, ROOT_ID};
use crate::imp::validate_component;

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

/// Runs a future, unwrapping the executor result.
fn run<F: Future>(future: F) -> F::Output {
	completion::block_on(future).unwrap()
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

	fn extents(&self) -> Vec<api::Extent> {
		vec![api::Extent {
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
	let count = completion::block_on(Fuse::read(
		&fs,
		&context,
		entry.inode,
		handle,
		&mut out,
		16,
		0,
	))
	.unwrap()
	.unwrap();
	assert_eq!(count, 4);
	assert_eq!(out.bytes(), b"four");
}

#[test]
fn snapshot_without_pool_is_unsupported() {
	let (_dir, _path, root) = root();
	let fs = filesystem(root, false);
	assert_eq!(
		completion::block_on(fs.snapshot())
			.unwrap()
			.unwrap_err()
			.raw_os_error(),
		Some(libc::EOPNOTSUPP)
	);
}

#[test]
fn snapshot_branch_restore_and_delete() {
	let (dir, path, root) = root();
	let pool_path = dir.path().join("snapshots");
	fs::create_dir(&pool_path).unwrap();
	let pool = OpenOptions::new().read(true).open(&pool_path).unwrap();

	let fs = PassthroughFs::with_snapshots(root, pool, false).unwrap();
	let context = Context::default();

	fs::write(path.join("file"), b"v1").unwrap();
	fs::hard_link(path.join("file"), path.join("hard")).unwrap();
	fs::create_dir(path.join("sub")).unwrap();
	fs::write(path.join("sub/nested"), b"nested-v1").unwrap();
	symlink("file", path.join("sym")).unwrap();
	let file_entry = fs
		.with(|state| state.lookup(&context, ROOT_ID, c"file"))
		.unwrap();
	fs.with(|state| state.set_xattr(&context, file_entry.inode, c"user.ver", b"1", 0))
		.unwrap();

	let snap1 = completion::block_on(fs.snapshot()).unwrap().unwrap();

	// Mutate the live workspace after taking `snap1`.
	fs::write(path.join("file"), b"v2").unwrap();
	fs::write(path.join("extra"), b"added").unwrap();
	fs::remove_file(path.join("sym")).unwrap();

	// Branching from `snap1` yields an isolated workspace at `snap1`'s state.
	let branched = completion::block_on(fs.branch(&snap1)).unwrap().unwrap();
	let branched_file = branched
		.with(|state| state.lookup(&context, ROOT_ID, c"file"))
		.unwrap();
	let branched_hard = branched
		.with(|state| state.lookup(&context, ROOT_ID, c"hard"))
		.unwrap();
	assert_eq!(branched_file.inode, branched_hard.inode);
	assert_eq!(
		branched
			.with(|state| state.get_xattr(&context, branched_file.inode, Some(c"user.ver"), 0))
			.unwrap(),
		b"1"
	);
	let branched_handle = branched
		.with(|state| state.open(&context, branched_file.inode, libc::O_RDONLY as u32))
		.unwrap();
	let mut data = [0u8; 8];
	let count = completion::block_on(async {
		let state = branched.state.borrow();
		state.read(branched_handle, 0, &mut data).await
	})
	.unwrap()
	.unwrap();
	assert_eq!(&data[..count], b"v1");
	branched
		.with(|state| state.release(branched_handle))
		.unwrap();
	assert!(
		branched
			.with(|state| state.lookup(&context, ROOT_ID, c"extra"))
			.is_err()
	);
	let branched_sym = branched
		.with(|state| state.lookup(&context, ROOT_ID, c"sym"))
		.unwrap();
	assert_eq!(
		branched
			.with(|state| state.read_link(branched_sym.inode))
			.unwrap(),
		b"file"
	);

	// Recursive snapshot from a branched workspace.
	let snap2 = completion::block_on(branched.snapshot()).unwrap().unwrap();
	completion::block_on(branched.delete(&snap2))
		.unwrap()
		.unwrap();

	// Restore the original workspace back to `snap1`.
	completion::block_on(fs.restore(&snap1)).unwrap().unwrap();
	assert_eq!(fs::read(path.join("file")).unwrap(), b"v1");
	assert_eq!(fs::read(path.join("sub/nested")).unwrap(), b"nested-v1");
	assert!(!path.join("extra").exists());
	assert_eq!(fs::read_link(path.join("sym")).unwrap(), Path::new("file"));

	// Deleting `snap1` reclaims it; branching from it afterwards fails with ENOENT.
	completion::block_on(fs.delete(&snap1)).unwrap().unwrap();
	assert_eq!(
		completion::block_on(fs.branch(&snap1))
			.unwrap()
			.err()
			.unwrap()
			.raw_os_error(),
		Some(libc::ENOENT)
	);
}

#[test]
fn volume_walk_is_sorted_relative_and_does_not_follow_symlinks() {
	let (_dir, path, root) = root();
	fs::create_dir(path.join("sub")).unwrap();
	fs::write(path.join("readme"), b"read").unwrap();
	fs::write(path.join("sub/nested"), b"nested").unwrap();
	symlink("sub", path.join("link")).unwrap();
	let fs = filesystem(root, false);

	let entries = run(Volume::walk(&fs, Path::new("/"))).unwrap();
	let paths: Vec<PathBuf> = entries.iter().map(|entry| entry.path.clone()).collect();
	assert_eq!(
		paths,
		vec![
			PathBuf::from("link"),
			PathBuf::from("readme"),
			PathBuf::from("sub"),
			PathBuf::from("sub/nested"),
		]
	);
	assert!(!paths.contains(&PathBuf::from("link/nested")));
	let link = entries
		.iter()
		.find(|entry| entry.path == Path::new("link"))
		.unwrap();
	assert_eq!(link.attr.mode & 0o170000, 0o120000);
	let nested = entries
		.iter()
		.find(|entry| entry.path == Path::new("sub/nested"))
		.unwrap();
	assert_eq!(nested.attr.size, 6);

	let scoped = run(Volume::walk(&fs, Path::new("sub"))).unwrap();
	assert_eq!(scoped.len(), 1);
	assert_eq!(scoped[0].path, PathBuf::from("nested"));

	assert_eq!(
		run(Volume::walk(&fs, Path::new("/missing")))
			.unwrap_err()
			.raw_os_error(),
		Some(libc::ENOENT)
	);
	assert_eq!(
		run(Volume::walk(&fs, Path::new("/readme")))
			.unwrap_err()
			.raw_os_error(),
		Some(libc::ENOTDIR)
	);
	assert_eq!(
		run(Volume::walk(&fs, Path::new("/link")))
			.unwrap_err()
			.raw_os_error(),
		Some(libc::ENOTDIR)
	);
	let again = run(Volume::walk(&fs, Path::new("/"))).unwrap();
	assert_eq!(
		again
			.iter()
			.map(|entry| entry.path.clone())
			.collect::<Vec<_>>(),
		paths
	);
}

#[test]
fn volume_read_range_is_bounded_at_eof_and_never_overflows() {
	let (_dir, path, root) = root();
	fs::create_dir(path.join("dir")).unwrap();
	fs::write(path.join("text"), b"0123456789").unwrap();
	symlink("text", path.join("link")).unwrap();
	let fs = filesystem(root, false);

	assert_eq!(
		run(Volume::read_range(&fs, Path::new("/text"), 0, 4)).unwrap(),
		b"0123"
	);
	assert_eq!(
		run(Volume::read_range(&fs, Path::new("/text"), 6, 100)).unwrap(),
		b"6789"
	);
	assert!(
		run(Volume::read_range(&fs, Path::new("/text"), 10, 4))
			.unwrap()
			.is_empty()
	);
	assert!(
		run(Volume::read_range(&fs, Path::new("/text"), u64::MAX, 4))
			.unwrap()
			.is_empty()
	);
	assert!(
		run(Volume::read_range(&fs, Path::new("/text"), 3, 0))
			.unwrap()
			.is_empty()
	);
	assert_eq!(
		run(Volume::read_range(&fs, Path::new("/text"), 2, usize::MAX)).unwrap(),
		b"23456789"
	);
	assert_eq!(
		run(Volume::read_range(&fs, Path::new("/missing"), 0, 1))
			.unwrap_err()
			.raw_os_error(),
		Some(libc::ENOENT)
	);
	assert_eq!(
		run(Volume::read_range(&fs, Path::new("/dir"), 0, 1))
			.unwrap_err()
			.raw_os_error(),
		Some(libc::EISDIR)
	);
	assert_eq!(
		run(Volume::read_range(&fs, Path::new("/link"), 0, 1))
			.unwrap_err()
			.raw_os_error(),
		Some(libc::ELOOP)
	);
}

#[test]
fn snapshot_diff_compares_content_and_copied_trees() {
	let (dir, path, root) = root();
	let pool_path = dir.path().join("snapshots");
	fs::create_dir(&pool_path).unwrap();
	let pool = OpenOptions::new().read(true).open(&pool_path).unwrap();
	let fs = PassthroughFs::with_snapshots(root, pool, false).unwrap();

	fs::create_dir(path.join("sub")).unwrap();
	fs::write(path.join("keep"), b"keep").unwrap();
	fs::write(path.join("edit"), b"AAAA").unwrap();
	fs::write(path.join("remove"), b"gone").unwrap();
	fs::write(path.join("kind"), b"file").unwrap();
	fs::write(path.join("sub/nested"), b"one!").unwrap();
	fs::write(path.join("sub/removed"), b"old!").unwrap();
	symlink("keep", path.join("link")).unwrap();
	let snapshot = run(fs.snapshot()).unwrap();

	// Detect same-size edits with unchanged mtime; ignore copied inode/ctime.
	let original_mtime = fs::metadata(path.join("edit")).unwrap().modified().unwrap();
	fs::write(path.join("edit"), b"BBBB").unwrap();
	OpenOptions::new()
		.write(true)
		.open(path.join("edit"))
		.unwrap()
		.set_times(FileTimes::new().set_modified(original_mtime))
		.unwrap();
	fs::write(path.join("sub/nested"), b"two!").unwrap();
	fs::write(path.join("add"), b"new").unwrap();
	fs::write(path.join("sub/added"), b"new").unwrap();
	fs::remove_file(path.join("remove")).unwrap();
	fs::remove_file(path.join("sub/removed")).unwrap();
	fs::remove_file(path.join("kind")).unwrap();
	fs::create_dir(path.join("kind")).unwrap();
	fs::write(path.join("kind/child"), b"x").unwrap();
	fs::remove_file(path.join("link")).unwrap();
	symlink("add", path.join("link")).unwrap();

	let diff = run(fs.diff(&snapshot, Path::new("/"))).unwrap();
	let changed: Vec<(PathBuf, DiffKind)> = diff
		.into_iter()
		.map(|entry| (entry.path, entry.kind))
		.collect();
	assert_eq!(
		changed,
		vec![
			(PathBuf::from("add"), DiffKind::Added),
			(PathBuf::from("edit"), DiffKind::Modified),
			(PathBuf::from("kind"), DiffKind::Modified),
			(PathBuf::from("kind/child"), DiffKind::Added),
			(PathBuf::from("link"), DiffKind::Modified),
			(PathBuf::from("remove"), DiffKind::Removed),
			(PathBuf::from("sub/added"), DiffKind::Added),
			(PathBuf::from("sub/nested"), DiffKind::Modified),
			(PathBuf::from("sub/removed"), DiffKind::Removed),
		]
	);

	let scoped = run(fs.diff(&snapshot, Path::new("sub"))).unwrap();
	assert_eq!(
		scoped
			.into_iter()
			.map(|entry| (entry.path, entry.kind))
			.collect::<Vec<_>>(),
		vec![
			(PathBuf::from("added"), DiffKind::Added),
			(PathBuf::from("nested"), DiffKind::Modified),
			(PathBuf::from("removed"), DiffKind::Removed),
		]
	);

	// The snapshot remains unchanged.
	let branched = run(fs.branch(&snapshot)).unwrap();
	assert_eq!(
		run(Volume::read(&branched, Path::new("/edit"))).unwrap(),
		b"AAAA"
	);
	assert!(run(fs.diff(&snapshot, Path::new("/missing"))).is_err());
	assert!(run(fs.diff(&999, Path::new("/"))).is_err());

	run(fs.restore(&snapshot)).unwrap();
	assert!(run(fs.diff(&snapshot, Path::new("/"))).unwrap().is_empty());
}

#[test]
fn volume_path_operations_and_confinement() {
	let (_dir, _path, root) = root();
	let fs = filesystem(root, false);

	assert!(
		completion::block_on(Volume::read(&fs, Path::new("../outside")))
			.unwrap()
			.is_err()
	);

	completion::block_on(fs.create_dir_all(Path::new("/a/b/c")))
		.unwrap()
		.unwrap();
	completion::block_on(Volume::write(&fs, Path::new("a/b/c/hello.txt"), b"world"))
		.unwrap()
		.unwrap();
	assert_eq!(
		completion::block_on(Volume::read(&fs, Path::new("/a/b/c/hello.txt")))
			.unwrap()
			.unwrap(),
		b"world"
	);
	assert_eq!(
		completion::block_on(fs.stat(Path::new("a/b/c/hello.txt")))
			.unwrap()
			.unwrap()
			.size,
		5
	);

	let copied =
		completion::block_on(fs.copy(Path::new("a/b/c/hello.txt"), Path::new("a/b/c/copied.txt")))
			.unwrap()
			.unwrap();
	assert_eq!(copied, 5);
	assert_eq!(
		completion::block_on(Volume::read(&fs, Path::new("a/b/c/copied.txt")))
			.unwrap()
			.unwrap(),
		b"world"
	);

	completion::block_on(Volume::rename(
		&fs,
		Path::new("a/b/c/copied.txt"),
		Path::new("a/b/moved.txt"),
	))
	.unwrap()
	.unwrap();
	completion::block_on(Volume::symlink(
		&fs,
		Path::new("moved.txt"),
		Path::new("a/b/link.txt"),
	))
	.unwrap()
	.unwrap();
	assert_eq!(
		completion::block_on(Volume::readlink(&fs, Path::new("a/b/link.txt")))
			.unwrap()
			.unwrap(),
		b"moved.txt"
	);

	let mut names: Vec<Vec<u8>> = completion::block_on(fs.list(Path::new("a/b")))
		.unwrap()
		.unwrap()
		.into_iter()
		.map(|entry| entry.name)
		.collect();
	names.sort();
	assert_eq!(
		names,
		vec![b"c".to_vec(), b"link.txt".to_vec(), b"moved.txt".to_vec()]
	);

	completion::block_on(fs.remove_file(Path::new("a/b/link.txt")))
		.unwrap()
		.unwrap();
	completion::block_on(fs.remove_all(Path::new("a")))
		.unwrap()
		.unwrap();
	assert!(
		completion::block_on(fs.list(Path::new("/")))
			.unwrap()
			.unwrap()
			.is_empty()
	);
}

#[test]
fn path_xattrs_search_and_external_changes() {
	use api::{IndexOptions, Search, SearchQuery, XATTR_SIG_NAME, decode_sig_xattr};
	let (_scratch, host, root) = root();
	let fs = filesystem(root, false).with_index(IndexOptions::default());
	run(async {
		let path = Path::new("/text");
		let mut data = b"padding\n".repeat(3000);
		data.extend_from_slice(b"a Needle end\n");
		Volume::write(&fs, path, &data).await.unwrap();
		Volume::setxattr(&fs, path, c"user.test", b"value", 0)
			.await
			.unwrap();
		assert_eq!(
			Volume::getxattr(&fs, path, c"user.test").await.unwrap(),
			b"value"
		);
		Volume::removexattr(&fs, path, c"user.test").await.unwrap();
		assert!(Volume::getxattr(&fs, path, c"user.test").await.is_err());
		let attr = Volume::stat(&fs, path).await.unwrap();
		let raw = Volume::getxattr(&fs, path, XATTR_SIG_NAME).await.unwrap();
		assert!(decode_sig_xattr(&attr, &raw).is_some());
		fs.search_index().unwrap().clear();
		let matches = fs
			.search(Path::new("/"), &SearchQuery::new("Needle"))
			.await
			.unwrap();
		assert_eq!(matches.len(), 1);
		assert_eq!((matches[0].line, matches[0].column), (3001, 3));
		assert_eq!(matches[0].line_text, "a Needle end");
		fs::write(host.join("text"), b"new external text\n").unwrap();
		assert!(decode_sig_xattr(&Volume::stat(&fs, path).await.unwrap(), &raw).is_none());
		fs.search_index().unwrap().notify_reset();
		let found = fs
			.search(Path::new("/"), &SearchQuery::new("external"))
			.await
			.unwrap();
		assert_eq!(found.len(), 1);
		assert_eq!((found[0].line, found[0].column), (1, 5));
	});
}

#[test]
fn indexed_search_snapshot_restores_xattrs() {
	use api::{IndexOptions, Search, SearchQuery, XATTR_SIG_NAME};
	let scratch = Scratch::new();
	let host = scratch.path().join("root");
	let pool = scratch.path().join("snapshots");
	fs::create_dir(&host).unwrap();
	fs::create_dir(&pool).unwrap();
	let fs = PassthroughFs::with_snapshots(
		File::open(&host).unwrap(),
		File::open(&pool).unwrap(),
		false,
	)
	.unwrap()
	.with_index(IndexOptions::default());
	run(async {
		let path = Path::new("/text");
		Volume::write(&fs, path, b"old snapshot text\n")
			.await
			.unwrap();
		let raw = Volume::getxattr(&fs, path, XATTR_SIG_NAME).await.unwrap();
		let id = fs.snapshot().await.unwrap();
		Volume::write(&fs, path, b"new text\n").await.unwrap();
		fs.restore(&id).await.unwrap();
		assert_eq!(
			Volume::getxattr(&fs, path, XATTR_SIG_NAME).await.unwrap(),
			raw
		);
		let found = fs
			.search(Path::new("/"), &SearchQuery::new("snapshot"))
			.await
			.unwrap();
		assert_eq!(found.len(), 1);
		assert_eq!((found[0].line, found[0].column), (1, 5));
	});
}

struct SearchReads<'a> {
	fs: &'a PassthroughFs,
	ranges: std::cell::RefCell<Vec<u64>>,
}

impl Volume for SearchReads<'_> {
	async fn walk(&self, path: &Path) -> io::Result<Vec<api::WalkEntry>> {
		self.fs.walk(path).await
	}
	async fn getxattr(&self, path: &Path, name: &std::ffi::CStr) -> io::Result<Vec<u8>> {
		Volume::getxattr(self.fs, path, name).await
	}
	async fn read(&self, _path: &Path) -> io::Result<Vec<u8>> {
		panic!("indexed search must not read the whole file")
	}
	async fn read_range(&self, path: &Path, offset: u64, len: usize) -> io::Result<Vec<u8>> {
		self.ranges.borrow_mut().push(offset);
		self.fs.read_range(path, offset, len.min(97)).await
	}
}

impl api::Search for SearchReads<'_> {
	fn search_index(&self) -> Option<&api::SearchIndex> {
		api::Search::search_index(self.fs)
	}
}

#[test]
fn indexed_read_ranges_skip_nonmatching_pages() {
	use api::{IndexOptions, Search, SearchQuery};
	let (_scratch, _host, root) = root();
	let fs = filesystem(root, false).with_index(IndexOptions::default());
	run(async {
		let mut data = b"padding\n".repeat(4096);
		data.extend_from_slice(b"unique Needle end\n");
		Volume::write(&fs, Path::new("/text"), &data).await.unwrap();
		fs.search_index().unwrap().clear();
		let counted = SearchReads {
			fs: &fs,
			ranges: std::cell::RefCell::new(Vec::new()),
		};
		let found = counted
			.search(Path::new("/"), &SearchQuery::new("Needle"))
			.await
			.unwrap();
		assert_eq!(found.len(), 1);
		assert_eq!((found[0].line, found[0].column), (4097, 8));
		assert!(
			counted
				.ranges
				.borrow()
				.iter()
				.all(|&offset| offset >= 6 * 4096)
		);
		counted.ranges.borrow_mut().clear();
		assert!(
			counted
				.search(Path::new("/"), &SearchQuery::new("ZZnotpresentZZ"))
				.await
				.unwrap()
				.is_empty()
		);
		assert!(counted.ranges.borrow().is_empty());
	});
}

#[test]
fn path_xattrs_respect_namespace_root_and_symlinks() {
	let (_scratch, host, root) = root();
	let fs = filesystem(root, false);
	fs::write(host.join("target"), b"data").unwrap();
	symlink("target", host.join("link")).unwrap();
	run(async {
		Volume::setxattr(&fs, Path::new("/"), c"user.root", b"value", 0)
			.await
			.unwrap();
		assert_eq!(
			Volume::getxattr(&fs, Path::new("/"), c"user.root")
				.await
				.unwrap(),
			b"value"
		);
		assert_eq!(
			Volume::getxattr(&fs, Path::new("/link"), c"user.root")
				.await
				.unwrap_err()
				.raw_os_error(),
			Some(libc::ENODATA)
		);
		assert_eq!(
			Volume::setxattr(&fs, Path::new("/link"), c"user.root", b"value", 0)
				.await
				.unwrap_err()
				.raw_os_error(),
			Some(libc::EPERM)
		);
		assert_eq!(
			Volume::getxattr(&fs, Path::new("/target"), c"security.hidden")
				.await
				.unwrap_err()
				.raw_os_error(),
			Some(libc::ENODATA)
		);
	});
}

struct RestartReads<'a> {
	fs: &'a PassthroughFs,
	walks: std::cell::Cell<usize>,
	reads: std::cell::RefCell<Vec<PathBuf>>,
	xattrs: std::cell::RefCell<Vec<PathBuf>>,
}
impl Volume for RestartReads<'_> {
	async fn walk(&self, path: &Path) -> io::Result<Vec<api::WalkEntry>> {
		self.walks.set(self.walks.get() + 1);
		self.fs.walk(path).await
	}
	async fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
		self.reads.borrow_mut().push(path.to_owned());
		Volume::read(self.fs, path).await
	}
	async fn getxattr(&self, path: &Path, name: &std::ffi::CStr) -> io::Result<Vec<u8>> {
		self.xattrs.borrow_mut().push(path.to_owned());
		Volume::getxattr(self.fs, path, name).await
	}
	async fn setxattr(
		&self,
		path: &Path,
		name: &std::ffi::CStr,
		value: &[u8],
		flags: u32,
	) -> io::Result<()> {
		Volume::setxattr(self.fs, path, name, value, flags).await
	}
}
impl api::Search for RestartReads<'_> {
	fn search_index(&self) -> Option<&api::SearchIndex> {
		api::Search::search_index(self.fs)
	}
}

#[test]
fn search_root_snapshots_survive_restart_and_reconcile_only_offline_changes() {
	use api::{IndexOptions, Search};
	let (_scratch, host, root) = root();
	let fs = filesystem(root, false).with_index(IndexOptions::default());
	run(async {
		Volume::write(&fs, Path::new("/same"), b"same\n")
			.await
			.unwrap();
		Volume::write(&fs, Path::new("/changed"), b"old\n")
			.await
			.unwrap();
		fs.indexed_walk(Path::new("/")).await.unwrap();
	});
	drop(fs);
	let fs = filesystem(File::open(&host).unwrap(), false).with_index(IndexOptions::default());
	let counted = RestartReads {
		fs: &fs,
		walks: std::cell::Cell::new(0),
		reads: Default::default(),
		xattrs: Default::default(),
	};
	run(async {
		assert_eq!(counted.indexed_walk(Path::new("/")).await.unwrap().len(), 2);
		assert!(counted.reads.borrow().is_empty());
		assert!(counted.xattrs.borrow().iter().all(|p| p == Path::new("/")));
		counted.indexed_walk(Path::new("/")).await.unwrap();
		assert_eq!(counted.walks.get(), 1);
	});
	drop(fs);
	fs::write(host.join("changed"), b"new\n").unwrap();
	let fs = filesystem(File::open(&host).unwrap(), false).with_index(IndexOptions::default());
	let counted = RestartReads {
		fs: &fs,
		walks: std::cell::Cell::new(0),
		reads: Default::default(),
		xattrs: Default::default(),
	};
	run(async {
		counted.indexed_walk(Path::new("/")).await.unwrap();
		assert_eq!(*counted.reads.borrow(), [PathBuf::from("/changed")]);
	});
}
