//! Linux confined pathname resolution for the passthrough backend.
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
//! st_ino)` identity — the same verified-reopen protocol as macOS (see
//! `reopen`).
//!

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rustix::fs::ResolveFlags as Resolve;

use fuse_api::Kstatfs;
pub(super) use posix::{chmod, chown, mkdir, mknod, symlink, timestamps, truncate, unlink};
#[path = "posix.rs"]
mod posix;

use posix::{cvt, fstat_identity};
const O_PATH: i32 = 0o10_000_000;

const RESOLVE: Resolve = Resolve::BENEATH.union(Resolve::NO_SYMLINKS);

pub(super) fn probe(root: libc::c_int) -> io::Result<()> {
	drop(open(root, Path::new("."), O_PATH | libc::O_DIRECTORY)?);
	Ok(())
}

pub(super) fn inspect(root: libc::c_int, path: &Path) -> io::Result<File> {
	open(root, path, O_PATH | libc::O_NOFOLLOW)
}

pub(super) fn inspect_name(root: libc::c_int, name: &CStr) -> io::Result<File> {
	open_cstr(root, name, O_PATH | libc::O_NOFOLLOW, 0)
}

pub(super) fn open(root: libc::c_int, path: &Path, flags: libc::c_int) -> io::Result<File> {
	open_with_mode(root, path, flags, 0)
}

pub(super) fn open_with_mode(
	root: libc::c_int,
	path: &Path,
	flags: libc::c_int,
	mode: u32,
) -> io::Result<File> {
	let bytes = if path.as_os_str().is_empty() {
		b".".as_slice()
	} else {
		path.as_os_str().as_bytes()
	};
	let path = CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
	open_cstr(root, &path, flags, mode)
}

pub(super) fn open_name_with_mode(
	root: libc::c_int,
	name: &CStr,
	flags: libc::c_int,
	mode: u32,
) -> io::Result<File> {
	open_cstr(root, name, flags, mode)
}

fn open_cstr(root: libc::c_int, path: &CStr, flags: libc::c_int, mode: u32) -> io::Result<File> {
	use rustix::fs::{Mode, OFlags};
	use std::os::fd::BorrowedFd;

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
/// The identity handle pins the inode for the whole window, so a
/// swapped-in file can never be confused with the pinned one — the
/// TOCTTOU is closed by verification, not by luck. No procfs, no magic
/// links, no path reconstruction.
pub(super) fn reopen(
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

pub(super) fn read_link(file: &File) -> io::Result<Vec<u8>> {
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

pub(super) fn rename(
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

pub(super) fn link(file: &File, parent: &File, name: &CStr) -> io::Result<()> {
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

pub(super) fn get_xattr(file: &File, name: Option<&CStr>) -> io::Result<Vec<u8>> {
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

pub(super) fn set_xattr(file: &File, name: &CStr, value: &[u8], flags: u32) -> io::Result<()> {
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

pub(super) fn remove_xattr(file: &File, name: &CStr) -> io::Result<()> {
	cvt(unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr()) })
}

pub(super) fn errno_clear() {
	unsafe { *libc::__errno_location() = 0 };
}

pub(super) fn statfs(file: &File) -> io::Result<Kstatfs> {
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

fn cvt_long(result: libc::c_long) -> io::Result<()> {
	if result == 0 {
		Ok(())
	} else {
		Err(io::Error::last_os_error())
	}
}
