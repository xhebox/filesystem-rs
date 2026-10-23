//! macOS confined pathname resolution for the passthrough backend.
//!
//! macOS has no `openat2`, so confinement is achieved by construction rather
//! than by a single atomic kernel check:
//!
//! - Every pathname that reaches this module is a single, already-validated
//!   component (see `backend::validate_component`) or `.`. Components cannot
//!   contain `/`, `..`, or NUL, so `openat` from the root fd cannot resolve
//!   outside the preopened directory.
//! - Lookups open the name with `O_SYMLINK`, which opens a symlink itself
//!   instead of following it: links are visible to the guest (`read_link`,
//!   `getattr`) but can never be traversed, because every open is one
//!   component and the backend refuses to `open` a symlink node.
//!
//! Upgrades (handle with read-only identity → handle with guest-requested
//! access) re-derive the handle from its `(parent, name)` locator and
//! verify `(st_dev, st_ino)` against the pinned identity handle — see
//! `reopen`. Linux does this atomically via `openat2(fd, "")`; here it is
//! verified, which is why every node carries its locator.
//!
//! Known gaps:
//! - No `RESOLVE_NO_XDEV` equivalent: the volume is a path subtree, and this
//!   platform never enforced mount boundaries.
//! - There is no `O_PATH`: inspect handles are opened `O_RDONLY`, so
//!   looking up a file the host user cannot read fails with `EACCES`
//!   where the Linux backend's lookup would succeed.
//! - `link` cannot name its source fd (`AT_EMPTY_PATH` is Linux-only); the
//!   source path is recovered with `F_GETPATH` on the already-confined fd.
//!   A concurrent rename between `F_GETPATH` and the syscall is a narrow
//!   TOCTOU window that cannot escape the volume's authority, only misname
//!   the source object.
//! - A node whose locator went stale (host-side rename/unlink of an object
//!   with an open handle) fails its next upgrade with `ESTALE`; the guest
//!   re-looks it up. Linux keeps serving such handles.
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use fuse_api::Kstatfs;
pub(super) use posix::{chmod, chown, mkdir, mknod, symlink, timestamps, truncate, unlink};
#[path = "posix.rs"]
mod posix;

use posix::{cvt, fstat_identity};
pub(super) fn probe(root: libc::c_int) -> io::Result<()> {
	// The root must be openable; confinement needs no auxiliary filesystem
	// (there is no `/dev/fd` dependency — see `reopen`).
	drop(open(root, Path::new("."), libc::O_DIRECTORY)?);
	Ok(())
}

pub(super) fn inspect(root: libc::c_int, path: &Path) -> io::Result<File> {
	open(
		root,
		path,
		libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK,
	)
}

pub(super) fn inspect_name(root: libc::c_int, name: &CStr) -> io::Result<File> {
	// O_SYMLINK (not O_NOFOLLOW) is the Darwin equivalent of Linux's O_PATH
	// lookup: it opens a symlink itself instead of following it or failing
	// with ELOOP, so the backend can serve read_link and enforce its symlink
	// policy at open time. The name is a single validated component, and
	// O_SYMLINK never traverses the link, so nothing escapes the root fd.
	// This Darwin kernel rejects O_NOFOLLOW_ANY with EINVAL despite libc
	// advertising it, so it is not used as defense in depth.
	open_cstr(
		root,
		name,
		libc::O_RDONLY | libc::O_SYMLINK | libc::O_NONBLOCK,
		0,
	)
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
	let fd = unsafe {
		libc::openat(
			root,
			path.as_ptr(),
			flags | libc::O_CLOEXEC,
			mode as libc::c_uint,
		)
	};
	if fd < 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(unsafe { File::from_raw_fd(fd) })
}

/// Re-opens a confined handle with new access flags. macOS has no
/// `openat2(fd, "")`, so the handle is re-derived from its `(parent_fd,
/// name)` locator and the result is **verified against the handle's
/// identity**: `(st_dev, st_ino)` must match, or the locator went stale
/// (host-side rename/unlink) and the request fails with `ESTALE`. The
/// identity handle pins the inode for the whole window, so a swapped-in
/// file can never be confused with the pinned one — the TOCTTOU is closed
/// by verification, not by luck.
pub(super) fn reopen(
	file: &File,
	parent_fd: libc::c_int,
	name: &CStr,
	flags: libc::c_int,
) -> io::Result<File> {
	let pinned = fstat_identity(file.as_raw_fd())?;
	let fd = unsafe {
		libc::openat(
			parent_fd,
			name.as_ptr(),
			(flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as libc::c_int,
			0,
		)
	};
	if fd < 0 {
		return Err(io::Error::last_os_error());
	}
	let reopened = unsafe { File::from_raw_fd(fd) };
	if fstat_identity(reopened.as_raw_fd())? != pinned {
		return Err(io::Error::from_raw_os_error(libc::ESTALE));
	}
	Ok(reopened)
}

/// Absolute path of an fd's vnode. The fd's confinement is already
/// established; the path is only used to name the same object in syscalls
/// macOS does not provide an fd-relative variant for (`link`).
fn path_of_fd(file: &File) -> io::Result<CString> {
	let mut buffer = vec![0 as libc::c_char; libc::PATH_MAX as usize];
	if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buffer.as_mut_ptr()) } < 0 {
		return Err(io::Error::last_os_error());
	}
	let bytes: Vec<u8> = buffer
		.iter()
		.take_while(|byte| **byte != 0)
		.map(|byte| *byte as u8)
		.collect();
	CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(libc::EIO))
}

pub(super) fn read_link(file: &File) -> io::Result<Vec<u8>> {
	// Darwin readlinkat has no Linux-style empty-path extension; the fd was
	// opened O_SYMLINK, so recover the link's own path with F_GETPATH and
	// read through it.
	let path = path_of_fd(file)?;
	let mut target = vec![0; libc::PATH_MAX as usize];
	let length = unsafe { libc::readlink(path.as_ptr(), target.as_mut_ptr().cast(), target.len()) };
	if length < 0 {
		return Err(io::Error::last_os_error());
	}
	target.truncate(length as usize);
	Ok(target)
}

/// Darwin `renameatx_np` flag with the same no-replacement semantics.
const DARWIN_RENAME_EXCL: libc::c_uint = 0x0000_0004;

use super::{RENAME_EXCHANGE, RENAME_NOREPLACE};

pub(super) fn rename(
	old_parent: &File,
	old_name: &CStr,
	new_parent: &File,
	new_name: &CStr,
	flags: u32,
) -> io::Result<()> {
	if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE) != 0 {
		return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
	}
	if flags & RENAME_EXCHANGE != 0 {
		// Darwin has no exchange rename.
		return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
	}
	if flags & RENAME_NOREPLACE != 0 {
		return cvt(unsafe {
			libc::renameatx_np(
				old_parent.as_raw_fd(),
				old_name.as_ptr(),
				new_parent.as_raw_fd(),
				new_name.as_ptr(),
				DARWIN_RENAME_EXCL,
			)
		});
	}
	cvt(unsafe {
		libc::renameat(
			old_parent.as_raw_fd(),
			old_name.as_ptr(),
			new_parent.as_raw_fd(),
			new_name.as_ptr(),
		)
	})
}

pub(super) fn link(file: &File, parent: &File, name: &CStr) -> io::Result<()> {
	// No `linkat(AT_EMPTY_PATH)` on Darwin: name the confined source fd via
	// F_GETPATH and hardlink it under the destination parent fd.
	let source = path_of_fd(file)?;
	cvt(unsafe {
		libc::linkat(
			libc::AT_FDCWD,
			source.as_ptr(),
			parent.as_raw_fd(),
			name.as_ptr(),
			0,
		)
	})
}

pub(super) fn get_xattr(file: &File, name: Option<&CStr>) -> io::Result<Vec<u8>> {
	let name = name.map(|name| name.as_ptr()).unwrap_or(std::ptr::null());
	let size = if name.is_null() {
		// Darwin xattr calls take a trailing `options` argument (and fgetxattr
		// a `position` before it); both 0 outside resource forks.
		unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0, 0) }
	} else {
		unsafe { libc::fgetxattr(file.as_raw_fd(), name, std::ptr::null_mut(), 0, 0, 0) }
	};
	if size < 0 {
		return Err(io::Error::last_os_error());
	}
	let mut value = vec![0; size as usize];
	let result = if name.is_null() {
		unsafe { libc::flistxattr(file.as_raw_fd(), value.as_mut_ptr().cast(), value.len(), 0) }
	} else {
		unsafe {
			libc::fgetxattr(
				file.as_raw_fd(),
				name,
				value.as_mut_ptr().cast(),
				value.len(),
				0,
				0,
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
	// XATTR_CREATE/XATTR_REPLACE share the Linux flag values (1/2).
	cvt(unsafe {
		libc::fsetxattr(
			file.as_raw_fd(),
			name.as_ptr(),
			value.as_ptr().cast(),
			value.len(),
			0,
			flags as libc::c_int,
		)
	})
}

pub(super) fn remove_xattr(file: &File, name: &CStr) -> io::Result<()> {
	cvt(unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr(), 0) })
}

pub(super) fn errno_clear() {
	unsafe { *libc::__error() = 0 };
}

pub(super) fn statfs(file: &File) -> io::Result<Kstatfs> {
	// fstatvfs, not fstatfs: the pinned libc's Darwin `statfs` struct omits
	// f_namemax/f_frsize while its `statvfs` struct carries both.
	let mut stat = unsafe { std::mem::zeroed::<libc::statvfs>() };
	if unsafe { libc::fstatvfs(file.as_raw_fd(), &mut stat) } < 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(Kstatfs {
		blocks: stat.f_blocks as u64,
		bfree: stat.f_bfree as u64,
		bavail: stat.f_bavail as u64,
		files: stat.f_files as u64,
		ffree: stat.f_ffree as u64,
		bsize: stat.f_bsize as u32,
		namelen: stat.f_namemax as u32,
		frsize: stat.f_frsize as u32,
		..Kstatfs::default()
	})
}
