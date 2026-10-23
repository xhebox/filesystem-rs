//! Syscall wrappers the Linux and macOS passthrough backends share: each one
//! is a single fd-relative call with the same arguments on both kernels.

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

/// The `(st_dev, st_ino)` identity of an open file descriptor.
pub(super) fn fstat_identity(fd: libc::c_int) -> io::Result<(u64, u64)> {
	let mut stat: libc::stat = unsafe { std::mem::zeroed() };
	if unsafe { libc::fstat(fd, &mut stat) } < 0 {
		return Err(io::Error::last_os_error());
	}
	Ok((stat.st_dev as u64, stat.st_ino as u64))
}

pub(crate) fn mkdir(parent: &File, name: &CStr, mode: u32) -> io::Result<()> {
	cvt(unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) })
}

pub(crate) fn mknod(parent: &File, name: &CStr, mode: u32, rdev: u32) -> io::Result<()> {
	cvt(unsafe {
		libc::mknodat(
			parent.as_raw_fd(),
			name.as_ptr(),
			mode as libc::mode_t,
			rdev as libc::dev_t,
		)
	})
}

pub(crate) fn unlink(parent: &File, name: &CStr, directory: bool) -> io::Result<()> {
	cvt(unsafe {
		libc::unlinkat(
			parent.as_raw_fd(),
			name.as_ptr(),
			if directory { libc::AT_REMOVEDIR } else { 0 },
		)
	})
}

pub(crate) fn symlink(target: &CStr, parent: &File, name: &CStr) -> io::Result<()> {
	cvt(unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr()) })
}

pub(crate) fn chmod(file: &File, mode: u32) -> io::Result<()> {
	cvt(unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) })
}

pub(crate) fn chown(file: &File, uid: u32, gid: u32) -> io::Result<()> {
	cvt(unsafe { libc::fchown(file.as_raw_fd(), uid, gid) })
}

pub(crate) fn truncate(file: &File, size: u64) -> io::Result<()> {
	let size =
		libc::off_t::try_from(size).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
	cvt(unsafe { libc::ftruncate(file.as_raw_fd(), size) })
}

pub(crate) fn timestamps(
	file: &File,
	atime: libc::timespec,
	mtime: libc::timespec,
) -> io::Result<()> {
	let times = [atime, mtime];
	cvt(unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) })
}

pub(super) fn cvt(result: libc::c_int) -> io::Result<()> {
	if result == 0 {
		Ok(())
	} else {
		Err(io::Error::last_os_error())
	}
}
