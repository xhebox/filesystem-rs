//! The platform surface of the passthrough backend on a host without confined
//! resolution.
//!
//! This module exists so the backend's platform-neutral code and the
//! `FileSystem` implementation type-check. Every operation is unavailable:
//! startup fails at `probe` with `ENOSYS`. A port keeps the exact surface —
//! single-component names only, no path reconstruction, identity-verified
//! upgrades (see `linux.rs`/`macos.rs` for the two existing strategies).

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::path::Path;

use fuse_api::Kstatfs;

fn unavailable() -> io::Error {
	io::Error::from_raw_os_error(libc::ENOSYS)
}

pub(super) fn probe(_root: libc::c_int) -> io::Result<()> {
	Err(unavailable())
}

pub(super) fn inspect(_root: libc::c_int, _path: &Path) -> io::Result<File> {
	Err(unavailable())
}

pub(super) fn inspect_name(_root: libc::c_int, _name: &CStr) -> io::Result<File> {
	Err(unavailable())
}

pub(super) fn open(_root: libc::c_int, _path: &Path, _flags: libc::c_int) -> io::Result<File> {
	Err(unavailable())
}

pub(super) fn open_with_mode(
	_root: libc::c_int,
	_path: &Path,
	_flags: libc::c_int,
	_mode: u32,
) -> io::Result<File> {
	Err(unavailable())
}

pub(super) fn open_name_with_mode(
	_root: libc::c_int,
	_name: &CStr,
	_flags: libc::c_int,
	_mode: u32,
) -> io::Result<File> {
	Err(unavailable())
}

pub(super) fn reopen(
	_file: &File,
	_parent_fd: libc::c_int,
	_name: &CStr,
	_flags: libc::c_int,
) -> io::Result<File> {
	Err(unavailable())
}

pub(super) fn read_link(_file: &File) -> io::Result<Vec<u8>> {
	Err(unavailable())
}

pub(super) fn mkdir(_parent: &File, _name: &CStr, _mode: u32) -> io::Result<()> {
	Err(unavailable())
}

pub(super) fn mknod(_parent: &File, _name: &CStr, _mode: u32, _rdev: u32) -> io::Result<()> {
	Err(unavailable())
}

pub(super) fn unlink(_parent: &File, _name: &CStr, _directory: bool) -> io::Result<()> {
	Err(unavailable())
}

pub(super) fn rename(
	_old_parent: &File,
	_old_name: &CStr,
	_new_parent: &File,
	_new_name: &CStr,
	_flags: u32,
) -> io::Result<()> {
	Err(unavailable())
}

pub(super) fn link(_file: &File, _parent: &File, _name: &CStr) -> io::Result<()> {
	Err(unavailable())
}

pub(super) fn symlink(_target: &CStr, _parent: &File, _name: &CStr) -> io::Result<()> {
	Err(unavailable())
}

pub(super) fn chmod(_file: &File, _mode: u32) -> io::Result<()> {
	Err(unavailable())
}

pub(super) fn chown(_file: &File, _uid: u32, _gid: u32) -> io::Result<()> {
	Err(unavailable())
}

pub(super) fn truncate(_file: &File, _size: u64) -> io::Result<()> {
	Err(unavailable())
}

pub(super) fn timestamps(
	_file: &File,
	_atime: libc::timespec,
	_mtime: libc::timespec,
) -> io::Result<()> {
	Err(unavailable())
}

pub(super) fn get_xattr(_file: &File, _name: Option<&CStr>) -> io::Result<Vec<u8>> {
	Err(unavailable())
}

pub(super) fn set_xattr(_file: &File, _name: &CStr, _value: &[u8], _flags: u32) -> io::Result<()> {
	Err(unavailable())
}

pub(super) fn remove_xattr(_file: &File, _name: &CStr) -> io::Result<()> {
	Err(unavailable())
}

pub(super) fn errno_clear() {}

pub(super) fn statfs(_file: &File) -> io::Result<Kstatfs> {
	Err(unavailable())
}
