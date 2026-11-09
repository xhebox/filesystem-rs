//! Path-addressed [`Volume`] operations for callers outside a guest.

use std::ffi::CStr;
use std::io;
use std::path::{Path, PathBuf};

use crate::fuse::{Attr, DirEntry, unsupported};

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;

/// An entry beneath the root of a [`Volume::walk`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalkEntry {
	/// Path relative to the walk root.
	pub path: PathBuf,
	/// Attributes of the entry itself, never of a symlink's target.
	pub attr: Attr,
}

/// Path-addressed operations on a volume, for callers outside a guest.
///
/// Unsupported operations return `ENOSYS`; `walk` defaults to `list` + `stat`.
#[allow(async_fn_in_trait)]
pub trait Volume {
	/// Reads an extended attribute without following the final symlink.
	async fn getxattr(&self, _path: &Path, _name: &CStr) -> io::Result<Vec<u8>> {
		Err(unsupported())
	}

	/// Sets an extended attribute without following the final symlink.
	async fn setxattr(
		&self,
		_path: &Path,
		_name: &CStr,
		_value: &[u8],
		_flags: u32,
	) -> io::Result<()> {
		Err(unsupported())
	}

	/// Removes an extended attribute without following the final symlink.
	async fn removexattr(&self, _path: &Path, _name: &CStr) -> io::Result<()> {
		Err(unsupported())
	}

	/// Reads the entire contents of `path`.
	async fn read(&self, _path: &Path) -> io::Result<Vec<u8>> {
		Err(unsupported())
	}

	/// Reads up to `len` bytes at `offset` from a regular file.
	///
	/// EOF returns an empty buffer. Short reads may occur before EOF; loop to
	/// fill a range. A zero-length read still checks the path. Directories and
	/// symlinks fail as with [`read`](Volume::read).
	///
	/// Implementations must bound I/O to the requested range and remaining file
	/// length without overflowing `offset + len` or reading the whole file.
	/// Defaults to `ENOSYS`.
	async fn read_range(&self, _path: &Path, _offset: u64, _len: usize) -> io::Result<Vec<u8>> {
		Err(unsupported())
	}

	/// Lists all descendants of `root`, sorted by relative path, excluding root.
	/// Symlinks are reported without following them.
	///
	/// A missing root returns `ENOENT`; a non-directory or symlink root returns
	/// `ENOTDIR`. Entry errors propagate; unrepresentable names return
	/// [`InvalidData`](io::ErrorKind::InvalidData), as in [`name_to_path`].
	///
	/// Enumeration and result memory are O(n), sorting is O(n log n). No paging,
	/// streaming, or cancellation is provided. Concurrent mutations may produce
	/// a mixed view unless the backend supplies snapshot consistency.
	///
	/// Defaults to [`list`](Volume::list) + [`stat`](Volume::stat); backends may
	/// override it with native traversal.
	async fn walk(&self, root: &Path) -> io::Result<Vec<WalkEntry>> {
		walk_with_listing(self, root).await
	}

	/// Writes `data` to `path`, creating the file if absent or truncating it if
	/// present.
	async fn write(&self, _path: &Path, _data: &[u8]) -> io::Result<()> {
		Err(unsupported())
	}

	/// Queries the attributes of `path` without following a final symlink.
	async fn stat(&self, _path: &Path) -> io::Result<Attr> {
		Err(unsupported())
	}

	/// Reads the target of the symbolic link at `path`.
	async fn readlink(&self, _path: &Path) -> io::Result<Vec<u8>> {
		Err(unsupported())
	}

	/// Creates a symbolic link at `link` pointing to `target`.
	async fn symlink(&self, _target: &Path, _link: &Path) -> io::Result<()> {
		Err(unsupported())
	}

	/// Lists the direct entries of the directory at `path`.
	async fn list(&self, _path: &Path) -> io::Result<Vec<DirEntry>> {
		Err(unsupported())
	}

	/// Creates a directory at `path`.
	async fn create_dir(&self, _path: &Path) -> io::Result<()> {
		Err(unsupported())
	}

	/// Creates a directory at `path` and any missing parents.
	async fn create_dir_all(&self, _path: &Path) -> io::Result<()> {
		Err(unsupported())
	}

	/// Removes the file or symbolic link at `path`.
	async fn remove_file(&self, _path: &Path) -> io::Result<()> {
		Err(unsupported())
	}

	/// Removes the empty directory at `path`.
	async fn remove_dir(&self, _path: &Path) -> io::Result<()> {
		Err(unsupported())
	}

	/// Removes the file, symbolic link, or directory tree at `path`.
	async fn remove_all(&self, _path: &Path) -> io::Result<()> {
		Err(unsupported())
	}

	/// Renames `from` to `to`.
	async fn rename(&self, _from: &Path, _to: &Path) -> io::Result<()> {
		Err(unsupported())
	}

	/// Copies the regular file at `from` to `to`, returning the number of bytes
	/// copied.
	async fn copy(&self, _from: &Path, _to: &Path) -> io::Result<u64> {
		Err(unsupported())
	}
}

/// Lists and stats each entry, then sorts by relative path.
async fn walk_with_listing<V: Volume + ?Sized>(
	volume: &V,
	root: &Path,
) -> io::Result<Vec<WalkEntry>> {
	let attr = volume.stat(root).await?;
	if attr.mode & S_IFMT != S_IFDIR {
		return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
	}
	let mut out = Vec::new();
	let mut pending = vec![(root.to_path_buf(), PathBuf::new())];
	while let Some((directory, relative)) = pending.pop() {
		let mut entries = volume.list(&directory).await?;
		entries.sort_by(|a, b| a.name.cmp(&b.name));
		for entry in entries {
			let name = name_to_path(&entry.name)?;
			let child = directory.join(&name);
			let path = relative.join(&name);
			let attr = volume.stat(&child).await?;
			if attr.mode & S_IFMT == S_IFDIR {
				pending.push((child, path.clone()));
			}
			out.push(WalkEntry { path, attr });
		}
	}
	out.sort_by(|a, b| a.path.cmp(&b.path));
	Ok(out)
}

/// Converts [`DirEntry::name`] to a path: raw bytes on Unix, UTF-8 elsewhere.
/// Invalid UTF-8 on non-Unix platforms returns [`InvalidData`](io::ErrorKind::InvalidData).
pub fn name_to_path(name: &[u8]) -> io::Result<PathBuf> {
	#[cfg(unix)]
	{
		use std::os::unix::ffi::OsStrExt;
		Ok(PathBuf::from(std::ffi::OsStr::from_bytes(name)))
	}
	#[cfg(not(unix))]
	{
		let text = std::str::from_utf8(name).map_err(|_| {
			io::Error::new(
				io::ErrorKind::InvalidData,
				"a directory entry name is not valid UTF-8",
			)
		})?;
		Ok(PathBuf::from(text))
	}
}
