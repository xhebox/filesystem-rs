//! Path-addressed [`Volume`] operations for callers outside a guest.

use std::io;
use std::path::Path;

use crate::fuse::{Attr, DirEntry, unsupported};

/// Path-addressed operations on a volume, for callers outside a guest.
///
/// Every method defaults to `ENOSYS`, so a back-end implements only what it
/// supports.
#[allow(async_fn_in_trait)]
pub trait Volume {
	/// Reads the entire contents of `path`.
	async fn read(&self, _path: &Path) -> io::Result<Vec<u8>> {
		Err(unsupported())
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
