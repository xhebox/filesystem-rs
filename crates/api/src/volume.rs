//! Path-addressed [`Volume`] operations for callers outside a guest.

use std::ffi::CStr;
use std::future::Future;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;

use crate::fuse::{Attr, DirEntry, unsupported};

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;

/// Boxed future used by [`VolumeWriter`] to remain runtime-agnostic.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Sequential streaming writer returned by [`Volume::open_write`].
///
/// Dropping a writer without calling [`finish`](VolumeWriter::finish) releases
/// the underlying handle without guaranteeing flush.
pub trait VolumeWriter<'v>: Send {
	/// Appends `data` at the current sequential write offset.
	fn write_all<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, io::Result<()>>;

	/// Flushes and closes the underlying file handle.
	fn finish(self: Box<Self>) -> BoxFuture<'v, io::Result<()>>;
}

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

	/// Opens `path` for sequential streaming writes, creating the file if
	/// absent or truncating it if present.
	async fn open_write<'v>(&'v self, _path: &Path) -> io::Result<Box<dyn VolumeWriter<'v> + 'v>> {
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

	/// Clones the file or directory tree at `src` to `dst` within the same
	/// volume.
	///
	/// `dst` must not already exist, and its parent directory must exist.
	/// Backends with native Copy-on-Write support (such as `JuiceFS` `Meta.Clone`,
	/// `MemFs` structural sharing, or `reflink`) can clone without copying file
	/// data blocks. Defaults to `ENOSYS`.
	async fn clone_tree(&self, _src: &Path, _dst: &Path) -> io::Result<()> {
		Err(unsupported())
	}
}

impl<V: Volume + ?Sized> Volume for &V {
	async fn getxattr(&self, path: &Path, name: &CStr) -> io::Result<Vec<u8>> {
		(**self).getxattr(path, name).await
	}

	async fn setxattr(&self, path: &Path, name: &CStr, value: &[u8], flags: u32) -> io::Result<()> {
		(**self).setxattr(path, name, value, flags).await
	}

	async fn removexattr(&self, path: &Path, name: &CStr) -> io::Result<()> {
		(**self).removexattr(path, name).await
	}

	async fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
		(**self).read(path).await
	}

	async fn read_range(&self, path: &Path, offset: u64, len: usize) -> io::Result<Vec<u8>> {
		(**self).read_range(path, offset, len).await
	}

	async fn walk(&self, root: &Path) -> io::Result<Vec<WalkEntry>> {
		(**self).walk(root).await
	}

	async fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
		(**self).write(path, data).await
	}

	async fn open_write<'v>(&'v self, path: &Path) -> io::Result<Box<dyn VolumeWriter<'v> + 'v>> {
		(**self).open_write(path).await
	}

	async fn stat(&self, path: &Path) -> io::Result<Attr> {
		(**self).stat(path).await
	}

	async fn readlink(&self, path: &Path) -> io::Result<Vec<u8>> {
		(**self).readlink(path).await
	}

	async fn symlink(&self, target: &Path, link: &Path) -> io::Result<()> {
		(**self).symlink(target, link).await
	}

	async fn list(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
		(**self).list(path).await
	}

	async fn create_dir(&self, path: &Path) -> io::Result<()> {
		(**self).create_dir(path).await
	}

	async fn create_dir_all(&self, path: &Path) -> io::Result<()> {
		(**self).create_dir_all(path).await
	}

	async fn remove_file(&self, path: &Path) -> io::Result<()> {
		(**self).remove_file(path).await
	}

	async fn remove_dir(&self, path: &Path) -> io::Result<()> {
		(**self).remove_dir(path).await
	}

	async fn remove_all(&self, path: &Path) -> io::Result<()> {
		(**self).remove_all(path).await
	}

	async fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
		(**self).rename(from, to).await
	}

	async fn copy(&self, from: &Path, to: &Path) -> io::Result<u64> {
		(**self).copy(from, to).await
	}

	async fn clone_tree(&self, src: &Path, dst: &Path) -> io::Result<()> {
		(**self).clone_tree(src, dst).await
	}
}

/// A [`Volume`] view scoped to a subdirectory `root` of an underlying volume.
///
/// Paths passed to `SubVolume` are resolved relative to `root`; `..` components
/// cannot escape above `root`.
#[derive(Clone, Debug)]
pub struct SubVolume<V> {
	inner: V,
	root: PathBuf,
}

impl<V> SubVolume<V> {
	/// Creates a scoped view rooted at `root` within `inner`.
	///
	/// Rejects `root` paths that contain `..` escaping above the volume root.
	pub fn new(inner: V, root: impl AsRef<Path>) -> io::Result<Self> {
		let root = normalize_subpath(root.as_ref())?;
		let rooted = if root.as_os_str().is_empty() {
			PathBuf::from("/")
		} else {
			PathBuf::from("/").join(root)
		};
		Ok(Self {
			inner,
			root: rooted,
		})
	}

	/// Returns a reference to the underlying volume.
	pub fn inner(&self) -> &V {
		&self.inner
	}

	/// Returns the root path within the underlying volume.
	pub fn root(&self) -> &Path {
		&self.root
	}

	fn resolve(&self, path: &Path) -> io::Result<PathBuf> {
		let rel = normalize_subpath(path)?;
		if rel.as_os_str().is_empty() {
			Ok(self.root.clone())
		} else {
			Ok(self.root.join(rel))
		}
	}
}

fn normalize_subpath(path: &Path) -> io::Result<PathBuf> {
	let mut parts = Vec::new();
	for component in path.components() {
		match component {
			Component::RootDir | Component::CurDir => {}
			Component::ParentDir => {
				if parts.pop().is_none() {
					return Err(io::Error::from_raw_os_error(libc::EACCES));
				}
			}
			Component::Normal(part) => parts.push(part),
			Component::Prefix(_) => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
		}
	}
	let mut out = PathBuf::new();
	for part in parts {
		out.push(part);
	}
	Ok(out)
}

impl<V: Volume> Volume for SubVolume<V> {
	async fn getxattr(&self, path: &Path, name: &CStr) -> io::Result<Vec<u8>> {
		let path = self.resolve(path)?;
		self.inner.getxattr(&path, name).await
	}

	async fn setxattr(&self, path: &Path, name: &CStr, value: &[u8], flags: u32) -> io::Result<()> {
		let path = self.resolve(path)?;
		self.inner.setxattr(&path, name, value, flags).await
	}

	async fn removexattr(&self, path: &Path, name: &CStr) -> io::Result<()> {
		let path = self.resolve(path)?;
		self.inner.removexattr(&path, name).await
	}

	async fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
		let path = self.resolve(path)?;
		self.inner.read(&path).await
	}

	async fn read_range(&self, path: &Path, offset: u64, len: usize) -> io::Result<Vec<u8>> {
		let path = self.resolve(path)?;
		self.inner.read_range(&path, offset, len).await
	}

	async fn walk(&self, root: &Path) -> io::Result<Vec<WalkEntry>> {
		let root = self.resolve(root)?;
		self.inner.walk(&root).await
	}

	async fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
		let path = self.resolve(path)?;
		self.inner.write(&path, data).await
	}

	async fn open_write<'v>(&'v self, path: &Path) -> io::Result<Box<dyn VolumeWriter<'v> + 'v>> {
		let path = self.resolve(path)?;
		self.inner.open_write(&path).await
	}

	async fn stat(&self, path: &Path) -> io::Result<Attr> {
		let path = self.resolve(path)?;
		self.inner.stat(&path).await
	}

	async fn readlink(&self, path: &Path) -> io::Result<Vec<u8>> {
		let path = self.resolve(path)?;
		self.inner.readlink(&path).await
	}

	async fn symlink(&self, target: &Path, link: &Path) -> io::Result<()> {
		let link = self.resolve(link)?;
		self.inner.symlink(target, &link).await
	}

	async fn list(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
		let path = self.resolve(path)?;
		self.inner.list(&path).await
	}

	async fn create_dir(&self, path: &Path) -> io::Result<()> {
		let path = self.resolve(path)?;
		self.inner.create_dir(&path).await
	}

	async fn create_dir_all(&self, path: &Path) -> io::Result<()> {
		let path = self.resolve(path)?;
		self.inner.create_dir_all(&path).await
	}

	async fn remove_file(&self, path: &Path) -> io::Result<()> {
		let path = self.resolve(path)?;
		self.inner.remove_file(&path).await
	}

	async fn remove_dir(&self, path: &Path) -> io::Result<()> {
		let path = self.resolve(path)?;
		self.inner.remove_dir(&path).await
	}

	async fn remove_all(&self, path: &Path) -> io::Result<()> {
		let path = self.resolve(path)?;
		self.inner.remove_all(&path).await
	}

	async fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
		let from = self.resolve(from)?;
		let to = self.resolve(to)?;
		self.inner.rename(&from, &to).await
	}

	async fn copy(&self, from: &Path, to: &Path) -> io::Result<u64> {
		let from = self.resolve(from)?;
		let to = self.resolve(to)?;
		self.inner.copy(&from, &to).await
	}

	async fn clone_tree(&self, src: &Path, dst: &Path) -> io::Result<()> {
		let src = self.resolve(src)?;
		let dst = self.resolve(dst)?;
		self.inner.clone_tree(&src, &dst).await
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
