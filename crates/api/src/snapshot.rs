//! Point-in-time [`Snapshot`] lifecycle trait for [`Fuse`](crate::Fuse) and
//! [`Volume`](crate::Volume) back-ends.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use crate::fuse::{Attr, unsupported};
use crate::volume::{Volume, WalkEntry};

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

/// Change from snapshot to current state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DiffKind {
	/// The path exists in the current tree but not in the snapshot.
	Added,
	/// The path exists in both trees with different content, kind, or symlink
	/// target.
	Modified,
	/// The path exists in the snapshot but not in the current tree.
	Removed,
}

/// A [`Snapshot::diff`] result with a scope-relative path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffEntry {
	pub path: PathBuf,
	pub kind: DiffKind,
}

/// Point-in-time snapshots and writable branches of a [`Fuse`](crate::Fuse) or
/// [`Volume`](crate::Volume) back-end.
///
/// Every method defaults to `ENOSYS`, so a back-end implements only the
/// lifecycle operations its storage supports.
#[allow(async_fn_in_trait)]
pub trait Snapshot: Sized {
	type Id;

	/// Captures the current state as a snapshot.
	async fn snapshot(&self) -> io::Result<Self::Id> {
		Err(unsupported())
	}

	/// Forks a new writable instance from snapshot `id`.
	async fn branch(&self, _id: &Self::Id) -> io::Result<Self> {
		Err(unsupported())
	}

	/// Restores this instance's state to snapshot `id`.
	async fn restore(&self, _id: &Self::Id) -> io::Result<()> {
		Err(unsupported())
	}

	/// Deletes snapshot `id`.
	async fn delete(&self, _id: &Self::Id) -> io::Result<()> {
		Err(unsupported())
	}

	/// Reports changes from snapshot `id` to the current state beneath `scope`.
	/// Paths are relative to scope; scope itself is excluded. Results should
	/// be sorted by path. The snapshot is left unchanged.
	///
	/// Scope must be a directory wherever it exists. If present on only one
	/// side, all its descendants are added or removed. Absent on both sides
	/// returns `ENOENT`; a non-directory on either side returns `ENOTDIR`.
	///
	/// Compares file kinds, regular-file bytes, symlink targets, and device IDs.
	/// Ignores other attributes, including inode identity and timestamps.
	/// Same-size edits must be detected; directory mtimes cannot justify
	/// skipping descendants. Equal reads ending before the advertised size
	/// return [`UnexpectedEof`](io::ErrorKind::UnexpectedEof).
	///
	/// Traversal costs O(n) plus sorting; content comparison may read all file
	/// bytes. Concurrent mutations may produce a mixed view unless the backend
	/// supplies snapshot consistency. Defaults to `ENOSYS`; implementations
	/// with two volume views can use [`diff_volumes`].
	async fn diff(&self, _id: &Self::Id, _scope: &Path) -> io::Result<Vec<DiffEntry>> {
		Err(unsupported())
	}
}

/// Implements [`Snapshot::diff`] using two volume views.
/// Walks both trees, compares content in bounded chunks, and sorts results.
/// Uses O(entries) memory; same-size files require byte reads.
pub async fn diff_volumes<S, C>(
	snapshot: &S,
	current: &C,
	scope: &Path,
) -> io::Result<Vec<DiffEntry>>
where
	S: Volume + ?Sized,
	C: Volume + ?Sized,
{
	let snapshot_attr = stat_optional(snapshot, scope).await?;
	let current_attr = stat_optional(current, scope).await?;
	let snapshot_dir = optional_directory(snapshot_attr.as_ref())?;
	let current_dir = optional_directory(current_attr.as_ref())?;

	match (snapshot_dir, current_dir) {
		(false, false) => return Err(errno(libc::ENOENT)),
		(false, true) => {
			return walk_added(current, scope).await;
		}
		(true, false) => {
			return walk_removed(snapshot, scope).await;
		}
		(true, true) => {}
	}

	let snapshot_entries = snapshot.walk(scope).await?;
	let current_entries = current.walk(scope).await?;
	let mut snapshot_map = entry_map(snapshot_entries);
	let current_map = entry_map(current_entries);
	let mut diff = Vec::new();
	for (path, current_attr) in &current_map {
		match snapshot_map.remove(path) {
			None => diff.push(DiffEntry {
				path: path.clone(),
				kind: DiffKind::Added,
			}),
			Some(snapshot_attr) => {
				if modified(snapshot, current, scope, path, &snapshot_attr, current_attr).await? {
					diff.push(DiffEntry {
						path: path.clone(),
						kind: DiffKind::Modified,
					});
				}
			}
		}
	}
	for path in snapshot_map.into_keys() {
		diff.push(DiffEntry {
			path,
			kind: DiffKind::Removed,
		});
	}
	diff.sort_by(|a, b| a.path.cmp(&b.path));
	Ok(diff)
}

fn entry_map(entries: Vec<WalkEntry>) -> BTreeMap<PathBuf, Attr> {
	entries
		.into_iter()
		.map(|entry| (entry.path, entry.attr))
		.collect()
}

async fn walk_added<C: Volume + ?Sized>(current: &C, scope: &Path) -> io::Result<Vec<DiffEntry>> {
	Ok(current
		.walk(scope)
		.await?
		.into_iter()
		.map(|entry| DiffEntry {
			path: entry.path,
			kind: DiffKind::Added,
		})
		.collect())
}

async fn walk_removed<S: Volume + ?Sized>(
	snapshot: &S,
	scope: &Path,
) -> io::Result<Vec<DiffEntry>> {
	Ok(snapshot
		.walk(scope)
		.await?
		.into_iter()
		.map(|entry| DiffEntry {
			path: entry.path,
			kind: DiffKind::Removed,
		})
		.collect())
}

async fn stat_optional<V: Volume + ?Sized>(volume: &V, path: &Path) -> io::Result<Option<Attr>> {
	match volume.stat(path).await {
		Ok(attr) => Ok(Some(attr)),
		Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
		Err(error) => Err(error),
	}
}

fn optional_directory(attr: Option<&Attr>) -> io::Result<bool> {
	match attr {
		None => Ok(false),
		Some(attr) if attr.mode & S_IFMT == S_IFDIR => Ok(true),
		Some(_) => Err(errno(libc::ENOTDIR)),
	}
}

async fn modified<S: Volume + ?Sized, C: Volume + ?Sized>(
	snapshot: &S,
	current: &C,
	scope: &Path,
	path: &Path,
	snapshot_attr: &Attr,
	current_attr: &Attr,
) -> io::Result<bool> {
	let snapshot_kind = snapshot_attr.mode & S_IFMT;
	let current_kind = current_attr.mode & S_IFMT;
	if snapshot_kind != current_kind {
		return Ok(true);
	}
	let full = scope.join(path);
	match snapshot_kind {
		S_IFDIR => Ok(false),
		S_IFREG => {
			if snapshot_attr.size != current_attr.size {
				return Ok(true);
			}
			let mut offset = 0u64;
			while offset < current_attr.size {
				let len = (current_attr.size - offset).min(DIFF_CHUNK as u64) as usize;
				let snapshot_bytes = read_full(snapshot, &full, offset, len).await?;
				let current_bytes = read_full(current, &full, offset, len).await?;
				if snapshot_bytes != current_bytes {
					return Ok(true);
				}
				if current_bytes.len() < len {
					return Err(unexpected_eof(&full));
				}
				offset += len as u64;
			}
			Ok(false)
		}
		S_IFLNK => Ok(snapshot.readlink(&full).await? != current.readlink(&full).await?),
		_ => Ok(snapshot_attr.rdev != current_attr.rdev),
	}
}

const DIFF_CHUNK: usize = 64 * 1024;

/// Fills a range across short reads, stopping at EOF.
async fn read_full<V: Volume + ?Sized>(
	volume: &V,
	path: &Path,
	offset: u64,
	len: usize,
) -> io::Result<Vec<u8>> {
	let mut out = Vec::with_capacity(len);
	while out.len() < len {
		let at = offset
			.checked_add(out.len() as u64)
			.ok_or_else(|| errno(libc::EOVERFLOW))?;
		let remaining = len - out.len();
		let chunk = volume.read_range(path, at, remaining).await?;
		if chunk.is_empty() {
			break;
		}
		if chunk.len() > remaining {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"read_range returned more bytes than requested",
			));
		}
		out.extend_from_slice(&chunk);
	}
	Ok(out)
}

/// Rejects premature EOF instead of treating truncated files as equal.
fn unexpected_eof(path: &Path) -> io::Error {
	io::Error::new(
		io::ErrorKind::UnexpectedEof,
		format!("{} ended before its reported size", path.display()),
	)
}

fn errno(code: libc::c_int) -> io::Error {
	io::Error::from_raw_os_error(code)
}
