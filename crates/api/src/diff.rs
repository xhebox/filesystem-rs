//! Tree diffing helpers built on [`Volume`] and [`SubVolume`](crate::SubVolume).

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use crate::fuse::Attr;
use crate::volume::{SubVolume, Volume, WalkEntry};

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

/// Change between two directory trees.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DiffKind {
	/// The path exists in the target tree but not in the base tree.
	Added,
	/// The path exists in both trees with different content, kind, or symlink
	/// target.
	Modified,
	/// The path exists in the base tree but not in the target tree.
	Removed,
}

/// A tree diff result with a scope-relative path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffEntry {
	pub path: PathBuf,
	pub kind: DiffKind,
}

/// Reports changes from `base` subtree to `target` subtree beneath `scope`
/// within the same [`Volume`].
pub async fn diff_trees<V>(
	volume: &V,
	base: &Path,
	target: &Path,
	scope: &Path,
) -> io::Result<Vec<DiffEntry>>
where
	V: Volume + ?Sized,
{
	let base_view = SubVolume::new(volume, base)?;
	let target_view = SubVolume::new(volume, target)?;
	diff_volumes(&base_view, &target_view, scope).await
}

/// Compares `base` and `target` [`Volume`] views beneath `scope`.
///
/// Paths are relative to `scope`; `scope` itself is excluded. Results are
/// sorted by path. Scope must be a directory wherever it exists. If present on
/// only one side, all its descendants are added or removed. Absent on both sides
/// returns `ENOENT`; a non-directory on either side returns `ENOTDIR`.
///
/// Walks both trees, compares content in bounded chunks, and sorts results.
/// Uses O(entries) memory; same-size files require byte reads.
pub async fn diff_volumes<B, T>(base: &B, target: &T, scope: &Path) -> io::Result<Vec<DiffEntry>>
where
	B: Volume + ?Sized,
	T: Volume + ?Sized,
{
	let base_attr = stat_optional(base, scope).await?;
	let target_attr = stat_optional(target, scope).await?;
	let base_dir = optional_directory(base_attr.as_ref())?;
	let target_dir = optional_directory(target_attr.as_ref())?;

	match (base_dir, target_dir) {
		(false, false) => return Err(errno(libc::ENOENT)),
		(false, true) => {
			return walk_added(target, scope).await;
		}
		(true, false) => {
			return walk_removed(base, scope).await;
		}
		(true, true) => {}
	}

	let base_entries = base.walk(scope).await?;
	let target_entries = target.walk(scope).await?;
	let mut base_map = entry_map(base_entries);
	let target_map = entry_map(target_entries);
	let mut diff = Vec::new();
	for (path, target_attr) in &target_map {
		match base_map.remove(path) {
			None => diff.push(DiffEntry {
				path: path.clone(),
				kind: DiffKind::Added,
			}),
			Some(base_attr) => {
				if modified(base, target, scope, path, &base_attr, target_attr).await? {
					diff.push(DiffEntry {
						path: path.clone(),
						kind: DiffKind::Modified,
					});
				}
			}
		}
	}
	for path in base_map.into_keys() {
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

async fn walk_added<T: Volume + ?Sized>(target: &T, scope: &Path) -> io::Result<Vec<DiffEntry>> {
	Ok(target
		.walk(scope)
		.await?
		.into_iter()
		.map(|entry| DiffEntry {
			path: entry.path,
			kind: DiffKind::Added,
		})
		.collect())
}

async fn walk_removed<B: Volume + ?Sized>(base: &B, scope: &Path) -> io::Result<Vec<DiffEntry>> {
	Ok(base
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

async fn modified<B: Volume + ?Sized, T: Volume + ?Sized>(
	base: &B,
	target: &T,
	scope: &Path,
	path: &Path,
	base_attr: &Attr,
	target_attr: &Attr,
) -> io::Result<bool> {
	let base_kind = base_attr.mode & S_IFMT;
	let target_kind = target_attr.mode & S_IFMT;
	if base_kind != target_kind {
		return Ok(true);
	}
	let full = scope.join(path);
	match base_kind {
		S_IFDIR => Ok(false),
		S_IFREG => {
			if base_attr.size != target_attr.size {
				return Ok(true);
			}
			let mut offset = 0u64;
			while offset < target_attr.size {
				let len = (target_attr.size - offset).min(DIFF_CHUNK as u64) as usize;
				let base_bytes = read_full(base, &full, offset, len).await?;
				let target_bytes = read_full(target, &full, offset, len).await?;
				if base_bytes != target_bytes {
					return Ok(true);
				}
				if target_bytes.len() < len {
					return Err(unexpected_eof(&full));
				}
				offset += len as u64;
			}
			Ok(false)
		}
		S_IFLNK => Ok(base.readlink(&full).await? != target.readlink(&full).await?),
		_ => Ok(base_attr.rdev != target_attr.rdev),
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
