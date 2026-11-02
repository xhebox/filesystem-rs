//! Literal search with stamped page signatures and range verification.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CStr;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::{Attr, Volume, WalkEntry};

pub const SEARCH_PAGE_SIZE: usize = 4096;
pub const SEARCH_OVERLAP: usize = 64;
pub const SIG_BYTES: usize = 64;
pub const XATTR_SIG_NAME: &CStr = c"user.boxfs.sig";
pub type PageSig = [u8; SIG_BYTES];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexOptions {
	pub enabled: bool,
	pub persist_xattr: bool,
	pub max_file_size: u64,
}

impl Default for IndexOptions {
	fn default() -> Self {
		Self {
			enabled: true,
			persist_xattr: true,
			max_file_size: 16 * 1024 * 1024,
		}
	}
}

impl IndexOptions {
	pub fn disabled() -> Self {
		Self {
			enabled: false,
			..Self::default()
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchQuery {
	pub pattern: String,
	pub case_sensitive: bool,
}

impl SearchQuery {
	pub fn new(pattern: impl Into<String>) -> Self {
		Self {
			pattern: pattern.into(),
			case_sensitive: true,
		}
	}

	pub fn case_insensitive(pattern: impl Into<String>) -> Self {
		Self {
			pattern: pattern.into(),
			case_sensitive: false,
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchMatch {
	pub path: PathBuf,
	pub line: usize,
	/// One-based byte column.
	pub column: usize,
	pub line_text: String,
}

fn gram_buckets(gram: &[u8], folded: bool, out: &mut Vec<usize>) {
	let mut a = 2166136261u32;
	let mut b = 5381u32;
	for &byte in gram {
		let byte = if folded {
			byte.to_ascii_lowercase()
		} else {
			byte
		};
		a = (a ^ u32::from(byte)).wrapping_mul(16777619);
		b = b.wrapping_mul(33) ^ u32::from(byte);
	}
	let (base, width) = if folded { (0, 384) } else { (384, 128) };
	out.push(base + a as usize % width);
	if gram.len() == 3 {
		out.push(base + b as usize % width);
	}
}

pub fn compute_page_sig(window: &[u8]) -> PageSig {
	let mut sig = [0; SIG_BYTES];
	let mut buckets = Vec::new();
	for gram in window.windows(2) {
		gram_buckets(gram, true, &mut buckets);
	}
	for gram in window.windows(3) {
		gram_buckets(gram, true, &mut buckets);
		gram_buckets(gram, false, &mut buckets);
	}
	for b in buckets {
		sig[b / 8] |= 1 << (b % 8);
	}
	sig
}

pub fn compute_file_sigs(data: &[u8]) -> Vec<PageSig> {
	(0..data.len().div_ceil(SEARCH_PAGE_SIZE))
		.map(|p| {
			let start = p * SEARCH_PAGE_SIZE;
			compute_page_sig(
				&data[start..(start + SEARCH_PAGE_SIZE + SEARCH_OVERLAP).min(data.len())],
			)
		})
		.collect()
}

pub fn query_buckets(pattern: &[u8], case_sensitive: bool) -> Vec<usize> {
	// A match's prefix always fits in the owning page and its overlap.
	let prefix = &pattern[..pattern.len().min(SEARCH_OVERLAP)];
	let mut out = Vec::new();
	for gram in prefix.windows(2) {
		gram_buckets(gram, true, &mut out);
	}
	for gram in prefix.windows(3) {
		gram_buckets(gram, true, &mut out);
		if case_sensitive {
			gram_buckets(gram, false, &mut out);
		}
	}
	out.sort_unstable();
	out.dedup();
	out
}

/// Newline counts exclude the overlap and retain all 512 signature bits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileSignatures {
	pub pages: Vec<PageSig>,
	pub newlines: Vec<u16>,
}

impl FileSignatures {
	pub fn compute(data: &[u8]) -> Self {
		Self {
			pages: compute_file_sigs(data),
			newlines: data
				.chunks(SEARCH_PAGE_SIZE)
				.map(|page| page.iter().filter(|&&b| b == b'\n').count() as u16)
				.collect(),
		}
	}
}

pub fn encode_sig_xattr(attr: &Attr, sigs: &FileSignatures) -> Vec<u8> {
	let mut out = Vec::with_capacity(40 + sigs.pages.len() * (SIG_BYTES + 2));
	out.extend_from_slice(b"BXS1");
	out.extend_from_slice(&attr.ino.to_le_bytes());
	out.extend_from_slice(&(sigs.pages.len() as u64).to_le_bytes());
	out.extend_from_slice(&attr.mtimensec.to_le_bytes());
	out.extend_from_slice(&attr.mtime.to_le_bytes());
	out.extend_from_slice(&attr.size.to_le_bytes());
	for sig in &sigs.pages {
		out.extend_from_slice(sig);
	}
	for count in &sigs.newlines {
		out.extend_from_slice(&count.to_le_bytes());
	}
	out
}

pub fn decode_sig_xattr(attr: &Attr, raw: &[u8]) -> Option<FileSignatures> {
	if raw.len() < 40 {
		return None;
	}
	let n = usize::try_from(u64::from_le_bytes(raw[12..20].try_into().ok()?)).ok()?;
	if n != 0 && n as u64 != attr.size.div_ceil(SEARCH_PAGE_SIZE as u64) {
		return None;
	}
	let expected = n.checked_mul(SIG_BYTES + 2)?.checked_add(40)?;
	if raw.len() != expected
		|| &raw[..4] != b"BXS1"
		|| raw[4..12] != attr.ino.to_le_bytes()
		|| raw[20..24] != attr.mtimensec.to_le_bytes()
		|| raw[24..32] != attr.mtime.to_le_bytes()
		|| raw[32..40] != attr.size.to_le_bytes()
	{
		return None;
	}
	let pages = raw[40..40 + n * SIG_BYTES]
		.as_chunks::<SIG_BYTES>()
		.0
		.to_vec();
	let newlines: Vec<u16> = raw[40 + n * SIG_BYTES..]
		.as_chunks::<2>()
		.0
		.iter()
		.map(|s| u16::from_le_bytes(*s))
		.collect();
	for (p, &count) in newlines.iter().enumerate() {
		if u64::from(count)
			> (attr.size - p as u64 * SEARCH_PAGE_SIZE as u64).min(SEARCH_PAGE_SIZE as u64)
		{
			return None;
		}
	}
	Some(FileSignatures { pages, newlines })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileStamp {
	pub ino: u64,
	pub mtime: u64,
	pub mtimensec: u32,
	pub size: u64,
}
impl From<&Attr> for FileStamp {
	fn from(a: &Attr) -> Self {
		Self {
			ino: a.ino,
			mtime: a.mtime,
			mtimensec: a.mtimensec,
			size: a.size,
		}
	}
}
struct ChunkGroup {
	rows: [u64; 512],
	valid: u64,
}
struct CachedFile {
	stamp: FileStamp,
	sigs: FileSignatures,
	groups: Vec<ChunkGroup>,
}

/// A derived view maintained by volume mutations and startup reconciliation.
pub trait VolumeHook: Send + Sync {
	fn name(&self) -> &'static str;
	fn file_xattr(&self) -> Option<&'static CStr> {
		None
	}
	fn root_xattr(&self) -> Option<&'static CStr> {
		None
	}
	/// Whether a matching stamped entry is already loaded, including empty results.
	fn contains(&self, _path: &Path, _attr: &Attr) -> bool {
		false
	}
	fn on_file_write(&self, path: &Path, attr: &Attr, data: &[u8]) -> Option<Vec<u8>>;
	fn on_file_load(&self, path: &Path, attr: &Attr, raw: &[u8]) -> bool;
	fn on_dir(&self, _path: &Path, _attr: &Attr) {}
	fn on_remove(&self, path: &Path);
	fn on_rename(&self, from: &Path, to: &Path);
	fn on_reset(&self);
	fn export_root(&self, _root: &Path) -> Option<Vec<u8>> {
		None
	}
	fn import_root(&self, _root: &Path, _raw: &[u8]) -> bool {
		false
	}
}

#[derive(Default)]
pub struct PathIndex {
	entries: Mutex<BTreeMap<PathBuf, Attr>>,
}

impl PathIndex {
	pub fn paths_under(&self, root: &Path) -> Vec<WalkEntry> {
		self.entries
			.lock()
			.unwrap()
			.iter()
			.filter_map(|(path, attr)| {
				let relative = path.strip_prefix(root).ok()?;
				(!relative.as_os_str().is_empty()).then(|| WalkEntry {
					path: relative.to_owned(),
					attr: *attr,
				})
			})
			.collect()
	}
}

fn rename_entries<T>(entries: &mut BTreeMap<PathBuf, T>, from: &Path, to: &Path) {
	if from == to {
		return;
	}
	let paths: Vec<_> = entries
		.keys()
		.filter(|p| p.starts_with(from))
		.cloned()
		.collect();
	let moved: Vec<_> = paths
		.into_iter()
		.map(|p| {
			let target = to.join(p.strip_prefix(from).unwrap());
			(target, entries.remove(&p).unwrap())
		})
		.collect();
	entries.retain(|p, _| !p.starts_with(to));
	entries.extend(moved);
}

// Snapshots use length-prefixed relative paths and payloads; reject partial imports.
fn snapshot(magic: &[u8; 4], records: impl Iterator<Item = (PathBuf, Attr, Vec<u8>)>) -> Vec<u8> {
	let mut out = magic.to_vec();
	for (path, attr, payload) in records {
		let path = path.as_os_str().as_encoded_bytes();
		out.extend_from_slice(&(path.len() as u64).to_le_bytes());
		out.extend_from_slice(path);
		for n in [
			attr.ino,
			attr.size,
			attr.blocks,
			attr.atime,
			attr.mtime,
			attr.ctime,
		] {
			out.extend_from_slice(&n.to_le_bytes());
		}
		for n in [
			attr.atimensec,
			attr.mtimensec,
			attr.ctimensec,
			attr.mode,
			attr.nlink,
			attr.uid,
			attr.gid,
			attr.rdev,
			attr.blksize,
			attr.flags,
		] {
			out.extend_from_slice(&n.to_le_bytes());
		}
		out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
		out.extend_from_slice(&payload);
	}
	out
}
fn take<'a>(raw: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
	let (head, tail) = raw.split_at_checked(n)?;
	*raw = tail;
	Some(head)
}
fn u64_from(raw: &mut &[u8]) -> Option<u64> {
	Some(u64::from_le_bytes(take(raw, 8)?.try_into().ok()?))
}
fn u32_from(raw: &mut &[u8]) -> Option<u32> {
	Some(u32::from_le_bytes(take(raw, 4)?.try_into().ok()?))
}
fn restore(magic: &[u8; 4], mut raw: &[u8]) -> Option<Vec<(PathBuf, Attr, Vec<u8>)>> {
	if take(&mut raw, 4)? != magic {
		return None;
	}
	let mut entries = Vec::new();
	let mut paths = BTreeSet::new();
	while !raw.is_empty() {
		let len = usize::try_from(u64_from(&mut raw)?).ok()?;
		let path = crate::name_to_path(take(&mut raw, len)?).ok()?;
		if path.as_os_str().is_empty()
			|| path
				.components()
				.any(|c| !matches!(c, std::path::Component::Normal(_)))
			|| !paths.insert(path.clone())
		{
			return None;
		}
		let attr = Attr {
			ino: u64_from(&mut raw)?,
			size: u64_from(&mut raw)?,
			blocks: u64_from(&mut raw)?,
			atime: u64_from(&mut raw)?,
			mtime: u64_from(&mut raw)?,
			ctime: u64_from(&mut raw)?,
			atimensec: u32_from(&mut raw)?,
			mtimensec: u32_from(&mut raw)?,
			ctimensec: u32_from(&mut raw)?,
			mode: u32_from(&mut raw)?,
			nlink: u32_from(&mut raw)?,
			uid: u32_from(&mut raw)?,
			gid: u32_from(&mut raw)?,
			rdev: u32_from(&mut raw)?,
			blksize: u32_from(&mut raw)?,
			flags: u32_from(&mut raw)?,
		};
		let len = usize::try_from(u64_from(&mut raw)?).ok()?;
		entries.push((path, attr, take(&mut raw, len)?.to_vec()));
	}
	Some(entries)
}

impl VolumeHook for PathIndex {
	fn name(&self) -> &'static str {
		"paths"
	}
	fn root_xattr(&self) -> Option<&'static CStr> {
		Some(c"user.boxfs.idx.paths")
	}
	fn contains(&self, path: &Path, attr: &Attr) -> bool {
		self.entries
			.lock()
			.unwrap()
			.get(path)
			.is_some_and(|a| FileStamp::from(a) == attr.into() && a.mode == attr.mode)
	}
	fn on_file_write(&self, path: &Path, attr: &Attr, _data: &[u8]) -> Option<Vec<u8>> {
		self.on_dir(path, attr);
		None
	}
	fn on_file_load(&self, path: &Path, attr: &Attr, _raw: &[u8]) -> bool {
		self.on_dir(path, attr);
		true
	}
	fn on_dir(&self, path: &Path, attr: &Attr) {
		self.entries.lock().unwrap().insert(path.to_owned(), *attr);
	}
	fn on_remove(&self, path: &Path) {
		self.entries
			.lock()
			.unwrap()
			.retain(|p, _| !p.starts_with(path));
	}
	fn on_rename(&self, from: &Path, to: &Path) {
		rename_entries(&mut self.entries.lock().unwrap(), from, to);
	}
	fn on_reset(&self) {
		self.entries.lock().unwrap().clear();
	}
	fn export_root(&self, root: &Path) -> Option<Vec<u8>> {
		Some(snapshot(
			b"BXP1",
			self.paths_under(root)
				.into_iter()
				.map(|e| (e.path, e.attr, Vec::new())),
		))
	}
	fn import_root(&self, root: &Path, raw: &[u8]) -> bool {
		let Some(entries) = restore(b"BXP1", raw) else {
			return false;
		};
		let mut map = self.entries.lock().unwrap();
		map.retain(|p, _| !p.starts_with(root));
		map.extend(entries.into_iter().map(|(p, a, _)| (root.join(p), a)));
		true
	}
}

#[derive(Default)]
pub struct ContentIndex {
	cache: Mutex<BTreeMap<PathBuf, Arc<CachedFile>>>,
}
impl ContentIndex {
	fn cache_file(&self, path: &Path, attr: &Attr, sigs: FileSignatures) -> Arc<CachedFile> {
		let groups = sigs
			.pages
			.chunks(64)
			.map(|pages| {
				let mut group = ChunkGroup {
					rows: [0; 512],
					valid: u64::MAX >> (64 - pages.len()),
				};
				for (p, sig) in pages.iter().enumerate() {
					for b in 0..512 {
						if sig[b / 8] & (1 << (b % 8)) != 0 {
							group.rows[b] |= 1 << p;
						}
					}
				}
				group
			})
			.collect();
		let cached = Arc::new(CachedFile {
			stamp: attr.into(),
			sigs,
			groups,
		});
		self.cache
			.lock()
			.unwrap_or_else(|e| e.into_inner())
			.insert(path.to_path_buf(), Arc::clone(&cached));
		cached
	}
	fn get(&self, path: &Path, attr: &Attr) -> Option<Arc<CachedFile>> {
		self.cache
			.lock()
			.unwrap_or_else(|e| e.into_inner())
			.get(path)
			.filter(|e| e.stamp == attr.into())
			.cloned()
	}
}

impl VolumeHook for ContentIndex {
	fn name(&self) -> &'static str {
		"content"
	}
	fn file_xattr(&self) -> Option<&'static CStr> {
		Some(XATTR_SIG_NAME)
	}
	fn root_xattr(&self) -> Option<&'static CStr> {
		Some(c"user.boxfs.idx.content")
	}
	fn contains(&self, path: &Path, attr: &Attr) -> bool {
		self.get(path, attr).is_some()
	}
	fn on_file_write(&self, path: &Path, attr: &Attr, data: &[u8]) -> Option<Vec<u8>> {
		let sigs = if data.contains(&0) {
			FileSignatures {
				pages: Vec::new(),
				newlines: Vec::new(),
			}
		} else {
			FileSignatures::compute(data)
		};
		let raw = encode_sig_xattr(attr, &sigs);
		self.cache_file(path, attr, sigs);
		Some(raw)
	}
	fn on_file_load(&self, path: &Path, attr: &Attr, raw: &[u8]) -> bool {
		let Some(sigs) = decode_sig_xattr(attr, raw) else {
			return false;
		};
		self.cache_file(path, attr, sigs);
		true
	}
	fn on_remove(&self, path: &Path) {
		self.cache
			.lock()
			.unwrap()
			.retain(|p, _| !p.starts_with(path));
	}
	fn on_rename(&self, from: &Path, to: &Path) {
		rename_entries(&mut self.cache.lock().unwrap(), from, to);
	}
	fn on_reset(&self) {
		self.cache.lock().unwrap().clear();
	}
	fn export_root(&self, root: &Path) -> Option<Vec<u8>> {
		Some(snapshot(
			b"BXC1",
			self.cache.lock().unwrap().iter().filter_map(|(p, f)| {
				let relative = p.strip_prefix(root).ok()?;
				let attr = Attr {
					ino: f.stamp.ino,
					mtime: f.stamp.mtime,
					mtimensec: f.stamp.mtimensec,
					size: f.stamp.size,
					..Attr::default()
				};
				Some((relative.to_owned(), attr, encode_sig_xattr(&attr, &f.sigs)))
			}),
		))
	}
	fn import_root(&self, root: &Path, raw: &[u8]) -> bool {
		let Some(entries) = restore(b"BXC1", raw) else {
			return false;
		};
		let Some(entries) = entries
			.into_iter()
			.map(|(p, a, raw)| Some((p, a, decode_sig_xattr(&a, &raw)?)))
			.collect::<Option<Vec<_>>>()
		else {
			return false;
		};
		self.on_remove(root);
		for (p, a, sigs) in entries {
			self.cache_file(&root.join(p), &a, sigs);
		}
		true
	}
}

pub struct SearchIndex {
	options: IndexOptions,
	paths: Arc<PathIndex>,
	content: Arc<ContentIndex>,
	custom_hooks: Mutex<Vec<Arc<dyn VolumeHook>>>,
	reconciled_roots: Mutex<BTreeSet<PathBuf>>,
	reconciliation: asyncband::mutex::Mutex<()>,
}
impl SearchIndex {
	pub fn new(options: IndexOptions) -> Self {
		Self {
			options,
			paths: Arc::default(),
			content: Arc::default(),
			custom_hooks: Mutex::default(),
			reconciled_roots: Mutex::default(),
			reconciliation: asyncband::mutex::Mutex::new(()),
		}
	}
	pub fn options(&self) -> &IndexOptions {
		&self.options
	}
	pub fn register_hook(&self, hook: Arc<dyn VolumeHook>) {
		self.custom_hooks.lock().unwrap().push(hook);
		self.reconciled_roots.lock().unwrap().clear();
	}
	fn hooks(&self) -> Vec<Arc<dyn VolumeHook>> {
		let mut hooks: Vec<Arc<dyn VolumeHook>> = vec![self.paths.clone(), self.content.clone()];
		hooks.extend(self.custom_hooks.lock().unwrap().iter().cloned());
		hooks
	}
	pub fn notify_write(
		&self,
		path: &Path,
		attr: &Attr,
		data: &[u8],
	) -> Vec<(&'static CStr, Vec<u8>)> {
		self.hooks()
			.into_iter()
			.filter_map(|h| {
				let raw = h.on_file_write(path, attr, data)?;
				if self.options.persist_xattr {
					Some((h.file_xattr()?, raw))
				} else {
					None
				}
			})
			.collect()
	}
	pub fn notify_mkdir(&self, path: &Path, attr: &Attr) {
		for h in self.hooks() {
			h.on_dir(path, attr);
		}
	}
	pub fn notify_remove(&self, path: &Path) {
		for h in self.hooks() {
			h.on_remove(path);
		}
	}
	pub fn notify_rename(&self, from: &Path, to: &Path) {
		for h in self.hooks() {
			h.on_rename(from, to);
		}
	}
	pub fn notify_reset(&self) {
		self.reconciled_roots.lock().unwrap().clear();
		for h in self.hooks() {
			h.on_reset();
		}
	}
	pub fn clear(&self) {
		self.notify_reset();
	}
	pub fn invalidate(&self, path: &Path) {
		self.reconciled_roots
			.lock()
			.unwrap()
			.retain(|r| !path.starts_with(r) && !r.starts_with(path));
		self.notify_remove(path);
	}
	pub fn insert(&self, path: &Path, attr: &Attr, sigs: FileSignatures) {
		self.paths.on_dir(path, attr);
		self.content.cache_file(path, attr, sigs);
	}
	/// Persist current reconciled roots after a successful mutation, without walking.
	pub async fn persist_roots<V: Volume + ?Sized>(&self, v: &V) {
		if !self.options.persist_xattr {
			return;
		}
		let roots: Vec<_> = self
			.reconciled_roots
			.lock()
			.unwrap()
			.iter()
			.cloned()
			.collect();
		for root in roots {
			self.persist_root(v, &root).await;
		}
	}
	async fn persist_root<V: Volume + ?Sized>(&self, v: &V, root: &Path) {
		for hook in self.hooks() {
			if let Some(name) = hook.root_xattr()
				&& let Some(raw) = hook.export_root(root)
			{
				let _result = v.setxattr(root, name, &raw, 0).await;
			}
		}
	}
	pub async fn ensure_reconciled<V: Volume + ?Sized>(
		&self,
		v: &V,
		root: &Path,
	) -> io::Result<()> {
		if self.reconciled_roots.lock().unwrap().contains(root) {
			return Ok(());
		}
		let _guard = self.reconciliation.lock().await;
		if self.reconciled_roots.lock().unwrap().contains(root) {
			return Ok(());
		}
		let hooks = self.hooks();
		let mut changed = false;
		for h in &hooks {
			if self.options.persist_xattr
				&& let Some(name) = h.root_xattr()
			{
				if let Ok(raw) = v.getxattr(root, name).await {
					changed |= !h.import_root(root, &raw);
				} else {
					changed = true;
				}
			}
		}
		let entries = v.walk(root).await?;
		let present: BTreeSet<_> = entries.iter().map(|e| e.path.clone()).collect();
		for previous in self.paths.paths_under(root) {
			if !present.contains(&previous.path) {
				self.notify_remove(&root.join(previous.path));
				changed = true;
			}
		}
		for entry in entries {
			let path = root.join(entry.path);
			let attr = entry.attr;
			let same = self.paths.contains(&path, &attr);
			let type_changed = self
				.paths
				.entries
				.lock()
				.unwrap()
				.get(&path)
				.is_some_and(|old| old.mode & 0o170000 != attr.mode & 0o170000);
			if type_changed {
				self.notify_remove(&path);
			}
			if attr.mode & 0o170000 != 0o100000 {
				changed |= !same;
				for h in &hooks {
					h.on_dir(&path, &attr);
				}
				continue;
			}
			if same && hooks.iter().all(|h| h.contains(&path, &attr)) {
				continue;
			}
			changed = true;
			self.paths.on_dir(&path, &attr);
			let mut missing = Vec::new();
			for h in &hooks {
				if h.contains(&path, &attr) {
					continue;
				}
				if self.options.persist_xattr
					&& let Some(name) = h.file_xattr()
					&& let Ok(raw) = v.getxattr(&path, name).await
					&& h.on_file_load(&path, &attr, &raw)
				{
					continue;
				}
				missing.push(h);
			}
			if !missing.is_empty() {
				let data = v.read(&path).await?;
				for h in missing {
					if let Some(raw) = h.on_file_write(&path, &attr, &data)
						&& self.options.persist_xattr
						&& let Some(name) = h.file_xattr()
					{
						let _result = v.setxattr(&path, name, &raw, 0).await;
					}
				}
			}
			self.paths.on_dir(&path, &attr);
		}
		if changed && self.options.persist_xattr {
			self.persist_root(v, root).await;
		}
		self.reconciled_roots
			.lock()
			.unwrap()
			.insert(root.to_owned());
		Ok(())
	}
}

#[allow(async_fn_in_trait)]
pub trait Search: Volume {
	fn search_index(&self) -> Option<&SearchIndex> {
		None
	}
	/// Returns signatures from native page storage, when available.
	async fn native_page_signatures(
		&self,
		_path: &Path,
		_attr: &Attr,
	) -> io::Result<Option<Vec<PageSig>>> {
		Ok(None)
	}
	/// Native signatures with exact newline counts for range verification.
	async fn native_file_signatures(
		&self,
		path: &Path,
		attr: &Attr,
	) -> io::Result<Option<FileSignatures>> {
		let Some(pages) = self.native_page_signatures(path, attr).await? else {
			return Ok(None);
		};
		let bytes = self.read(path).await?;
		if bytes.contains(&0) {
			return Ok(Some(FileSignatures {
				pages: Vec::new(),
				newlines: Vec::new(),
			}));
		}
		Ok(Some(FileSignatures {
			pages,
			newlines: FileSignatures::compute(&bytes).newlines,
		}))
	}
	async fn indexed_walk(&self, root: &Path) -> io::Result<Vec<WalkEntry>> {
		if let Some(idx) = self.search_index() {
			idx.ensure_reconciled(self, root).await?;
			Ok(idx.paths.paths_under(root))
		} else {
			self.walk(root).await
		}
	}
	async fn search(&self, root: &Path, query: &SearchQuery) -> io::Result<Vec<SearchMatch>> {
		search_volume(self, root, query).await
	}
}

async fn read_range<V: Volume + ?Sized>(
	v: &V,
	path: &Path,
	start: usize,
	end: usize,
) -> io::Result<Vec<u8>> {
	let mut bytes = Vec::new();
	while bytes.len() < end - start {
		let part = v
			.read_range(
				path,
				(start + bytes.len()) as u64,
				end - start - bytes.len(),
			)
			.await?;
		if part.is_empty() {
			break;
		}
		bytes.extend_from_slice(&part);
	}
	Ok(bytes)
}

pub async fn search_volume<V: Search + ?Sized>(
	v: &V,
	root: &Path,
	query: &SearchQuery,
) -> io::Result<Vec<SearchMatch>> {
	if query.pattern.is_empty() {
		return Ok(Vec::new());
	}
	let options = v
		.search_index()
		.map(|i| *i.options())
		.unwrap_or_else(IndexOptions::disabled);
	let buckets = query_buckets(query.pattern.as_bytes(), query.case_sensitive);
	let mut matches = Vec::new();
	for entry in v.indexed_walk(root).await? {
		let attr = entry.attr;
		if attr.mode & 0o170000 != 0o100000 || attr.size == 0 || attr.size > options.max_file_size {
			continue;
		}
		let path = root.join(entry.path);
		let size =
			usize::try_from(attr.size).map_err(|_| io::Error::from_raw_os_error(libc::EFBIG))?;
		let mut candidates = Vec::new();
		let mut counts = Vec::new();
		if let Some(idx) = v.search_index().filter(|_| options.enabled) {
			let Some(cached) = idx.content.get(&path, &attr) else {
				continue;
			};
			counts.clone_from(&cached.sigs.newlines);
			for (g, group) in cached.groups.iter().enumerate() {
				let mut mask = group.valid;
				for &b in &buckets {
					mask &= group.rows[b];
					if mask == 0 {
						break;
					}
				}
				while mask != 0 {
					let bit = mask.trailing_zeros() as usize;
					candidates.push(g * 64 + bit);
					mask &= mask - 1;
				}
			}
		} else {
			let data = v.read(&path).await?;
			if !data.contains(&0) {
				scan(&path, &data, 1, query, &mut matches, &mut BTreeSet::new());
			}
			continue;
		}
		let mut seen = BTreeSet::new();
		let mut i = 0;
		while i < candidates.len() {
			let first = candidates[i];
			let mut last = first;
			while i + 1 < candidates.len() && candidates[i + 1] == last + 1 {
				i += 1;
				last += 1;
			}
			i += 1;
			let mut start = first * SEARCH_PAGE_SIZE;
			let line = 1 + counts[..first].iter().map(|&n| n as usize).sum::<usize>();
			let mut end = ((last + 1) * SEARCH_PAGE_SIZE)
				.saturating_add(query.pattern.len().max(SEARCH_OVERLAP))
				.min(size);
			let mut bytes = read_range(v, &path, start, end).await?;
			// Include the complete leading line, including a newline at start - 1.
			while start > 0 {
				let prev_start = start.saturating_sub(SEARCH_PAGE_SIZE);
				let prev = read_range(v, &path, prev_start, start).await?;
				if let Some(n) = prev.iter().rposition(|&b| b == b'\n') {
					bytes.splice(..0, prev[n + 1..].iter().copied());
					break;
				}
				bytes.splice(..0, prev);
				start = prev_start;
			}
			// The leading fragments contain no newlines; the page's line is unchanged.
			while end < size && bytes.last() != Some(&b'\n') {
				let next_end = (end + SEARCH_PAGE_SIZE).min(size);
				let next = read_range(v, &path, end, next_end).await?;
				if next.is_empty() {
					break;
				}
				end += next.len();
				if let Some(n) = next.iter().position(|&b| b == b'\n') {
					bytes.extend_from_slice(&next[..=n]);
					break;
				}
				bytes.extend_from_slice(&next);
			}
			if !bytes.contains(&0) {
				scan(&path, &bytes, line, query, &mut matches, &mut seen);
			}
		}
	}
	matches.sort_by(|a, b| (&a.path, a.line, a.column).cmp(&(&b.path, b.line, b.column)));
	Ok(matches)
}

fn scan(
	path: &Path,
	bytes: &[u8],
	first_line: usize,
	query: &SearchQuery,
	out: &mut Vec<SearchMatch>,
	seen: &mut BTreeSet<(usize, usize)>,
) {
	let needle = query.pattern.as_bytes();
	for pos in 0..bytes.len().saturating_sub(needle.len()).saturating_add(1) {
		let Some(window) = bytes.get(pos..pos + needle.len()) else {
			continue;
		};
		if if query.case_sensitive {
			window == needle
		} else {
			window.eq_ignore_ascii_case(needle)
		} {
			let line = first_line + bytes[..pos].iter().filter(|&&b| b == b'\n').count();
			let start = bytes[..pos]
				.iter()
				.rposition(|&b| b == b'\n')
				.map_or(0, |n| n + 1);
			let end = bytes[pos..]
				.iter()
				.position(|&b| b == b'\n')
				.map_or(bytes.len(), |n| pos + n);
			let column = pos - start + 1;
			if seen.insert((line, column)) {
				out.push(SearchMatch {
					path: path.to_path_buf(),
					line,
					column,
					line_text: String::from_utf8_lossy(&bytes[start..end]).into_owned(),
				});
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::{
		FileSignatures, SEARCH_PAGE_SIZE, compute_file_sigs, decode_sig_xattr, encode_sig_xattr,
		query_buckets,
	};
	use crate::Attr;

	#[test]
	fn signature_prefix_has_no_false_negatives() {
		let mut data = Vec::new();
		for i in 0..SEARCH_PAGE_SIZE * 3 {
			data.push(b'A' + (i * 17 % 26) as u8);
		}
		let sigs = compute_file_sigs(&data);
		for start in [0, 4000, 4095, 4096, 8180] {
			for len in [2, 3, 64, 200] {
				for sensitive in [true, false] {
					let pattern = data[start..start + len].to_vec();
					for b in query_buckets(&pattern, sensitive) {
						assert_ne!(sigs[start / SEARCH_PAGE_SIZE][b / 8] & (1 << (b % 8)), 0);
					}
				}
			}
		}
	}

	#[test]
	fn signature_xattr_validates_stamp_and_payload() {
		let data = b"line\n".repeat(1000);
		let attr = Attr {
			size: data.len() as u64,
			mtime: 1234,
			mtimensec: 5678,
			..Attr::default()
		};
		let sigs = FileSignatures::compute(&data);
		let raw = encode_sig_xattr(&attr, &sigs);
		assert_eq!(decode_sig_xattr(&attr, &raw), Some(sigs));
		for end in 0..raw.len() {
			assert!(decode_sig_xattr(&attr, &raw[..end]).is_none());
		}
		let changed = Attr {
			mtime: 1235,
			..attr
		};
		assert!(decode_sig_xattr(&changed, &raw).is_none());
		let changed = Attr {
			mtimensec: 1,
			..attr
		};
		assert!(decode_sig_xattr(&changed, &raw).is_none());
		let changed = Attr {
			size: attr.size + 1,
			..attr
		};
		assert!(decode_sig_xattr(&changed, &raw).is_none());
	}
}
