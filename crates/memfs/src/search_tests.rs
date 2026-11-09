use std::cell::RefCell;
use std::ffi::CStr;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::tests::block_on;
use api::{
	Attr, ContentIndex, IndexOptions, Search, SearchIndex, SearchQuery, Snapshot, Volume,
	VolumeHook, WalkEntry,
};

use crate::MemFs;

struct Counted<'a> {
	fs: &'a MemFs,
	index: SearchIndex,
	walks: AtomicUsize,
	reads: RefCell<Vec<PathBuf>>,
	xattrs: RefCell<Vec<PathBuf>>,
	ranges: RefCell<Vec<PathBuf>>,
}
impl<'a> Counted<'a> {
	fn new(fs: &'a MemFs) -> Self {
		Self {
			fs,
			index: SearchIndex::new(IndexOptions::default()),
			walks: AtomicUsize::new(0),
			reads: RefCell::default(),
			xattrs: RefCell::default(),
			ranges: RefCell::default(),
		}
	}
}
impl Volume for Counted<'_> {
	async fn walk(&self, root: &Path) -> io::Result<Vec<WalkEntry>> {
		self.walks.fetch_add(1, Ordering::Relaxed);
		let mut yielded = false;
		std::future::poll_fn(|cx| {
			if yielded {
				std::task::Poll::Ready(())
			} else {
				yielded = true;
				cx.waker().wake_by_ref();
				std::task::Poll::Pending
			}
		})
		.await;
		self.fs.walk(root).await
	}
	async fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
		self.reads.borrow_mut().push(path.to_owned());
		Volume::read(self.fs, path).await
	}
	async fn read_range(&self, path: &Path, offset: u64, len: usize) -> io::Result<Vec<u8>> {
		self.ranges.borrow_mut().push(path.to_owned());
		self.fs.read_range(path, offset, len).await
	}
	async fn getxattr(&self, path: &Path, name: &CStr) -> io::Result<Vec<u8>> {
		self.xattrs.borrow_mut().push(path.to_owned());
		Volume::getxattr(self.fs, path, name).await
	}
	async fn setxattr(&self, path: &Path, name: &CStr, raw: &[u8], flags: u32) -> io::Result<()> {
		Volume::setxattr(self.fs, path, name, raw, flags).await
	}
}
impl Search for Counted<'_> {
	fn search_index(&self) -> Option<&SearchIndex> {
		Some(&self.index)
	}
}

#[derive(Default)]
struct MockHook {
	content: ContentIndex,
	writes: AtomicUsize,
	loads: AtomicUsize,
	removes: AtomicUsize,
	renames: AtomicUsize,
}
impl VolumeHook for MockHook {
	fn name(&self) -> &'static str {
		"mock"
	}
	fn file_xattr(&self) -> Option<&'static CStr> {
		Some(c"user.mock")
	}
	fn root_xattr(&self) -> Option<&'static CStr> {
		Some(c"user.mock.root")
	}
	fn contains(&self, p: &Path, a: &Attr) -> bool {
		self.content.contains(p, a)
	}
	fn on_file_write(&self, p: &Path, a: &Attr, data: &[u8]) -> Option<Vec<u8>> {
		self.writes.fetch_add(1, Ordering::Relaxed);
		self.content.on_file_write(p, a, data)
	}
	fn on_file_load(&self, p: &Path, a: &Attr, raw: &[u8]) -> bool {
		self.loads.fetch_add(1, Ordering::Relaxed);
		self.content.on_file_load(p, a, raw)
	}
	fn on_remove(&self, p: &Path) {
		self.removes.fetch_add(1, Ordering::Relaxed);
		self.content.on_remove(p);
	}
	fn on_rename(&self, from: &Path, to: &Path) {
		self.renames.fetch_add(1, Ordering::Relaxed);
		self.content.on_rename(from, to);
	}
	fn on_reset(&self) {
		self.content.on_reset();
	}
	fn export_root(&self, p: &Path) -> Option<Vec<u8>> {
		self.content.export_root(p)
	}
	fn import_root(&self, p: &Path, raw: &[u8]) -> bool {
		self.content.import_root(p, raw)
	}
}

#[test]
fn search_reconciles_once_and_restores_unchanged_files_without_reads() {
	block_on(async {
		let fs = MemFs::new(false);
		let root = Path::new("/");
		Volume::write(&fs, Path::new("/matching"), b"Needle\n")
			.await
			.unwrap();
		Volume::write(&fs, Path::new("/other"), b"unrelated\n")
			.await
			.unwrap();
		let first = Counted::new(&fs);
		first.index.register_hook(Arc::new(MockHook::default()));
		assert_eq!(
			first
				.search(root, &SearchQuery::new("Needle"))
				.await
				.unwrap()
				.len(),
			1
		);
		let xattrs = first.xattrs.borrow().len();
		let reads = first.reads.borrow().len();
		assert_eq!(first.indexed_walk(root).await.unwrap().len(), 2);
		assert_eq!(
			first
				.search(root, &SearchQuery::new("Needle"))
				.await
				.unwrap()
				.len(),
			1
		);
		assert_eq!(first.walks.load(Ordering::Relaxed), 1);
		assert_eq!(first.xattrs.borrow().len(), xattrs);
		assert_eq!(first.reads.borrow().len(), reads);
		assert!(
			first
				.ranges
				.borrow()
				.iter()
				.all(|p| p == Path::new("/matching"))
		);
		let restart = Counted::new(&fs);
		restart.index.register_hook(Arc::new(MockHook::default()));
		restart.indexed_walk(root).await.unwrap();
		assert!(restart.reads.borrow().is_empty());
		assert!(restart.xattrs.borrow().iter().all(|p| p == root));
		Volume::write(&fs, Path::new("/other"), b"different\n")
			.await
			.unwrap();
		let changed = Counted::new(&fs);
		changed.indexed_walk(root).await.unwrap();
		assert_eq!(*changed.reads.borrow(), [PathBuf::from("/other")]);
	});
}

#[test]
fn custom_hook_persists_loads_and_receives_live_mutations() {
	block_on(async {
		let hook = Arc::new(MockHook::default());
		let fs = MemFs::new(false)
			.with_index(IndexOptions::default())
			.with_hook(hook.clone());
		let root = Path::new("/");
		Volume::create_dir_all(&fs, Path::new("/src/sub"))
			.await
			.unwrap();
		Volume::write(&fs, Path::new("/src/sub/file"), b"Needle\n")
			.await
			.unwrap();
		assert_eq!(hook.writes.load(Ordering::Relaxed), 1);
		assert!(
			!Volume::getxattr(&fs, Path::new("/src/sub/file"), c"user.mock")
				.await
				.unwrap()
				.is_empty()
		);
		fs.search_index().unwrap().notify_reset();
		fs.indexed_walk(root).await.unwrap();
		assert_eq!(hook.loads.load(Ordering::Relaxed), 1);
		let snapshot = fs.snapshot().await.unwrap();
		Volume::rename(&fs, Path::new("/src"), Path::new("/moved"))
			.await
			.unwrap();
		assert_eq!(hook.renames.load(Ordering::Relaxed), 1);
		assert_eq!(hook.writes.load(Ordering::Relaxed), 1);
		assert_eq!(
			fs.search(root, &SearchQuery::new("Needle")).await.unwrap()[0].path,
			Path::new("/moved/sub/file")
		);
		Volume::remove_all(&fs, Path::new("/moved")).await.unwrap();
		assert!(fs.indexed_walk(root).await.unwrap().is_empty());
		assert_eq!(hook.removes.load(Ordering::Relaxed), 1);
		fs.restore(&snapshot).await.unwrap();
		assert_eq!(
			fs.search(root, &SearchQuery::new("Needle"))
				.await
				.unwrap()
				.len(),
			1
		);
		Volume::remove_file(&fs, Path::new("/src/sub/file"))
			.await
			.unwrap();
		assert!(
			fs.search(root, &SearchQuery::new("Needle"))
				.await
				.unwrap()
				.is_empty()
		);
		Volume::write(&fs, Path::new("/src/sub/new"), b"Needle again\n")
			.await
			.unwrap();
		assert_eq!(
			fs.search(root, &SearchQuery::new("Needle"))
				.await
				.unwrap()
				.len(),
			1
		);
	});
}

#[test]
fn concurrent_first_access_reconciles_only_once() {
	use std::future::Future;
	use std::task::Poll;
	let fs = MemFs::new(false);
	let counted = Counted::new(&fs);
	block_on(async {
		let mut left = std::pin::pin!(counted.indexed_walk(Path::new("/")));
		let mut right = std::pin::pin!(counted.indexed_walk(Path::new("/")));
		let mut left_done = false;
		let mut right_done = false;
		std::future::poll_fn(|cx| {
			if !left_done && let Poll::Ready(result) = left.as_mut().poll(cx) {
				result.unwrap();
				left_done = true;
			}
			if !right_done && let Poll::Ready(result) = right.as_mut().poll(cx) {
				result.unwrap();
				right_done = true;
			}
			if left_done && right_done {
				Poll::Ready(())
			} else {
				Poll::Pending
			}
		})
		.await;
	});
	assert_eq!(counted.walks.load(Ordering::Relaxed), 1);
}
