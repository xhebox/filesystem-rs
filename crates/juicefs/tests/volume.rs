//! Ignored live-volume test. Set `BOXFS_JUICEFS_META` to a formatted metadata
//! URL and run with `--ignored`; `BOXFS_JUICEFS_CACHE` overrides the cache.
//!
//! ```text
//! juicefs format --storage file --bucket "$PWD/target/test-tmp/objects" \
//!   sqlite3://$PWD/target/test-tmp/meta.db testvol
//! BOXFS_JUICEFS_META=sqlite3://$PWD/target/test-tmp/meta.db \
//!   cargo test -p boxfs-juicefs --test volume -- --ignored
//! ```

use std::fmt::Debug;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::task::{Context, Poll, Waker};

use api::{DiffKind, Snapshot, Volume};

/// Polls a future while the volume's worker threads perform I/O.
fn block_on<F: Future>(future: F) -> F::Output {
	let mut future = std::pin::pin!(future);
	let mut context = Context::from_waker(Waker::noop());
	loop {
		if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
			return output;
		}
		std::thread::yield_now();
	}
}

fn run<T, E: Debug, F: Future<Output = Result<T, E>>>(future: F) -> T {
	block_on(future).unwrap()
}

fn try_run<T, E, F: Future<Output = Result<T, E>>>(future: F) -> Result<T, E> {
	block_on(future)
}

#[test]
#[ignore = "needs BOXFS_JUICEFS_META, a formatted JuiceFS metadata URL"]
fn walk_read_range_and_diff() {
	let Ok(meta) = std::env::var("BOXFS_JUICEFS_META") else {
		return;
	};
	let cache = std::env::var_os("BOXFS_JUICEFS_CACHE")
		.map(PathBuf::from)
		.unwrap_or_else(|| {
			Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-tmp/juicefs-cache")
		});
	fs::create_dir_all(&cache).unwrap();
	let volume = boxfs_juicefs::Volume::mount(&meta, &cache).unwrap();
	let root = format!("/juicefs-contract-{}", std::process::id());
	let root = Path::new(&root);

	drop(try_run(Volume::remove_all(&volume, root)));
	run(Volume::create_dir_all(&volume, &root.join("sub")));
	for (path, data) in [
		("keep", b"keep".as_slice()),
		("edit", b"AAAA".as_slice()),
		("remove", b"gone".as_slice()),
		("kind", b"file".as_slice()),
		("sub/nested", b"one!".as_slice()),
		("sub/removed", b"old!".as_slice()),
	] {
		run(Volume::write(&volume, &root.join(path), data));
	}
	run(Volume::symlink(
		&volume,
		Path::new("keep"),
		&root.join("link"),
	));

	let entries = run(Volume::walk(&volume, root));
	let paths: Vec<PathBuf> = entries.iter().map(|entry| entry.path.clone()).collect();
	assert_eq!(
		paths,
		vec![
			PathBuf::from("edit"),
			PathBuf::from("keep"),
			PathBuf::from("kind"),
			PathBuf::from("link"),
			PathBuf::from("remove"),
			PathBuf::from("sub"),
			PathBuf::from("sub/nested"),
			PathBuf::from("sub/removed"),
		]
	);
	assert!(!paths.contains(&PathBuf::from("link/nested")));
	assert_eq!(
		run(Volume::read_range(&volume, &root.join("keep"), 0, 2)),
		b"ke"
	);
	assert!(run(Volume::read_range(&volume, &root.join("keep"), 4, 2)).is_empty());
	assert!(run(Volume::read_range(&volume, &root.join("keep"), 1, 0)).is_empty());

	let snapshot = run(Snapshot::snapshot(&volume));
	run(Volume::write(&volume, &root.join("edit"), b"BBBB"));
	run(Volume::write(&volume, &root.join("sub/nested"), b"two!"));
	run(Volume::write(&volume, &root.join("add"), b"new"));
	run(Volume::write(&volume, &root.join("sub/added"), b"new"));
	run(Volume::remove_file(&volume, &root.join("remove")));
	run(Volume::remove_file(&volume, &root.join("sub/removed")));
	run(Volume::remove_file(&volume, &root.join("kind")));
	run(Volume::create_dir(&volume, &root.join("kind")));
	run(Volume::write(&volume, &root.join("kind/child"), b"x"));
	run(Volume::remove_file(&volume, &root.join("link")));
	run(Volume::symlink(
		&volume,
		Path::new("add"),
		&root.join("link"),
	));

	let changed: Vec<(PathBuf, DiffKind)> = run(Snapshot::diff(&volume, &snapshot, root))
		.into_iter()
		.map(|entry| (entry.path, entry.kind))
		.collect();
	assert_eq!(
		changed,
		vec![
			(PathBuf::from("add"), DiffKind::Added),
			(PathBuf::from("edit"), DiffKind::Modified),
			(PathBuf::from("kind"), DiffKind::Modified),
			(PathBuf::from("kind/child"), DiffKind::Added),
			(PathBuf::from("link"), DiffKind::Modified),
			(PathBuf::from("remove"), DiffKind::Removed),
			(PathBuf::from("sub/added"), DiffKind::Added),
			(PathBuf::from("sub/nested"), DiffKind::Modified),
			(PathBuf::from("sub/removed"), DiffKind::Removed),
		]
	);
	let scoped: Vec<(PathBuf, DiffKind)> =
		run(Snapshot::diff(&volume, &snapshot, &root.join("sub")))
			.into_iter()
			.map(|entry| (entry.path, entry.kind))
			.collect();
	assert_eq!(
		scoped,
		vec![
			(PathBuf::from("added"), DiffKind::Added),
			(PathBuf::from("nested"), DiffKind::Modified),
			(PathBuf::from("removed"), DiffKind::Removed),
		]
	);
	assert!(try_run(Snapshot::diff(&volume, &snapshot, &root.join("missing"))).is_err());

	run(Snapshot::restore(&volume, &snapshot));
	assert!(run(Snapshot::diff(&volume, &snapshot, root)).is_empty());
	run(Snapshot::delete(&volume, &snapshot));
	run(Volume::remove_all(&volume, root));
}
