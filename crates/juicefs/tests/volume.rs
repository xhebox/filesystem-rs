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
use boxfs_juicefs::MountOptions;

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
	let volume = boxfs_juicefs::Volume::mount(
		&meta,
		MountOptions {
			cache_dir: Some(&cache),
			..Default::default()
		},
	)
	.unwrap();
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

#[test]
fn format_and_mount_isolated_sqlite_volumes() {
	let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
		.join("../../target/test-tmp")
		.join(format!("boxfs-juicefs-format-test-{}", std::process::id()));
	drop(fs::remove_dir_all(&dir));
	let owner_a = dir.join("owner-a");
	let owner_b = dir.join("owner-b");
	fs::create_dir_all(owner_a.join("chunks")).unwrap();
	fs::create_dir_all(owner_b.join("chunks")).unwrap();

	let meta_a = format!("sqlite3://{}", owner_a.join("meta.db").display());
	let meta_b = format!("sqlite3://{}", owner_b.join("meta.db").display());

	boxfs_juicefs::Volume::format(
		&meta_a,
		&boxfs_juicefs::Format {
			name: "owner-a".into(),
			storage: "file".into(),
			bucket: owner_a.join("chunks").display().to_string(),
			..Default::default()
		},
	)
	.unwrap();
	// Idempotent second call when force == false.
	boxfs_juicefs::Volume::format(
		&meta_a,
		&boxfs_juicefs::Format {
			name: "owner-a".into(),
			storage: "file".into(),
			bucket: owner_a.join("chunks").display().to_string(),
			..Default::default()
		},
	)
	.unwrap();

	boxfs_juicefs::Volume::format(
		&meta_b,
		&boxfs_juicefs::Format {
			name: "owner-b".into(),
			storage: "file".into(),
			bucket: owner_b.join("chunks").display().to_string(),
			..Default::default()
		},
	)
	.unwrap();

	let cache_a = owner_a.join("cache");
	let cache_b = owner_b.join("cache");
	let options_a = MountOptions {
		cache_dir: Some(&cache_a),
		..Default::default()
	};
	let options_b = MountOptions {
		cache_dir: Some(&cache_b),
		..Default::default()
	};
	{
		let vol_a = boxfs_juicefs::Volume::mount(&meta_a, options_a).unwrap();
		let vol_b = boxfs_juicefs::Volume::mount(&meta_b, options_b).unwrap();
		run(Volume::write(
			&vol_a,
			Path::new("/secret.txt"),
			b"alice-only",
		));
		assert!(try_run(Volume::read(&vol_b, Path::new("/secret.txt"))).is_err());
		run(Volume::write(&vol_b, Path::new("/secret.txt"), b"bob-only"));
		assert_eq!(
			run(Volume::read(&vol_a, Path::new("/secret.txt"))),
			b"alice-only"
		);
		assert_eq!(
			run(Volume::read(&vol_b, Path::new("/secret.txt"))),
			b"bob-only"
		);
	}

	// Re-mount vol_a after drop to verify native persistence.
	{
		let vol_a = boxfs_juicefs::Volume::mount(&meta_a, options_a).unwrap();
		assert_eq!(
			run(Volume::read(&vol_a, Path::new("/secret.txt"))),
			b"alice-only"
		);
	}

	{
		let read_only = boxfs_juicefs::Volume::mount(
			&meta_a,
			MountOptions {
				cache_dir: Some(&owner_a.join("read-only-cache")),
				read_only: true,
				..Default::default()
			},
		)
		.unwrap();
		assert_eq!(
			run(Volume::read(&read_only, Path::new("/secret.txt"))),
			b"alice-only"
		);
		assert!(
			try_run(Volume::write(
				&read_only,
				Path::new("/forbidden.txt"),
				b"must not be written",
			))
			.is_err()
		);
	}

	// Keep both subdirectory mounts alive while opening a whole-volume mount.
	let mount_subdir = |subdir, read_only| {
		boxfs_juicefs::Volume::mount(
			&meta_a,
			MountOptions {
				read_only,
				subdir: Some(subdir),
				..options_a
			},
		)
	};
	assert!(mount_subdir("/missing", true).is_err());
	let a = mount_subdir("/a", false).unwrap();
	let b = mount_subdir("/b", false).unwrap();
	let root = boxfs_juicefs::Volume::mount(&meta_a, options_a).unwrap();
	run(Volume::write(&a, Path::new("/marker"), b"a"));
	run(Volume::write(&b, Path::new("/marker"), b"b"));
	assert_eq!(run(Volume::read(&root, Path::new("/a/marker"))), b"a");
	assert_eq!(run(Volume::read(&root, Path::new("/b/marker"))), b"b");
	assert!(try_run(Volume::read(&a, Path::new("/secret.txt"))).is_err());
	let read_only = mount_subdir("/a", true).unwrap();
	assert_eq!(run(Volume::read(&read_only, Path::new("/marker"))), b"a");
	let ctx = boxfs_juicefs::Ctx::default();
	assert!(try_run(a.lookup(ctx, 1, c".trash")).is_err());
	assert!(try_run(root.lookup(ctx, 1, c".trash")).is_ok());
	for (volume, expect_trash) in [(&a, false), (&b, false), (&root, true)] {
		let fh = run(volume.opendir(ctx, 1, 0));
		let (entries, _) = run(volume.readdir(ctx, 1, fh, 0, 4096, true));
		assert!(entries.iter().any(|entry| entry.name == b".config"));
		assert_eq!(
			entries.iter().any(|entry| entry.name == b".trash"),
			expect_trash
		);
		run(volume.releasedir(ctx, 1, fh));
	}
	drop((read_only, a, b, root));
	drop(fs::remove_dir_all(&dir));
}

/// Root listing names, as raw bytes, for one directory handle's whole read.
fn root_names(volume: &boxfs_juicefs::Volume) -> Vec<Vec<u8>> {
	let ctx = boxfs_juicefs::Ctx::default();
	let fh = run(volume.opendir(ctx, 1, 0));
	let mut names = Vec::new();
	loop {
		let offset = names.len();
		let (entries, _) = run(volume.readdir(ctx, 1, fh, offset as u64, 4096, true));
		if entries.is_empty() {
			break;
		}
		names.extend(entries.into_iter().map(|entry| entry.name));
	}
	run(volume.releasedir(ctx, 1, fh));
	names
}

#[test]
fn hide_internal_and_cache_options() {
	let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
		.join("../../target/test-tmp")
		.join(format!("boxfs-juicefs-options-test-{}", std::process::id()));
	drop(fs::remove_dir_all(&dir));
	let chunks = dir.join("chunks");
	fs::create_dir_all(&chunks).unwrap();
	let meta = format!("sqlite3://{}", dir.join("meta.db").display());
	boxfs_juicefs::Volume::format(
		&meta,
		&boxfs_juicefs::Format {
			name: "options".into(),
			storage: "file".into(),
			bucket: chunks.display().to_string(),
			..Default::default()
		},
	)
	.unwrap();

	let cache = dir.join("cache");
	let hidden = boxfs_juicefs::Volume::mount(
		&meta,
		MountOptions {
			cache_dir: Some(&cache),
			hide_internal: true,
			..Default::default()
		},
	)
	.unwrap();
	let names = root_names(&hidden);
	assert!(names.iter().any(|name| name == b"."), "{names:?}");
	for internal in [b".config".as_slice(), b".stats", b".accesslog", b".trash"] {
		assert!(
			!names.iter().any(|name| name == internal),
			"{internal:?} must not be listed: {names:?}"
		);
	}
	// Hiding is a listing policy, not a permission: the node is still reachable.
	let ctx = boxfs_juicefs::Ctx::default();
	assert!(try_run(hidden.lookup(ctx, 1, c".config")).is_ok());

	// The same volume mounted without the flag still shows them.
	let shown = boxfs_juicefs::Volume::mount(
		&meta,
		MountOptions {
			cache_dir: Some(&cache),
			..Default::default()
		},
	)
	.unwrap();
	let names = root_names(&shown);
	for internal in [b".config".as_slice(), b".stats", b".accesslog", b".trash"] {
		assert!(
			names.iter().any(|name| name == internal),
			"{internal:?} must be listed: {names:?}"
		);
	}

	// Memory-only cache with non-default eviction and checksum, plus a custom
	// readahead and writeback, exercises the remaining option plumbing.
	let tuned = boxfs_juicefs::Volume::mount(
		&meta,
		MountOptions {
			cache_dir: Some(Path::new("memory")),
			cache_size: 64 << 20,
			cache_items: 1024,
			cache_eviction: boxfs_juicefs::CacheEviction::Lru,
			cache_checksum: boxfs_juicefs::CacheChecksum::Extend,
			max_readahead: 16 << 20,
			prefetch: 2,
			writeback: true,
			buffer_size: 64 << 20,
			max_uploads: 8,
			max_downloads: 16,
			io_retries: 3,
			get_timeout: std::time::Duration::from_secs(30),
			put_timeout: std::time::Duration::from_secs(30),
			free_space_permille: 0,
			..Default::default()
		},
	)
	.unwrap();
	let payload = vec![7u8; 3 << 20];
	run(Volume::write(&tuned, Path::new("/payload"), &payload));
	assert_eq!(run(Volume::read(&tuned, Path::new("/payload"))), payload);

	drop((tuned, shown, hidden));
	drop(fs::remove_dir_all(&dir));
}
