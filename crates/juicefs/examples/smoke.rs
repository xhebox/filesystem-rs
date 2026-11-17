//! Links the Go archive and drives it, which is the whole of what this crate
//! has to get right.
//!
//! Cargo normally downloads the archive released for the exact sys dependency.
//! Maintainers can use `task test-sys` to build and test a local archive.
//!
//! ```text
//! cargo run -p boxfs-juicefs --example smoke [META-URL]
//! ```
//!
//! `JUICEFS_SYS_CACHE` selects the native archive download cache.
//!
//! Without a metadata URL it opens an unformatted SQLite database and expects
//! the Go side to return an error. This verifies runtime startup and a round
//! trip through an exported function without requiring a running backend.
//!
//! With one, it mounts for real and asks the volume about its root: GETATTR
//! (ino 1) and STATFS. Between them they cross the same path the device uses
//! for metadata and for the block accounting.

// An example is a program: printing what the Go side negotiated is the point,
// and it owns its stdout the way the CLI does.
#![allow(clippy::print_stdout)]

use std::io;

/// Drives one future to its answer on this thread.
///
/// The device awaits these futures on its own reactor; an example has none, and
/// every future here is completed by a pool thread the call was handed to, so
/// polling until it is ready is all the executor this needs. `Waker::noop`
/// because there is nothing to wake: this thread is already spinning.
fn block_on<F: Future>(future: F) -> F::Output {
	let mut future = std::pin::pin!(future);
	let mut context = std::task::Context::from_waker(std::task::Waker::noop());
	loop {
		if let std::task::Poll::Ready(output) = future.as_mut().poll(&mut context) {
			return output;
		}
		std::thread::yield_now();
	}
}

fn main() -> io::Result<()> {
	let argument = std::env::args().nth(1);
	let cache = std::path::Path::new("/tmp/juicefs-smoke");

	boxfs_juicefs::start_runtime();
	println!("the Go runtime started");

	let Some(meta) = argument else {
		let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
			.join("../../target/test-tmp")
			.join(format!("boxfs-juicefs-smoke-{}", std::process::id()));
		std::fs::create_dir_all(&dir)?;
		let meta = format!("sqlite3://{}", dir.join("unformatted.db").display());
		let result = boxfs_juicefs::Volume::mount(&meta, cache);
		drop(std::fs::remove_dir_all(&dir));
		match result {
			Ok(_) => {
				return Err(io::Error::other(
					"a nonexistent volume unexpectedly mounted",
				));
			}
			Err(error) => println!("mount refused, as it should be: {error}"),
		}
		return Ok(());
	};

	let volume = boxfs_juicefs::Volume::mount(&meta, cache)?;
	println!("mounted");

	let ctx = boxfs_juicefs::Ctx::default();
	let root = block_on(volume.getattr(ctx, 1, false))?;
	println!(
		"GETATTR root: typ={} mode={:o} nlink={} uid={} gid={}",
		root.typ, root.mode, root.nlink, root.uid, root.gid
	);
	assert_eq!(root.typ, 2, "the root is a directory (meta.TypeDirectory)");

	let statfs = block_on(volume.statfs(ctx, 1))?;
	println!(
		"STATFS: total={} avail={} files={} favail={}",
		statfs.total, statfs.avail, statfs.files, statfs.favail
	);
	assert!(
		statfs.avail <= statfs.total,
		"the VFS never has more free than the total"
	);
	Ok(())
}
