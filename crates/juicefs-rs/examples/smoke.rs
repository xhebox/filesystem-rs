//! Links the Go archive and drives it, which is the whole of what this crate
//! has to get right.
//!
//! Run it after `task juicefs`, which installs the archive it builds into
//! `target/juicefs`, where the build script looks first — or after a build that
//! downloaded the archive published for this crate's version.
//!
//! ```text
//! cargo run -p juicefs-rs --example smoke [META-URL]
//! ```
//!
//! `JUICEFS_CACHE` moves that cache, here as in the build script.
//!
//! Without a metadata URL it mounts a URL that cannot resolve, and expects the
//! Go side to say so — which is the interesting part: a failure message is
//! proof that the runtime started, that the entry call carried the arguments
//! it needed, and that a `//export`ed function ran.
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

	juicefs_rs::start_runtime();
	println!("the Go runtime started");

	let Some(meta) = argument else {
		match juicefs_rs::Session::open(
			"sqlite3:///nonexistent/volume.db",
			cache,
			std::time::Duration::from_secs(1),
			std::time::Duration::from_secs(1),
		) {
			Ok(_) => println!("a volume that cannot exist mounted: wrong"),
			Err(error) => println!("mount refused, as it should be: {error}"),
		}
		return Ok(());
	};

	let volume = juicefs_rs::Session::open(
		&meta,
		cache,
		std::time::Duration::from_secs(1),
		std::time::Duration::from_secs(1),
	)?;
	println!("mounted");

	let ctx = juicefs_rs::Ctx::default();
	let root = block_on(volume.getattr(ctx, 1, false))?;
	println!(
		"GETATTR root: mode={:o} nlink={} uid={} gid={} blksize={}",
		root.mode, root.nlink, root.uid, root.gid, root.blksize
	);
	assert_eq!(root.ino, 1, "the root's attributes are the root's");

	let statfs = block_on(volume.statfs(ctx, 1))?;
	println!(
		"STATFS: blocks={} bfree={} bavail={} files={} ffree={} bsize={} namelen={}",
		statfs.blocks,
		statfs.bfree,
		statfs.bavail,
		statfs.files,
		statfs.ffree,
		statfs.bsize,
		statfs.namelen
	);
	assert_eq!(statfs.bsize, 4096);
	assert_eq!(statfs.namelen, 255);
	Ok(())
}
