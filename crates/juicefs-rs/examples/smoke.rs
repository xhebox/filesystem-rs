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
		match juicefs_rs::Volume::mount("sqlite3:///nonexistent/volume.db", cache) {
			Ok(_) => println!("a volume that cannot exist mounted: wrong"),
			Err(error) => println!("mount refused, as it should be: {error}"),
		}
		return Ok(());
	};

	let volume = juicefs_rs::Volume::mount(&meta, cache)?;
	println!("mounted");

	let ctx = juicefs_rs::Ctx::default();
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
