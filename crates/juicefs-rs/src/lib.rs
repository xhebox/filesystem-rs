//! One JuiceFS volume, served from the VMM's own process.
//!
//! `crates/juicefs-rs/binding` is a Go program built as a c-archive and
//! linked in here, so a `juicefs://` volume needs no helper process. Its C
//! surface is one function per VFS operation: the VMM parses the guest's FUSE
//! messages with the same front-end the passthrough back-end uses, and each
//! parsed operation becomes a call here. No FUSE bytes cross this boundary in
//! either direction.
//!
//! Two things about calling into Go from this process are not obvious, and
//! they are why this crate owns a thread pool rather than exposing the C calls
//! directly:
//!
//! * A call into Go is blocking, and reaches object storage and the metadata
//!   engine. On a device thread it would stall that thread's reactor.
//! * A seccomp filter is per-thread and is inherited by every thread a
//!   filtered thread starts. The VMM filters a device thread with
//!   `KillProcess` as the default action, and the Go runtime starts OS threads
//!   lazily — so one call into Go from a filtered thread would make every Go
//!   thread after it inherit that filter, to be killed by the first syscall
//!   the filter does not list.
//!
//! Both are answered the same way: a session owns a pool of plain threads, and
//! every call into Go happens on one of them. The pool is started by whoever
//! calls [`Volume::mount`], which must be a thread no device filter has
//! reached — in the VMM, the monitor thread, before the run seals.
//!
//! A call is a closure: it runs on a pool thread with the session's handle,
//! and its answer comes back through a oneshot channel. That is what lets the
//! methods below be ordinary futures, and what keeps a buffer alive for the
//! whole of a blocking read or write even when the future that started it is
//! dropped: the buffer moves into the closure with the call.

use std::ffi::{CStr, CString, c_char, c_int};
use std::io;
use std::path::Path;
use std::sync::Once;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use asyncband::oneshot;

/// How many calls into Go run at once. The device serves every chain as its
/// own task, so a handful in flight is what keeps a slow read from holding the
/// ones behind it; more would only add Go `M`s.
const WORKERS: usize = 4;

unsafe extern "C" {
	/// The Go runtime's entry point in a c-archive.
	///
	/// `-buildmode=c-archive` starts the runtime from a library constructor, and
	/// **no** constructor is handed `argc`/`argv`: musl does not pass them to
	/// `.init_array` at all, dyld does not pass them to a Mach-O module
	/// initializer, and MSVC's `.CRT$XCU` gets none either. Go needs them —
	/// `runtime.sysargs` walks `argv` on through `envp` to `auxv` on Linux, and
	/// reads the `executable_path=` entry out of `envp` on macOS — so with the
	/// constructor's zeros it walks a null pointer and the process dies before the
	/// first call.
	///
	/// The archive the build leaves here has that constructor removed, its
	/// `_rt0_<arch>_<os>_lib` entry renamed to `juicefs_rt0`, and every
	/// non-`juicefs_*` symbol localized so another Go archive can link into the
	/// same process beside this one; [`start_runtime`] makes the entry call with
	/// the arguments the process really has.
	fn juicefs_rt0(argc: c_int, argv: *mut *mut c_char);
}

#[allow(non_camel_case_types, non_snake_case, unreachable_pub, dead_code)]
mod binding;

// The C structures are `binding`'s, generated from the Go archive's header. The
// names here are the ones the rest of the crate has always used.
pub use binding::{
	juicefs_attr as Attr, juicefs_ctx as Ctx, juicefs_dirent as Dirent, juicefs_entry as Entry,
	juicefs_statvfs as Statfs,
};

/// bindgen types every pointer argument `*mut`, because cgo's header has no `const`.
/// Go only reads through the ones passed as `&T`, so the cast is all there is to it.
fn mut_ptr<T>(value: &T) -> *mut T {
	std::ptr::from_ref(value).cast_mut()
}

/// Starts the Go runtime, once per process, with this process's arguments.
///
/// [`Volume::mount`] calls this itself, and *when* it does so is what makes
/// that work. Starting the runtime brings up the Go scheduler's threads and
/// installs Go's own handling for `SIGSEGV`, `SIGBUS`, `SIGFPE`, `SIGURG`,
/// `SIGPIPE` and for `SIGINT`/`SIGTERM`, so it has to happen after whatever
/// puts the process in its namespace (`unshare` wants one thread; the runtime
/// is several), before the host installs signal handling of its own (or the
/// runtime takes `SIGINT`/`SIGTERM` back and the process stops shutting down
/// cleanly), and before any thread is confined (every thread the runtime goes
/// on to start inherits the confinement of the one that started it). In the
/// VMM those three sit either side of one call: `Volume::mount` runs while the
/// devices are being attached, which is after the sandbox is entered and
/// before it is sealed, and well before the run installs its handlers.
pub fn start_runtime() {
	static STARTED: Once = Once::new();
	STARTED.call_once(|| {
		let (argc, block) = startup_block();
		// Go holds these pointers for the life of the process.
		let block = Box::leak(block.into_boxed_slice());
		// SAFETY: the entry calls into this archive's Go runtime, which this
		// crate's contract is that it happens once and first; `block` is the
		// argument vector `runtime.sysargs` walks, laid out as the loader lays
		// it out.
		unsafe { juicefs_rt0(argc, block.as_mut_ptr()) }
	});
}

/// The argument block the Go runtime expects to be handed, which is not just
/// `argv`.
///
/// `runtime.sysargs` treats the block as one run of memory: it walks `argv`
/// until a null, keeps going through `envp` until the next one, and reads
/// `auxv` from what follows. Handing it a `Vec` of arguments — which is what
/// this looked like at first, and what a host naturally has — leaves it
/// reading whatever happens to be past the allocation once it runs off the
/// end of `envp`. On Linux the auxv walk then fails and falls back to
/// `/proc/self/auxv`, which is why it appears to work; the environment it
/// picked up along the way was garbage.
///
/// So the block is built the way `_start` is handed it: the arguments, a null,
/// the environment, a null, and the auxiliary vector.
fn startup_block() -> (c_int, Vec<*mut c_char>) {
	// A process with no arguments still passes one, since `sysargs` reads
	// `argv[0]` before it looks at anything else.
	let mut block: Vec<*mut c_char> = strings(std::env::args_os());
	if block.is_empty() {
		block.push(CString::new("juicefs").expect("no NUL").into_raw());
	}
	let argc = block.len() as c_int;
	block.push(std::ptr::null_mut());

	// When a second Go archive is linked into the same process, the later
	// runtime's `sigfwdgo` chains `SIGSEGV`, `SIGBUS`, `SIGFPE` and `SIGPIPE`
	// to the earlier one's handler, but drops `SIGURG` (`sigPreempt`) on any
	// thread whose `g` in the later runtime's TLS slot is nil. Turning off
	// signal-driven preemption leaves only cooperative preemption at function
	// prologues, so neither runtime sends `SIGURG`.
	let mut godebug = std::ffi::OsString::from("GODEBUG=");
	if let Some(existing) = std::env::var_os("GODEBUG").filter(|value| !value.is_empty()) {
		godebug.push(existing);
		godebug.push(",");
	}
	godebug.push("asyncpreemptoff=1");

	block.extend(strings(
		std::env::vars_os()
			.filter(|(name, _)| name != "GODEBUG")
			.map(|(name, value)| {
				let mut entry = name;
				entry.push("=");
				entry.push(value);
				entry
			})
			.chain(std::iter::once(godebug)),
	));
	block.push(std::ptr::null_mut());

	block.extend(auxv());
	(argc, block)
}

/// `OsString`s as the `char *`s the block holds, leaking each one: the Go
/// runtime keeps them for the life of the process.
fn strings<I: IntoIterator<Item = std::ffi::OsString>>(values: I) -> Vec<*mut c_char> {
	values
		.into_iter()
		.filter_map(|value| CString::new(value.as_encoded_bytes()).ok())
		.map(CString::into_raw)
		.collect()
}

/// `auxv` as `sysargs` reads it: pairs of machine words, terminated by the
/// `AT_NULL` pair. Read from the process's own, so the page size and the other
/// entries are the loader's rather than a guess. A host without `/proc` gets
/// the terminator alone, which leaves Go to its own fallback.
#[cfg(target_os = "linux")]
fn auxv() -> Vec<*mut c_char> {
	let Ok(bytes) = std::fs::read("/proc/self/auxv") else {
		return vec![std::ptr::null_mut(); 2];
	};
	let (words, _) = bytes.as_chunks::<{ size_of::<usize>() }>();
	let entries: Vec<*mut c_char> = words
		.iter()
		.map(|word| usize::from_ne_bytes(*word) as *mut c_char)
		.collect();
	// The walk ends on the `AT_NULL` pair; a file that has none would send
	// `sysauxv` off the end of this block.
	if entries.len() < 2 {
		return vec![std::ptr::null_mut(); 2];
	}
	entries
}

/// macOS has no auxv. What `sysargs` reads here is the entry after `envp`'s
/// terminator, which is where the kernel puts the "apple" vector — and its
/// first string is the one Go is after: the path to the executable, which it
/// takes the `executable_path=` prefix off.
#[cfg(target_os = "macos")]
fn auxv() -> Vec<*mut c_char> {
	match std::env::current_exe() {
		Ok(path) => {
			let mut entry = std::ffi::OsString::from("executable_path=");
			entry.push(path);
			let mut block = strings(std::iter::once(entry));
			block.push(std::ptr::null_mut());
			block
		}
		// Without it Go has no idea where it was loaded from; there is nothing
		// better to pass than the terminator.
		Err(_) => vec![std::ptr::null_mut()],
	}
}

/// The Windows runtime reads no argument vector at all (`os_windows.go` has no
/// `sysargs`), so the block ends here.
#[cfg(target_os = "windows")]
fn auxv() -> Vec<*mut c_char> {
	Vec::new()
}

/// A mounted volume and the threads that serve it.
///
/// Dropping it unmounts: the pool's threads see their queues close and end,
/// and the Go-side session is released.
pub struct Volume {
	handle: usize,
	/// One queue per worker, and a cursor over them. A single shared queue
	/// would have to be reached into exclusively by each worker, since the
	/// receive that blocks is the one that takes the queue — which would
	/// serialize them.
	queues: Vec<Sender<Job>>,
	next: AtomicUsize,
	workers: Vec<JoinHandle<()>>,
}

/// One call in flight: what to run with the session's handle, and the channel
/// the worker answers on.
type Job = Box<dyn FnOnce(usize) + Send>;

impl Volume {
	/// Mounts the volume `meta_url` names, caching chunks under `cache_dir`.
	///
	/// Starts the Go runtime if this is the process's first volume, and the
	/// pool with it, so it must run on a thread no device filter has reached
	/// and at a point [`start_runtime`] describes — see this module's
	/// documentation.
	pub fn mount(meta_url: &str, cache_dir: &Path) -> io::Result<Volume> {
		start_runtime();
		let payload = CString::new(meta_url).map_err(|_| {
			io::Error::new(io::ErrorKind::InvalidInput, "the metadata URL has a NUL")
		})?;
		let cache = CString::new(cache_dir.as_os_str().as_encoded_bytes())
			.map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the cache path has a NUL"))?;

		let mut error = 0usize;
		// SAFETY: both arguments are valid NUL-terminated strings for the
		// duration of the call, and `error` is a valid place to write one.
		let handle = unsafe {
			binding::juicefs_mount(
				payload.as_ptr().cast_mut(),
				cache.as_ptr().cast_mut(),
				&mut error,
			)
		};
		if handle == 0 {
			return Err(mount_error(error));
		}

		let mut queues = Vec::with_capacity(WORKERS);
		let mut workers = Vec::with_capacity(WORKERS);
		for index in 0..WORKERS {
			let (queue, jobs) = mpsc::channel::<Job>();
			let worker = thread::Builder::new()
				.name(format!("juicefs-{index}"))
				.spawn(move || serve(handle, jobs));
			match worker {
				Ok(worker) => {
					queues.push(queue);
					workers.push(worker);
				}
				Err(error) => {
					// Close what is running before releasing the session, so
					// no worker can reach it after this.
					drop(queues);
					for worker in workers {
						// A worker's own error is not this one's story.
						drop(worker.join());
					}
					// SAFETY: nothing can call into the session again.
					unsafe { binding::juicefs_unmount(handle) };
					return Err(io::Error::new(
						error.kind(),
						format!("spawn a juicefs worker: {error}"),
					));
				}
			}
		}

		Ok(Volume {
			handle,
			queues,
			next: AtomicUsize::new(0),
			workers,
		})
	}

	/// Runs `f` against the session's handle on a pool thread.
	///
	/// The closure is what keeps a call's ownership alive: whatever it
	/// captures lives until the blocking call returns, even when the future
	/// waiting on it is dropped.
	async fn call<R: Send + 'static>(
		&self,
		f: impl FnOnce(usize) -> io::Result<R> + Send + 'static,
	) -> io::Result<R> {
		let (done, answer) = oneshot::channel();
		let job: Job = Box::new(move |handle| drop(done.send(f(handle))));
		// The cursor is this function's only shared state, and `fetch_add`
		// gives each concurrent caller a different queue.
		let index = self.next.fetch_add(1, Ordering::Relaxed) % self.queues.len();
		self.queues[index]
			.send(job)
			.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "the JuiceFS pool is gone"))?;
		answer.await.map_err(|_| {
			io::Error::new(io::ErrorKind::BrokenPipe, "the JuiceFS worker went away")
		})?
	}

	pub async fn lookup(&self, ctx: Ctx, parent: u64, name: &CStr) -> io::Result<Entry> {
		let name = name.to_owned();
		self.call(move |handle| {
			let mut out = Entry::default();
			// SAFETY: `name` outlives the call, and `out` is a valid place for
			// the Go side to write the entry.
			let code = unsafe {
				binding::juicefs_lookup(
					handle,
					mut_ptr(&ctx),
					parent,
					name.as_ptr().cast_mut(),
					&mut out,
				)
			};
			check(code).map(|()| out)
		})
		.await
	}

	pub async fn getattr(&self, ctx: Ctx, ino: u64, opened: bool) -> io::Result<Attr> {
		self.call(move |handle| {
			let mut out = Attr::default();
			// SAFETY: `out` is a valid place for the Go side to write the attr.
			let code = unsafe {
				binding::juicefs_getattr(handle, mut_ptr(&ctx), ino, c_int::from(opened), &mut out)
			};
			check(code).map(|()| out)
		})
		.await
	}

	/// Reports the fields a SETATTR marked valid; the Go side applies the
	/// `ATIME_NOW`/`MTIME_NOW` substitutions itself, as the FUSE server does.
	pub async fn setattr(
		&self,
		ctx: Ctx,
		ino: u64,
		valid: u32,
		fh: u64,
		mode: u32,
		uid: u32,
		gid: u32,
		atime: i64,
		mtime: i64,
		atimensec: u32,
		mtimensec: u32,
		size: u64,
	) -> io::Result<Attr> {
		self.call(move |handle| {
			let mut out = Attr::default();
			// SAFETY: `out` is a valid place for the Go side to write the attr.
			let code = unsafe {
				binding::juicefs_setattr(
					handle,
					mut_ptr(&ctx),
					ino,
					valid,
					fh,
					mode,
					uid,
					gid,
					atime,
					mtime,
					atimensec,
					mtimensec,
					size,
					&mut out,
				)
			};
			check(code).map(|()| out)
		})
		.await
	}

	/// Reads a symbolic link's target.
	pub async fn readlink(&self, ctx: Ctx, ino: u64) -> io::Result<Vec<u8>> {
		self.call(move |handle| {
			let mut out = 0usize;
			// SAFETY: `out` is a valid place for the Go side to write.
			let code = unsafe { binding::juicefs_readlink(handle, mut_ptr(&ctx), ino, &mut out) };
			take(code, out)
		})
		.await
	}

	pub async fn symlink(
		&self,
		ctx: Ctx,
		target: &CStr,
		parent: u64,
		name: &CStr,
	) -> io::Result<Entry> {
		let target = target.to_owned();
		let name = name.to_owned();
		self.call(move |handle| {
			let mut out = Entry::default();
			// SAFETY: both strings outlive the call, and `out` is a valid place
			// for the Go side to write the entry.
			let code = unsafe {
				binding::juicefs_symlink(
					handle,
					mut_ptr(&ctx),
					target.as_ptr().cast_mut(),
					parent,
					name.as_ptr().cast_mut(),
					&mut out,
				)
			};
			check(code).map(|()| out)
		})
		.await
	}

	pub async fn mknod(
		&self,
		ctx: Ctx,
		parent: u64,
		name: &CStr,
		mode: u32,
		rdev: u32,
		umask: u32,
	) -> io::Result<Entry> {
		let name = name.to_owned();
		self.call(move |handle| {
			let mut out = Entry::default();
			// SAFETY: `name` outlives the call, and `out` is a valid place for
			// the Go side to write the entry.
			let code = unsafe {
				binding::juicefs_mknod(
					handle,
					mut_ptr(&ctx),
					parent,
					name.as_ptr().cast_mut(),
					mode,
					rdev,
					umask,
					&mut out,
				)
			};
			check(code).map(|()| out)
		})
		.await
	}

	pub async fn mkdir(
		&self,
		ctx: Ctx,
		parent: u64,
		name: &CStr,
		mode: u32,
		umask: u32,
	) -> io::Result<Entry> {
		let name = name.to_owned();
		self.call(move |handle| {
			let mut out = Entry::default();
			// SAFETY: `name` outlives the call, and `out` is a valid place for
			// the Go side to write the entry.
			let code = unsafe {
				binding::juicefs_mkdir(
					handle,
					mut_ptr(&ctx),
					parent,
					name.as_ptr().cast_mut(),
					mode,
					umask,
					&mut out,
				)
			};
			check(code).map(|()| out)
		})
		.await
	}

	pub async fn unlink(&self, ctx: Ctx, parent: u64, name: &CStr) -> io::Result<()> {
		let name = name.to_owned();
		self.call(move |handle| {
			// SAFETY: `name` outlives the call.
			check(unsafe {
				binding::juicefs_unlink(handle, mut_ptr(&ctx), parent, name.as_ptr().cast_mut())
			})
		})
		.await
	}

	pub async fn rmdir(&self, ctx: Ctx, parent: u64, name: &CStr) -> io::Result<()> {
		let name = name.to_owned();
		self.call(move |handle| {
			// SAFETY: `name` outlives the call.
			check(unsafe {
				binding::juicefs_rmdir(handle, mut_ptr(&ctx), parent, name.as_ptr().cast_mut())
			})
		})
		.await
	}

	pub async fn rename(
		&self,
		ctx: Ctx,
		parent: u64,
		name: &CStr,
		newparent: u64,
		newname: &CStr,
		flags: u32,
	) -> io::Result<()> {
		let name = name.to_owned();
		let newname = newname.to_owned();
		self.call(move |handle| {
			// SAFETY: both strings outlive the call.
			check(unsafe {
				binding::juicefs_rename(
					handle,
					mut_ptr(&ctx),
					parent,
					name.as_ptr().cast_mut(),
					newparent,
					newname.as_ptr().cast_mut(),
					flags,
				)
			})
		})
		.await
	}

	pub async fn link(
		&self,
		ctx: Ctx,
		ino: u64,
		newparent: u64,
		newname: &CStr,
	) -> io::Result<Entry> {
		let newname = newname.to_owned();
		self.call(move |handle| {
			let mut out = Entry::default();
			// SAFETY: `newname` outlives the call, and `out` is a valid place
			// for the Go side to write the entry.
			let code = unsafe {
				binding::juicefs_link(
					handle,
					mut_ptr(&ctx),
					ino,
					newparent,
					newname.as_ptr().cast_mut(),
					&mut out,
				)
			};
			check(code).map(|()| out)
		})
		.await
	}

	/// Opens a file, returning the entry the VFS gives it and the handle.
	pub async fn open(&self, ctx: Ctx, ino: u64, flags: u32) -> io::Result<(Entry, u64)> {
		self.call(move |handle| {
			let mut out = Entry::default();
			let mut fh = 0u64;
			// SAFETY: both out-parameters are valid for the Go side to write.
			let code = unsafe {
				binding::juicefs_open(handle, mut_ptr(&ctx), ino, flags, &mut out, &mut fh)
			};
			check(code).map(|()| (out, fh))
		})
		.await
	}

	pub async fn create(
		&self,
		ctx: Ctx,
		parent: u64,
		name: &CStr,
		mode: u32,
		umask: u32,
		flags: u32,
	) -> io::Result<(Entry, u64)> {
		let name = name.to_owned();
		self.call(move |handle| {
			let mut out = Entry::default();
			let mut fh = 0u64;
			// SAFETY: `name` outlives the call, and every out-parameter is a
			// valid place for the Go side to write.
			let code = unsafe {
				binding::juicefs_create(
					handle,
					mut_ptr(&ctx),
					parent,
					name.as_ptr().cast_mut(),
					mode,
					umask,
					flags,
					&mut out,
					&mut fh,
				)
			};
			check(code).map(|()| (out, fh))
		})
		.await
	}

	/// Reads up to `size` bytes at `offset`, as the VFS reads: the result holds the
	/// bytes it filled, and no more.
	pub async fn read(
		&self,
		ctx: Ctx,
		ino: u64,
		fh: u64,
		offset: u64,
		size: usize,
	) -> io::Result<Vec<u8>> {
		self.call(move |handle| {
			let mut buf = vec![0u8; size];
			let mut n = 0usize;
			// SAFETY: `buf` is `size` writable bytes that live in this closure for the
			// whole call, and `n` is a valid place for the Go side to write.
			let code = unsafe {
				binding::juicefs_read(
					handle,
					mut_ptr(&ctx),
					ino,
					fh,
					offset,
					buf.as_mut_ptr().cast(),
					buf.len(),
					&mut n,
				)
			};
			check(code).map(|()| {
				buf.truncate(n.min(size));
				buf
			})
		})
		.await
	}

	/// Writes `buf` at `offset`, as the VFS writes it. The buffer moves into the
	/// call, so the bytes stay valid until the Go side has copied them, even if
	/// this future is dropped first.
	pub async fn write(
		&self,
		ctx: Ctx,
		ino: u64,
		fh: u64,
		offset: u64,
		buf: Vec<u8>,
	) -> io::Result<()> {
		self.call(move |handle| {
			// SAFETY: `buf` lives in this closure for the whole call, and Go only reads it.
			check(unsafe {
				binding::juicefs_write(
					handle,
					mut_ptr(&ctx),
					ino,
					fh,
					offset,
					buf.as_ptr().cast::<c_char>().cast_mut(),
					buf.len(),
				)
			})
		})
		.await
	}

	/// `lock_owner` is the lock owner the VFS releases on flush; zero means none.
	pub async fn flush(&self, ctx: Ctx, ino: u64, fh: u64, lock_owner: u64) -> io::Result<()> {
		self.call(move |handle| {
			// SAFETY: every argument is a plain value.
			check(unsafe { binding::juicefs_flush(handle, mut_ptr(&ctx), ino, fh, lock_owner) })
		})
		.await
	}

	pub async fn fsync(&self, ctx: Ctx, ino: u64, fh: u64, datasync: bool) -> io::Result<()> {
		self.call(move |handle| {
			// SAFETY: every argument is a plain value.
			check(unsafe {
				binding::juicefs_fsync(handle, mut_ptr(&ctx), ino, fh, c_int::from(datasync))
			})
		})
		.await
	}

	pub async fn release(&self, ctx: Ctx, ino: u64, fh: u64) -> io::Result<()> {
		self.call(move |handle| {
			// SAFETY: every argument is a plain value.
			check(unsafe { binding::juicefs_release(handle, mut_ptr(&ctx), ino, fh) })
		})
		.await
	}

	pub async fn fallocate(
		&self,
		ctx: Ctx,
		ino: u64,
		fh: u64,
		mode: u8,
		offset: i64,
		length: i64,
	) -> io::Result<()> {
		self.call(move |handle| {
			// SAFETY: every argument is a plain value.
			check(unsafe {
				binding::juicefs_fallocate(handle, mut_ptr(&ctx), ino, fh, mode, offset, length)
			})
		})
		.await
	}

	pub async fn statfs(&self, ctx: Ctx, ino: u64) -> io::Result<Statfs> {
		self.call(move |handle| {
			let mut out = Statfs::default();
			// SAFETY: `out` is a valid place for the Go side to write.
			let code = unsafe { binding::juicefs_statfs(handle, mut_ptr(&ctx), ino, &mut out) };
			check(code).map(|()| out)
		})
		.await
	}

	pub async fn access(&self, ctx: Ctx, ino: u64, mask: u32) -> io::Result<()> {
		self.call(move |handle| {
			// SAFETY: every argument is a plain value.
			check(unsafe { binding::juicefs_access(handle, mut_ptr(&ctx), ino, mask) })
		})
		.await
	}

	pub async fn opendir(&self, ctx: Ctx, ino: u64, flags: u32) -> io::Result<u64> {
		self.call(move |handle| {
			let mut fh = 0u64;
			// SAFETY: `fh` is a valid place for the Go side to write.
			let code =
				unsafe { binding::juicefs_opendir(handle, mut_ptr(&ctx), ino, flags, &mut fh) };
			check(code).map(|()| fh)
		})
		.await
	}

	/// Lists a directory from `offset`, as the VFS does: `size` is the VFS's size
	/// argument and `plus` asks for current attributes. The second value is the
	/// time the VFS read the directory, in Unix nanoseconds.
	pub async fn readdir(
		&self,
		ctx: Ctx,
		ino: u64,
		fh: u64,
		offset: u64,
		size: u32,
		plus: bool,
	) -> io::Result<(Vec<DirEntry>, i64)> {
		self.call(move |handle| {
			let mut list = 0usize;
			let mut count = 0usize;
			let mut read_at = 0i64;
			// SAFETY: `list`, `count` and `read_at` are valid places for the Go side to write.
			let code = unsafe {
				binding::juicefs_readdir(
					handle,
					mut_ptr(&ctx),
					ino,
					fh,
					offset,
					size,
					c_int::from(plus),
					&mut list,
					&mut count,
					&mut read_at,
				)
			};
			check(code)?;
			// Every record is copied out before the list is released, on every path.
			let entries = (0..count)
				.map(|index| {
					let mut record = Dirent::default();
					// SAFETY: `list` holds `count` records, and `record` is a valid place for one.
					check(unsafe { binding::juicefs_dirent_at(list, index, &mut record) })
						.map(|()| dir_entry(&record))
				})
				.collect::<io::Result<Vec<_>>>();
			// SAFETY: `list` is the handle the call returned, released once.
			unsafe { binding::juicefs_dirents_free(list) };
			Ok((entries?, read_at))
		})
		.await
	}

	/// Records where a directory handle's reader stopped, so that the next read
	/// from `offset` resumes there.
	pub async fn update_readdir_offset(
		&self,
		ctx: Ctx,
		ino: u64,
		fh: u64,
		offset: u64,
	) -> io::Result<()> {
		self.call(move |handle| {
			// SAFETY: every argument is a plain value.
			check(unsafe {
				binding::juicefs_update_readdir_offset(handle, mut_ptr(&ctx), ino, fh, offset)
			})
		})
		.await
	}

	pub async fn releasedir(&self, ctx: Ctx, ino: u64, fh: u64) -> io::Result<()> {
		self.call(move |handle| {
			// SAFETY: every argument is a plain value.
			check(unsafe { binding::juicefs_releasedir(handle, mut_ptr(&ctx), ino, fh) })
		})
		.await
	}

	/// Reads one extended attribute's value.
	pub async fn getxattr(
		&self,
		ctx: Ctx,
		ino: u64,
		name: &CStr,
		size: u32,
	) -> io::Result<Vec<u8>> {
		let name = name.to_owned();
		self.call(move |handle| {
			let mut out = 0usize;
			// SAFETY: `name` outlives the call, and `out` is a valid place for the
			// Go side to write.
			let code = unsafe {
				binding::juicefs_getxattr(
					handle,
					mut_ptr(&ctx),
					ino,
					name.as_ptr().cast_mut(),
					size,
					&mut out,
				)
			};
			take(code, out)
		})
		.await
	}

	/// Lists the names of a file's extended attributes.
	pub async fn listxattr(&self, ctx: Ctx, ino: u64, size: u32) -> io::Result<Vec<u8>> {
		self.call(move |handle| {
			let mut out = 0usize;
			// SAFETY: `out` is a valid place for the Go side to write.
			let code =
				unsafe { binding::juicefs_listxattr(handle, mut_ptr(&ctx), ino, size, &mut out) };
			take(code, out)
		})
		.await
	}

	pub async fn setxattr(
		&self,
		ctx: Ctx,
		ino: u64,
		name: &CStr,
		value: &[u8],
		flags: u32,
	) -> io::Result<()> {
		let name = name.to_owned();
		// The bytes are copied into the job: the Go side is called on another
		// thread, and `value` may not outlive this future.
		let value = value.to_vec();
		self.call(move |handle| {
			// SAFETY: `name` and `value` live in this closure for the call.
			check(unsafe {
				binding::juicefs_setxattr(
					handle,
					mut_ptr(&ctx),
					ino,
					name.as_ptr().cast_mut(),
					value.as_ptr().cast_mut().cast(),
					value.len(),
					flags,
				)
			})
		})
		.await
	}

	pub async fn removexattr(&self, ctx: Ctx, ino: u64, name: &CStr) -> io::Result<()> {
		let name = name.to_owned();
		self.call(move |handle| {
			// SAFETY: `name` outlives the call.
			check(unsafe {
				binding::juicefs_removexattr(handle, mut_ptr(&ctx), ino, name.as_ptr().cast_mut())
			})
		})
		.await
	}

	/// Sets a file's length, and returns the attributes the VFS reports after it.
	pub async fn truncate(&self, ctx: Ctx, ino: u64, size: i64, fh: u64) -> io::Result<Attr> {
		self.call(move |handle| {
			let mut out = Attr::default();
			// SAFETY: `out` is a valid place for the Go side to write.
			let code = unsafe {
				binding::juicefs_truncate(handle, mut_ptr(&ctx), ino, size, fh, &mut out)
			};
			check(code).map(|()| out)
		})
		.await
	}

	/// Copies `size` bytes from one open file to another, and reports how many
	/// were copied.
	pub async fn copy_file_range(
		&self,
		ctx: Ctx,
		ino_in: u64,
		fh_in: u64,
		off_in: u64,
		ino_out: u64,
		fh_out: u64,
		off_out: u64,
		size: u64,
		flags: u32,
	) -> io::Result<u64> {
		self.call(move |handle| {
			let mut copied = 0u64;
			// SAFETY: `copied` is a valid place for the Go side to write.
			let code = unsafe {
				binding::juicefs_copy_file_range(
					handle,
					mut_ptr(&ctx),
					ino_in,
					fh_in,
					off_in,
					ino_out,
					fh_out,
					off_out,
					size,
					flags,
					&mut copied,
				)
			};
			check(code).map(|()| copied)
		})
		.await
	}

	/// Writes out the buffered data under `path`.
	pub async fn flush_all(&self, path: &CStr) -> io::Result<()> {
		let path = path.to_owned();
		self.call(move |handle| {
			let mut message = 0usize;
			// SAFETY: `path` outlives the call, and `message` is a valid place for
			// the Go side to write a failure's message.
			let code = unsafe {
				binding::juicefs_flush_all(handle, path.as_ptr().cast_mut(), &mut message)
			};
			if code == 0 {
				return Ok(());
			}
			Err(io::Error::other(
				String::from_utf8_lossy(&take_bytes(message)).into_owned(),
			))
		})
		.await
	}

	/// Whether `ino` has changed since `start`, given in Unix nanoseconds.
	pub async fn modified_since(&self, ino: u64, start: i64) -> io::Result<bool> {
		self.call(move |handle| {
			// SAFETY: every argument is a plain value.
			Ok(unsafe { binding::juicefs_modified_since(handle, ino, start) } != 0)
		})
		.await
	}

	/// Drops one open handle's state in the VFS.
	pub async fn release_handler(&self, ino: u64, fh: u64) -> io::Result<()> {
		self.call(move |handle| {
			// SAFETY: every argument is a plain value.
			unsafe { binding::juicefs_release_handler(handle, ino, fh) };
			Ok(())
		})
		.await
	}

	/// Refreshes a file's length from the chunk store, as the VFS does before it
	/// caches an attribute, and returns the length it settles on.
	pub async fn update_length(
		&self,
		ino: u64,
		full: bool,
		typ: u8,
		length: u64,
	) -> io::Result<u64> {
		self.call(move |handle| {
			let mut length = length;
			// SAFETY: `length` is a valid place for the Go side to read and write.
			unsafe {
				binding::juicefs_update_length(handle, ino, c_int::from(full), typ, &mut length)
			};
			Ok(length)
		})
		.await
	}

	/// Tests for a POSIX lock that conflicts with the described range. Returns the
	/// conflicting lock's `(start, len, typ, pid)`, or the query unchanged if none
	/// conflicts.
	pub async fn getlk(
		&self,
		ctx: Ctx,
		ino: u64,
		fh: u64,
		owner: u64,
		start: u64,
		len: u64,
		typ: u32,
		pid: u32,
	) -> io::Result<(u64, u64, u32, u32)> {
		self.call(move |handle| {
			let (mut start, mut len, mut typ, mut pid) = (start, len, typ, pid);
			// SAFETY: every out-parameter is a valid place for the Go side to read and write.
			let code = unsafe {
				binding::juicefs_getlk(
					handle,
					mut_ptr(&ctx),
					ino,
					fh,
					owner,
					&mut start,
					&mut len,
					&mut typ,
					&mut pid,
				)
			};
			check(code).map(|()| (start, len, typ, pid))
		})
		.await
	}

	/// Takes or releases a POSIX lock over `start..end`; `block` waits for a
	/// conflict to clear.
	pub async fn setlk(
		&self,
		ctx: Ctx,
		ino: u64,
		fh: u64,
		owner: u64,
		start: u64,
		end: u64,
		typ: u32,
		pid: u32,
		block: bool,
	) -> io::Result<()> {
		self.call(move |handle| {
			// SAFETY: every argument is a plain value.
			check(unsafe {
				binding::juicefs_setlk(
					handle,
					mut_ptr(&ctx),
					ino,
					fh,
					owner,
					start,
					end,
					typ,
					pid,
					c_int::from(block),
				)
			})
		})
		.await
	}

	/// Takes or releases a BSD lock on the whole file; `block` waits for a conflict.
	pub async fn flock(
		&self,
		ctx: Ctx,
		ino: u64,
		fh: u64,
		owner: u64,
		typ: u32,
		block: bool,
	) -> io::Result<()> {
		self.call(move |handle| {
			// SAFETY: every argument is a plain value.
			check(unsafe {
				binding::juicefs_flock(
					handle,
					mut_ptr(&ctx),
					ino,
					fh,
					owner,
					typ,
					c_int::from(block),
				)
			})
		})
		.await
	}

	/// Runs one ioctl. `input` goes to the VFS as it is, and the reply is the
	/// `output_len` bytes the VFS fills in.
	pub async fn ioctl(
		&self,
		ctx: Ctx,
		ino: u64,
		cmd: u32,
		arg: u64,
		input: Vec<u8>,
		output_len: usize,
	) -> io::Result<Vec<u8>> {
		self.call(move |handle| {
			let mut output = vec![0u8; output_len];
			// SAFETY: `input` and `output` live in this closure for the whole call,
			// and the lengths passed are their own.
			let code = unsafe {
				binding::juicefs_ioctl(
					handle,
					mut_ptr(&ctx),
					ino,
					cmd,
					arg,
					input.as_ptr().cast_mut().cast(),
					input.len(),
					output.as_mut_ptr().cast(),
					output.len(),
				)
			};
			check(code).map(|()| output)
		})
		.await
	}
}

impl Drop for Volume {
	fn drop(&mut self) {
		// Close the queues first, so the workers end rather than wait for more
		// work; then the Go side's session goes, with nothing able to reach it.
		drop(std::mem::take(&mut self.queues));
		for worker in std::mem::take(&mut self.workers) {
			if worker.join().is_err() {
				log::warn!("a JuiceFS worker panicked");
			}
		}
		// SAFETY: the pool is joined, so no call can be in flight.
		unsafe { binding::juicefs_unmount(self.handle) };
	}
}

/// Turns the message `juicefs_mount` returned into an error. A failed mount
/// always returns one, so the fallback is only for a Go side that did not.
fn mount_error(message: usize) -> io::Error {
	if message == 0 {
		return io::Error::other("mounting the JuiceFS volume failed");
	}
	io::Error::other(String::from_utf8_lossy(&take_bytes(message)).into_owned())
}

/// Takes the bytes of a successful reply and releases the handle. A failed call
/// returned no handle, so only the status is looked at first.
fn take(code: c_int, bytes: usize) -> io::Result<Vec<u8>> {
	check(code)?;
	Ok(take_bytes(bytes))
}

/// Copies the bytes a bytes handle holds out into a `Vec`, and releases the
/// handle. The length is read first, so the copy is exactly what the Go side has.
fn take_bytes(handle: usize) -> Vec<u8> {
	// SAFETY: `handle` is a live bytes handle from the Go side, and it is released
	// below, once.
	let len = unsafe { binding::juicefs_bytes_len(handle) };
	let mut out = vec![0u8; len];
	// SAFETY: `out` holds `len` writable bytes, which is what the Go side copies into.
	unsafe { binding::juicefs_bytes_copy(handle, out.as_mut_ptr().cast(), len) };
	// SAFETY: `handle` is the one released here, and it is not used after this.
	unsafe { binding::juicefs_bytes_free(handle) };
	out
}

/// One directory entry as the VFS holds it: the name is the bytes the VFS has,
/// and the attributes travel with it.
#[derive(Clone, Debug)]
pub struct DirEntry {
	pub ino: u64,
	pub attr: Attr,
	pub name: Vec<u8>,
}

fn dir_entry(record: &Dirent) -> DirEntry {
	DirEntry {
		ino: record.ino,
		attr: record.attr,
		name: name_bytes(record),
	}
}

/// The record's name bytes, cut at the array's bound.
fn name_bytes(record: &Dirent) -> Vec<u8> {
	let len = (record.namelen as usize).min(record.name.len());
	record.name[..len]
		.iter()
		.map(|byte| byte.to_ne_bytes()[0])
		.collect()
}

/// A host errno as an/// A host errno as an `io::Error`; the FUSE server translates it for the guest.
fn check(code: c_int) -> io::Result<()> {
	if code == 0 {
		Ok(())
	} else {
		Err(io::Error::from_raw_os_error(code))
	}
}

/// One worker's whole life: take a closure, run it with the session's handle,
/// answer on its channel.
fn serve(handle: usize, jobs: Receiver<Job>) {
	for job in jobs {
		job(handle);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Names are copied out byte for byte, and a name that would overrun the
	/// record is cut at the array's bound.
	#[test]
	fn names_are_bytes_not_text() {
		let mut record = Dirent {
			namelen: 3,
			..Dirent::default()
		};
		for (slot, byte) in record.name.iter_mut().zip(b"a\xffz") {
			*slot = *byte as c_char;
		}
		assert_eq!(name_bytes(&record), b"a\xffz");
		record.namelen = u32::MAX;
		assert_eq!(name_bytes(&record).len(), record.name.len());
	}
}
