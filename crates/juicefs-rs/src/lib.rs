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
//! calls [`Session::open`], which must be a thread no device filter has
//! reached — in the VMM, the monitor thread, before the run seals.
//!
//! A call is a closure: it runs on a pool thread with the session's handle,
//! and its answer comes back through a oneshot channel. That is what lets the
//! safe methods below be ordinary futures, and what keeps the owner of the
//! guest memory (an `Arc<dyn Memory>`) alive for the whole of a blocking read
//! or write even when the future that started it is dropped.

use std::ffi::{CStr, CString, c_char, c_int, c_longlong, c_void};
use std::io;
use std::path::Path;
use std::sync::Once;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use asyncband::oneshot;

mod juicefs;
pub use juicefs::{Volume, reply_len};

/// How many calls into Go run at once. The device serves every chain as its
/// own task, so a handful in flight is what keeps a slow read from holding the
/// ones behind it; more would only add Go `M`s.
const WORKERS: usize = 4;

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
/// The archive the build leaves here has that constructor removed, and
/// [`start_runtime`] makes the call instead, with the arguments the process
/// really has. The name is Go's own, per platform and architecture; the
/// `rt0_*.s` files under Go's `runtime/` define one each.
macro_rules! go_entry {
	($name:literal) => {
		unsafe extern "C" {
			#[link_name = $name]
			fn go_entry(argc: c_int, argv: *mut *mut c_char);
		}
	};
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
go_entry!("_rt0_amd64_linux_lib");
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
go_entry!("_rt0_arm64_linux_lib");
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
go_entry!("_rt0_amd64_darwin_lib");
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
go_entry!("_rt0_arm64_darwin_lib");
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
go_entry!("_rt0_amd64_windows_lib");
#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
go_entry!("_rt0_arm64_windows_lib");

/// `struct fuse_attr`: one inode's attributes, in the layout the guest's
/// kernel reads. The Go side fills it from the VFS's `meta.Attr`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Attr {
	pub ino: u64,
	pub size: u64,
	pub blocks: u64,
	pub atime: u64,
	pub mtime: u64,
	pub ctime: u64,
	pub atimensec: u32,
	pub mtimensec: u32,
	pub ctimensec: u32,
	pub mode: u32,
	pub nlink: u32,
	pub uid: u32,
	pub gid: u32,
	pub rdev: u32,
	pub blksize: u32,
	pub flags: u32,
}

/// A resolved name: the inode and its attributes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Entry {
	pub ino: u64,
	pub attr: Attr,
}

/// The credentials a request carries, filled from the FUSE request header.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Ctx {
	pub uid: u32,
	pub gid: u32,
	pub pid: u32,
}

/// One range of guest memory, as the C ABI takes it.
///
/// The pointer is only sent to the pool thread, which is what makes `read`
/// and `write` unsafe: the caller owns the memory and keeps it alive, through
/// the `owner` argument, for as long as the call runs.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IoVec {
	pub base: *mut c_void,
	pub len: usize,
}

// SAFETY: the pointer names guest memory, not a Rust allocation, and a call
// that carries one also carries an owner that keeps it alive until the pool
// thread returns. The struct itself holds no ownership.
unsafe impl Send for IoVec {}

/// One directory record, as `readdir` reports it. The type tag is not here:
/// it is `(attr.mode & S_IFMT) >> 12`, the kernel's own `DT_*` encoding.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Dirent {
	pub ino: u64,
	pub attr: Attr,
	pub namelen: u32,
	pub name: [c_char; 256],
}

impl Default for Dirent {
	fn default() -> Self {
		Self {
			ino: 0,
			attr: Attr::default(),
			namelen: 0,
			name: [0; 256],
		}
	}
}

/// The `fuse_kstatfs` body a STATFS reply carries.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Statfs {
	pub blocks: u64,
	pub bfree: u64,
	pub bavail: u64,
	pub files: u64,
	pub ffree: u64,
	pub bsize: u32,
	pub namelen: u32,
	pub frsize: u32,
}

/// The value of a GETXATTR: the bytes, or the size a probe must supply.
#[derive(Clone, Debug)]
pub enum Xattr {
	Value(Vec<u8>),
	Size(u32),
}

/// The value of a LISTXATTR: the name list, or the size a probe must supply.
#[derive(Clone, Debug)]
pub enum ListXattr {
	Names(Vec<u8>),
	Size(u32),
}

mod ffi {
	use super::{Attr, Ctx, Dirent, Entry, IoVec, Statfs};
	use std::ffi::{c_char, c_int, c_longlong, c_void};

	unsafe extern "C" {
		/// Mounts one volume. 0 means failure, with `err` set to a message the
		/// caller releases with `juicefs_free`; on success `err` is untouched.
		pub(crate) fn juicefs_mount(
			payload: *const c_char,
			cache_dir: *const c_char,
			attr_ttl_ms: c_longlong,
			entry_ttl_ms: c_longlong,
			err: *mut *mut c_char,
		) -> usize;

		pub(crate) fn juicefs_unmount(handle: usize);

		/// Releases a message `juicefs_mount` returned.
		pub(crate) fn juicefs_free(message: *mut c_char);

		// Every operation returns 0 or a host errno; replies go through the
		// out-parameter.
		pub(crate) fn juicefs_lookup(
			handle: usize,
			ctx: *const Ctx,
			parent: u64,
			name: *const c_char,
			out: *mut Entry,
		) -> c_int;
		pub(crate) fn juicefs_getattr(
			handle: usize,
			ctx: *const Ctx,
			ino: u64,
			opened: c_int,
			out: *mut Attr,
		) -> c_int;
		#[allow(clippy::too_many_arguments)]
		pub(crate) fn juicefs_setattr(
			handle: usize,
			ctx: *const Ctx,
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
			out: *mut Attr,
		) -> c_int;
		pub(crate) fn juicefs_readlink(
			handle: usize,
			ctx: *const Ctx,
			ino: u64,
			buf: *mut c_char,
			capacity: usize,
			length: *mut usize,
		) -> c_int;
		pub(crate) fn juicefs_symlink(
			handle: usize,
			ctx: *const Ctx,
			target: *const c_char,
			parent: u64,
			name: *const c_char,
			out: *mut Entry,
		) -> c_int;
		pub(crate) fn juicefs_mknod(
			handle: usize,
			ctx: *const Ctx,
			parent: u64,
			name: *const c_char,
			mode: u32,
			rdev: u32,
			umask: u32,
			out: *mut Entry,
		) -> c_int;
		pub(crate) fn juicefs_mkdir(
			handle: usize,
			ctx: *const Ctx,
			parent: u64,
			name: *const c_char,
			mode: u32,
			umask: u32,
			out: *mut Entry,
		) -> c_int;
		pub(crate) fn juicefs_unlink(
			handle: usize,
			ctx: *const Ctx,
			parent: u64,
			name: *const c_char,
		) -> c_int;
		pub(crate) fn juicefs_rmdir(
			handle: usize,
			ctx: *const Ctx,
			parent: u64,
			name: *const c_char,
		) -> c_int;
		pub(crate) fn juicefs_rename(
			handle: usize,
			ctx: *const Ctx,
			parent: u64,
			name: *const c_char,
			newparent: u64,
			newname: *const c_char,
			flags: u32,
		) -> c_int;
		pub(crate) fn juicefs_link(
			handle: usize,
			ctx: *const Ctx,
			ino: u64,
			parent: u64,
			name: *const c_char,
			out: *mut Entry,
		) -> c_int;
		pub(crate) fn juicefs_open(
			handle: usize,
			ctx: *const Ctx,
			ino: u64,
			flags: u32,
			fh: *mut u64,
			keep_cache: *mut c_int,
		) -> c_int;
		pub(crate) fn juicefs_create(
			handle: usize,
			ctx: *const Ctx,
			parent: u64,
			name: *const c_char,
			mode: u32,
			umask: u32,
			flags: u32,
			out: *mut Entry,
			fh: *mut u64,
			keep_cache: *mut c_int,
		) -> c_int;
		pub(crate) fn juicefs_read(
			handle: usize,
			ctx: *const Ctx,
			ino: u64,
			fh: u64,
			offset: u64,
			iov: *const IoVec,
			iovcnt: usize,
			n: *mut usize,
		) -> c_int;
		pub(crate) fn juicefs_write(
			handle: usize,
			ctx: *const Ctx,
			ino: u64,
			fh: u64,
			offset: u64,
			iov: *const IoVec,
			iovcnt: usize,
		) -> c_int;
		pub(crate) fn juicefs_flush(
			handle: usize,
			ctx: *const Ctx,
			ino: u64,
			fh: u64,
			lock_owner: u64,
		) -> c_int;
		pub(crate) fn juicefs_fsync(
			handle: usize,
			ctx: *const Ctx,
			ino: u64,
			fh: u64,
			datasync: c_int,
		) -> c_int;
		pub(crate) fn juicefs_release(handle: usize, ctx: *const Ctx, ino: u64, fh: u64) -> c_int;
		pub(crate) fn juicefs_fallocate(
			handle: usize,
			ctx: *const Ctx,
			ino: u64,
			fh: u64,
			mode: u32,
			offset: i64,
			length: i64,
		) -> c_int;
		pub(crate) fn juicefs_statfs(
			handle: usize,
			ctx: *const Ctx,
			ino: u64,
			out: *mut Statfs,
		) -> c_int;
		pub(crate) fn juicefs_access(handle: usize, ctx: *const Ctx, ino: u64, mask: u32) -> c_int;
		pub(crate) fn juicefs_opendir(
			handle: usize,
			ctx: *const Ctx,
			ino: u64,
			flags: u32,
			fh: *mut u64,
		) -> c_int;
		#[allow(clippy::too_many_arguments)]
		pub(crate) fn juicefs_readdir(
			handle: usize,
			ctx: *const Ctx,
			ino: u64,
			fh: u64,
			offset: u64,
			plus: c_int,
			out: *mut Dirent,
			capacity: usize,
			count: *mut usize,
			more: *mut c_int,
		) -> c_int;
		pub(crate) fn juicefs_readdir_offset(
			handle: usize,
			ctx: *const Ctx,
			ino: u64,
			fh: u64,
			offset: u64,
		) -> c_int;
		pub(crate) fn juicefs_releasedir(
			handle: usize,
			ctx: *const Ctx,
			ino: u64,
			fh: u64,
		) -> c_int;
		pub(crate) fn juicefs_getxattr(
			handle: usize,
			ctx: *const Ctx,
			ino: u64,
			name: *const c_char,
			size: u32,
			buf: *mut c_char,
			capacity: usize,
			length: *mut usize,
		) -> c_int;
		pub(crate) fn juicefs_listxattr(
			handle: usize,
			ctx: *const Ctx,
			ino: u64,
			size: u32,
			buf: *mut c_char,
			capacity: usize,
			length: *mut usize,
		) -> c_int;
		pub(crate) fn juicefs_setxattr(
			handle: usize,
			ctx: *const Ctx,
			ino: u64,
			name: *const c_char,
			value: *const c_void,
			len: usize,
			flags: u32,
		) -> c_int;
		pub(crate) fn juicefs_removexattr(
			handle: usize,
			ctx: *const Ctx,
			ino: u64,
			name: *const c_char,
		) -> c_int;
	}
}

/// Starts the Go runtime, once per process, with this process's arguments.
///
/// [`Session::open`] calls this itself, and *when* it does so is what makes
/// that work. Starting the runtime brings up the Go scheduler's threads and
/// installs Go's own handling for `SIGSEGV`, `SIGBUS`, `SIGFPE`, `SIGURG`,
/// `SIGPIPE` and for `SIGINT`/`SIGTERM`, so it has to happen after whatever
/// puts the process in its namespace (`unshare` wants one thread; the runtime
/// is several), before the host installs signal handling of its own (or the
/// runtime takes `SIGINT`/`SIGTERM` back and the process stops shutting down
/// cleanly), and before any thread is confined (every thread the runtime goes
/// on to start inherits the confinement of the one that started it). In the
/// VMM those three sit either side of one call: `Session::open` runs while the
/// devices are being attached, which is after the sandbox is entered and
/// before it is sealed, and well before the run installs its handlers.
pub fn start_runtime() {
	static STARTED: Once = Once::new();
	STARTED.call_once(|| {
		let (argc, block) = startup_block();
		// Go holds these pointers for the life of the process.
		let block = Box::leak(block.into_boxed_slice());
		// SAFETY: the entry calls into the Go runtime, which this crate's
		// contract is that it happens once and first; `block` is the argument
		// vector `runtime.sysargs` walks, laid out as the loader lays it out.
		unsafe { go_entry(argc, block.as_mut_ptr()) }
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

	block.extend(strings(std::env::vars_os().map(|(name, value)| {
		let mut entry = name;
		entry.push("=");
		entry.push(value);
		entry
	})));
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

/// How much room a READLINK reply gets. Longer than any symlink target the
/// VFS accepts, so a host `ERANGE` here means the guest named a target this
/// side cannot express rather than a buffer that is simply too small.
const READLINK_CAPACITY: usize = 4096;

/// A mounted volume and the threads that serve it.
///
/// Dropping it unmounts: the pool's threads see their queues close and end,
/// and the Go-side session is released.
pub struct Session {
	handle: usize,
	/// One queue per worker, and a cursor over them. A single shared queue
	/// would have to be reached into exclusively by each worker, since the
	/// receive that blocks is the one that takes the queue — which would
	/// serialize them.
	queues: Vec<Sender<Job>>,
	next: AtomicUsize,
	workers: Vec<JoinHandle<()>>,
	attr_ttl: Duration,
	entry_ttl: Duration,
}

/// One call in flight: what to run with the session's handle, and the channel
/// the worker answers on.
type Job = Box<dyn FnOnce(usize) + Send>;

impl Session {
	/// Mounts the volume `meta_url` names, caching chunks under `cache_dir`.
	///
	/// Starts the Go runtime if this is the process's first volume, and the
	/// pool with it, so it must run on a thread no device filter has reached
	/// and at a point [`start_runtime`] describes — see this module's
	/// documentation.
	pub fn open(
		meta_url: &str,
		cache_dir: &Path,
		attr_ttl: Duration,
		entry_ttl: Duration,
	) -> io::Result<Session> {
		start_runtime();
		let payload = CString::new(meta_url).map_err(|_| {
			io::Error::new(io::ErrorKind::InvalidInput, "the metadata URL has a NUL")
		})?;
		let cache = CString::new(cache_dir.as_os_str().as_encoded_bytes())
			.map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the cache path has a NUL"))?;

		let mut error: *mut c_char = std::ptr::null_mut();
		// SAFETY: both arguments are valid NUL-terminated strings for the
		// duration of the call, and `error` is a valid place to write one.
		let handle = unsafe {
			ffi::juicefs_mount(
				payload.as_ptr(),
				cache.as_ptr(),
				attr_ttl.as_millis() as c_longlong,
				entry_ttl.as_millis() as c_longlong,
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
					unsafe { ffi::juicefs_unmount(handle) };
					return Err(io::Error::new(
						error.kind(),
						format!("spawn a juicefs worker: {error}"),
					));
				}
			}
		}

		Ok(Session {
			handle,
			queues,
			next: AtomicUsize::new(0),
			workers,
			attr_ttl,
			entry_ttl,
		})
	}

	/// How long the guest may cache an inode's attributes.
	pub fn attr_ttl(&self) -> Duration {
		self.attr_ttl
	}

	/// How long the guest may cache a resolved name.
	pub fn entry_ttl(&self) -> Duration {
		self.entry_ttl
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
			let code =
				unsafe { ffi::juicefs_lookup(handle, &ctx, parent, name.as_ptr(), &mut out) };
			check(code).map(|()| out)
		})
		.await
	}

	pub async fn getattr(&self, ctx: Ctx, ino: u64, opened: bool) -> io::Result<Attr> {
		self.call(move |handle| {
			let mut out = Attr::default();
			// SAFETY: `out` is a valid place for the Go side to write the attr.
			let code =
				unsafe { ffi::juicefs_getattr(handle, &ctx, ino, c_int::from(opened), &mut out) };
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
				ffi::juicefs_setattr(
					handle, &ctx, ino, valid, fh, mode, uid, gid, atime, mtime, atimensec,
					mtimensec, size, &mut out,
				)
			};
			check(code).map(|()| out)
		})
		.await
	}

	pub async fn readlink(&self, ctx: Ctx, ino: u64) -> io::Result<Vec<u8>> {
		self.call(move |handle| {
			let mut buf = vec![0u8; READLINK_CAPACITY];
			let mut length = 0usize;
			// SAFETY: `buf` is a valid buffer of `READLINK_CAPACITY` bytes, and
			// `length` a valid place for the Go side to report what it used.
			let code = unsafe {
				ffi::juicefs_readlink(
					handle,
					&ctx,
					ino,
					buf.as_mut_ptr().cast(),
					buf.len(),
					&mut length,
				)
			};
			check(code).map(|()| {
				buf.truncate(length);
				buf
			})
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
				ffi::juicefs_symlink(
					handle,
					&ctx,
					target.as_ptr(),
					parent,
					name.as_ptr(),
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
				ffi::juicefs_mknod(
					handle,
					&ctx,
					parent,
					name.as_ptr(),
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
				ffi::juicefs_mkdir(handle, &ctx, parent, name.as_ptr(), mode, umask, &mut out)
			};
			check(code).map(|()| out)
		})
		.await
	}

	pub async fn unlink(&self, ctx: Ctx, parent: u64, name: &CStr) -> io::Result<()> {
		let name = name.to_owned();
		self.call(move |handle| {
			// SAFETY: `name` outlives the call.
			check(unsafe { ffi::juicefs_unlink(handle, &ctx, parent, name.as_ptr()) })
		})
		.await
	}

	pub async fn rmdir(&self, ctx: Ctx, parent: u64, name: &CStr) -> io::Result<()> {
		let name = name.to_owned();
		self.call(move |handle| {
			// SAFETY: `name` outlives the call.
			check(unsafe { ffi::juicefs_rmdir(handle, &ctx, parent, name.as_ptr()) })
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
				ffi::juicefs_rename(
					handle,
					&ctx,
					parent,
					name.as_ptr(),
					newparent,
					newname.as_ptr(),
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
				ffi::juicefs_link(handle, &ctx, ino, newparent, newname.as_ptr(), &mut out)
			};
			check(code).map(|()| out)
		})
		.await
	}

	/// Opens a file, returning its handle and whether the guest may keep the
	/// file's pages cached (`FOPEN_KEEP_CACHE`, as opposed to direct I/O).
	///
	/// Named `open_file` because [`Session::open`] is how the volume itself is
	/// mounted.
	pub async fn open_file(&self, ctx: Ctx, ino: u64, flags: u32) -> io::Result<(u64, bool)> {
		self.call(move |handle| {
			let mut fh = 0u64;
			let mut keep_cache = 0 as c_int;
			// SAFETY: both out-parameters are valid for the Go side to write.
			let code =
				unsafe { ffi::juicefs_open(handle, &ctx, ino, flags, &mut fh, &mut keep_cache) };
			check(code).map(|()| (fh, keep_cache != 0))
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
	) -> io::Result<(Entry, u64, bool)> {
		let name = name.to_owned();
		self.call(move |handle| {
			let mut out = Entry::default();
			let mut fh = 0u64;
			let mut keep_cache = 0 as c_int;
			// SAFETY: `name` outlives the call, and every out-parameter is a
			// valid place for the Go side to write.
			let code = unsafe {
				ffi::juicefs_create(
					handle,
					&ctx,
					parent,
					name.as_ptr(),
					mode,
					umask,
					flags,
					&mut out,
					&mut fh,
					&mut keep_cache,
				)
			};
			check(code).map(|()| (out, fh, keep_cache != 0))
		})
		.await
	}

	/// Reads into the ranges `iov` names.
	///
	/// # Safety
	/// Every range must be valid for writes for the whole call, which is why
	/// `owner` is taken: it is moved into the pool job and dropped only after
	/// the blocking call returns, so the memory behind the ranges stays alive
	/// even if this future is dropped first. `iov` itself is copied into the
	/// job.
	pub async unsafe fn read(
		&self,
		ctx: Ctx,
		ino: u64,
		fh: u64,
		offset: u64,
		iov: &[IoVec],
		owner: impl Send + 'static,
	) -> io::Result<usize> {
		let iov = iov.to_vec();
		self.call(move |handle| {
			let mut n = 0usize;
			// SAFETY: the caller's contract makes every range writable for the
			// whole call; `iov` lives in this closure and `n` is valid.
			let code = unsafe {
				ffi::juicefs_read(
					handle,
					&ctx,
					ino,
					fh,
					offset,
					iov.as_ptr(),
					iov.len(),
					&mut n,
				)
			};
			drop(owner);
			check(code).map(|()| n)
		})
		.await
	}

	/// Writes the bytes the ranges `iov` name.
	///
	/// # Safety
	/// As for [`Session::read`]: every range must be valid for reads for the
	/// whole call, and `owner` keeps the memory alive until the pool thread
	/// returns.
	pub async unsafe fn write(
		&self,
		ctx: Ctx,
		ino: u64,
		fh: u64,
		offset: u64,
		iov: &[IoVec],
		owner: impl Send + 'static,
	) -> io::Result<()> {
		let iov = iov.to_vec();
		self.call(move |handle| {
			// SAFETY: the caller's contract makes every range readable for the
			// whole call; `iov` lives in this closure.
			let code = unsafe {
				ffi::juicefs_write(handle, &ctx, ino, fh, offset, iov.as_ptr(), iov.len())
			};
			drop(owner);
			check(code)
		})
		.await
	}

	/// `lock_owner` is the FUSE flush owner; the front-end does not carry one,
	/// so it is passed as zero.
	pub async fn flush(&self, ctx: Ctx, ino: u64, fh: u64, lock_owner: u64) -> io::Result<()> {
		self.call(move |handle| {
			// SAFETY: every argument is a plain value.
			check(unsafe { ffi::juicefs_flush(handle, &ctx, ino, fh, lock_owner) })
		})
		.await
	}

	pub async fn fsync(&self, ctx: Ctx, ino: u64, fh: u64, datasync: bool) -> io::Result<()> {
		self.call(move |handle| {
			// SAFETY: every argument is a plain value.
			check(unsafe { ffi::juicefs_fsync(handle, &ctx, ino, fh, c_int::from(datasync)) })
		})
		.await
	}

	pub async fn release(&self, ctx: Ctx, ino: u64, fh: u64) -> io::Result<()> {
		self.call(move |handle| {
			// SAFETY: every argument is a plain value.
			check(unsafe { ffi::juicefs_release(handle, &ctx, ino, fh) })
		})
		.await
	}

	pub async fn fallocate(
		&self,
		ctx: Ctx,
		ino: u64,
		fh: u64,
		mode: u32,
		offset: i64,
		length: i64,
	) -> io::Result<()> {
		self.call(move |handle| {
			// SAFETY: every argument is a plain value.
			check(unsafe { ffi::juicefs_fallocate(handle, &ctx, ino, fh, mode, offset, length) })
		})
		.await
	}

	pub async fn statfs(&self, ctx: Ctx, ino: u64) -> io::Result<Statfs> {
		self.call(move |handle| {
			let mut out = Statfs::default();
			// SAFETY: `out` is a valid place for the Go side to write.
			let code = unsafe { ffi::juicefs_statfs(handle, &ctx, ino, &mut out) };
			check(code).map(|()| out)
		})
		.await
	}

	pub async fn access(&self, ctx: Ctx, ino: u64, mask: u32) -> io::Result<()> {
		self.call(move |handle| {
			// SAFETY: every argument is a plain value.
			check(unsafe { ffi::juicefs_access(handle, &ctx, ino, mask) })
		})
		.await
	}

	pub async fn opendir(&self, ctx: Ctx, ino: u64, flags: u32) -> io::Result<u64> {
		self.call(move |handle| {
			let mut fh = 0u64;
			// SAFETY: `fh` is a valid place for the Go side to write.
			let code = unsafe { ffi::juicefs_opendir(handle, &ctx, ino, flags, &mut fh) };
			check(code).map(|()| fh)
		})
		.await
	}

	/// Fetches at most `capacity` directory records from `offset`. The second
	/// value is whether the VFS had more entries than fit, so the caller knows
	/// to save its position.
	pub async fn readdir(
		&self,
		ctx: Ctx,
		ino: u64,
		fh: u64,
		offset: u64,
		plus: bool,
		capacity: usize,
	) -> io::Result<(Vec<Dirent>, bool)> {
		self.call(move |handle| {
			let mut out = vec![Dirent::default(); capacity];
			let mut count = 0usize;
			let mut more = 0 as c_int;
			// SAFETY: `out` names `capacity` writable records (a dangling
			// pointer when it is empty, which the Go side never dereferences),
			// and `count`/`more` are valid places to write.
			let code = unsafe {
				ffi::juicefs_readdir(
					handle,
					&ctx,
					ino,
					fh,
					offset,
					c_int::from(plus),
					out.as_mut_ptr(),
					out.len(),
					&mut count,
					&mut more,
				)
			};
			check(code).map(|()| {
				out.truncate(count.min(out.len()));
				(out, more != 0)
			})
		})
		.await
	}

	/// Tells the directory handle where the client stopped after a reply buffer
	/// filled before the batch did.
	pub async fn readdir_offset(&self, ctx: Ctx, ino: u64, fh: u64, offset: u64) -> io::Result<()> {
		self.call(move |handle| {
			// SAFETY: every argument is a plain value.
			check(unsafe { ffi::juicefs_readdir_offset(handle, &ctx, ino, fh, offset) })
		})
		.await
	}

	pub async fn releasedir(&self, ctx: Ctx, ino: u64, fh: u64) -> io::Result<()> {
		self.call(move |handle| {
			// SAFETY: every argument is a plain value.
			check(unsafe { ffi::juicefs_releasedir(handle, &ctx, ino, fh) })
		})
		.await
	}

	pub async fn getxattr(&self, ctx: Ctx, ino: u64, name: &CStr, size: u32) -> io::Result<Xattr> {
		let name = name.to_owned();
		self.call(move |handle| {
			if size == 0 {
				let mut length = 0usize;
				// SAFETY: this is the kernel's size probe: no buffer is passed,
				// and `length` is a valid place for the Go side to write.
				let code = unsafe {
					ffi::juicefs_getxattr(
						handle,
						&ctx,
						ino,
						name.as_ptr(),
						0,
						std::ptr::null_mut(),
						0,
						&mut length,
					)
				};
				return check(code).map(|()| Xattr::Size(length as u32));
			}
			let mut buf = vec![0u8; size as usize];
			let mut length = 0usize;
			// SAFETY: `buf` is `size` writable bytes and `length` is valid.
			let code = unsafe {
				ffi::juicefs_getxattr(
					handle,
					&ctx,
					ino,
					name.as_ptr(),
					size,
					buf.as_mut_ptr().cast(),
					buf.len(),
					&mut length,
				)
			};
			check(code).map(|()| {
				buf.truncate(length.min(buf.len()));
				Xattr::Value(buf)
			})
		})
		.await
	}

	pub async fn listxattr(&self, ctx: Ctx, ino: u64, size: u32) -> io::Result<ListXattr> {
		self.call(move |handle| {
			if size == 0 {
				let mut length = 0usize;
				// SAFETY: this is the kernel's size probe: no buffer is passed,
				// and `length` is a valid place for the Go side to write.
				let code = unsafe {
					ffi::juicefs_listxattr(
						handle,
						&ctx,
						ino,
						0,
						std::ptr::null_mut(),
						0,
						&mut length,
					)
				};
				return check(code).map(|()| ListXattr::Size(length as u32));
			}
			let mut buf = vec![0u8; size as usize];
			let mut length = 0usize;
			// SAFETY: `buf` is `size` writable bytes and `length` is valid.
			let code = unsafe {
				ffi::juicefs_listxattr(
					handle,
					&ctx,
					ino,
					size,
					buf.as_mut_ptr().cast(),
					buf.len(),
					&mut length,
				)
			};
			check(code).map(|()| {
				buf.truncate(length.min(buf.len()));
				ListXattr::Names(buf)
			})
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
				ffi::juicefs_setxattr(
					handle,
					&ctx,
					ino,
					name.as_ptr(),
					value.as_ptr().cast(),
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
			check(unsafe { ffi::juicefs_removexattr(handle, &ctx, ino, name.as_ptr()) })
		})
		.await
	}
}

impl Drop for Session {
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
		unsafe { ffi::juicefs_unmount(self.handle) };
	}
}

/// Takes the message `juicefs_mount` wrote into `error`, and releases it.
fn mount_error(error: *mut c_char) -> io::Error {
	if error.is_null() {
		return io::Error::other("mounting the JuiceFS volume failed");
	}
	// SAFETY: the Go side hands over a NUL-terminated message it allocated,
	// which `juicefs_free` is the matching release for.
	let message = unsafe { CStr::from_ptr(error) }
		.to_string_lossy()
		.into_owned();
	unsafe { ffi::juicefs_free(error) };
	io::Error::other(message)
}

/// A host errno as an `io::Error`; the FUSE server translates it for the guest.
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
