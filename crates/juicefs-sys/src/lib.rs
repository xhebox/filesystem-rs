//! Raw bindings to the filesystem-rs embedded JuiceFS Go archive.
//!
//! This is not an upstream JuiceFS C API. Call [`start_runtime`] before any raw function.

use std::ffi::{CString, c_char, c_int};
use std::sync::Once;

#[allow(non_camel_case_types, non_snake_case, dead_code)]
mod raw;
pub use raw::*;

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

/// Starts the Go runtime, once per process, with this process's arguments.
///
/// The safe wrapper's `Volume::mount` calls this itself, and *when* it does so is what makes
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
///
/// Android is Linux here: Bionic's loader writes the same `/proc/self/auxv`,
/// and Go's `android` runtime reads the vector the same way `linux` does.
#[cfg(any(target_os = "linux", target_os = "android"))]
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
