//! The guest memory a zero-copy read or write goes through.
//!
//! A transport hands a back-end [`Extent`](crate::Extent) ranges, not buffers:
//! the bytes live in the guest's address space, which the transport has mapped,
//! and a back-end that can read or fill them in place never copies them. What
//! stands between the two is [`Memory`] — one region of that mapping, which
//! resolves a range into a pointer and length the back-end may use directly.

use std::io;

/// A range of guest memory, resolved to this process's address space.
#[derive(Clone, Copy, Debug)]
pub struct MemoryRange {
	/// Pointer to the first byte of the range.
	pub ptr: *mut u8,
	/// Length of the range in bytes.
	pub len: usize,
}

// SAFETY: a range is a pointer into the region the `Memory` it came from keeps
// alive, and that `Memory` is `Send + Sync`; handing the range to the thread
// that does the I/O adds no aliasing the region does not already allow.
unsafe impl Send for MemoryRange {}

/// Guest memory, as the ranges a zero-copy request or reply names.
///
/// # Safety
/// A range [`resolve`](Memory::resolve) returns must describe memory that stays
/// valid, and stays readable or writable as the caller's operation says, for as
/// long as the `Memory` itself lives. `resolve` must not hand out a range
/// outside the region: a request that leaves it fails with
/// [`InvalidInput`](io::ErrorKind::InvalidInput) instead.
pub unsafe trait Memory: Send + Sync {
	/// The range of `len` bytes at guest address `offset`.
	fn resolve(&self, offset: usize, len: usize) -> io::Result<MemoryRange>;
}
