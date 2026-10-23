//! One contiguous byte range of guest or host memory, resolved to the pointer a
//! transfer names.
//!
//! A [`Span`] is what a read or a write is handed: it implements
//! [`completion::AsIoVec`], the one thing the runtime asks of a transfer's
//! memory. The range is resolved once, when the span is made, so a range the
//! memory does not back is refused there rather than at submission.

use std::io;
use std::sync::Arc;

use completion::{AsIoVec, IoVec};
use fuse_api::Memory;

/// `len` bytes of a [`Memory`] from `offset`, resolved to a pointer.
///
/// The span holds the memory it resolved against, so the pointer stays valid
/// for as long as the span, and every clone of it, is alive.
#[derive(Clone)]
pub(crate) struct Span {
	/// Never read: holding it keeps the range's memory alive for as long as the
	/// span is.
	_memory: Arc<dyn Memory>,
	resolved: IoVec,
}

impl Span {
	/// `len` bytes of `memory` from `offset`. Refused when the memory does not
	/// back the whole range.
	pub(crate) fn new(memory: Arc<dyn Memory>, offset: usize, len: usize) -> io::Result<Span> {
		let range = memory.resolve(offset, len)?;
		Ok(Span {
			_memory: memory,
			resolved: IoVec {
				ptr: range.ptr,
				len: range.len,
			},
		})
	}
}

// SAFETY: the span holds the memory it resolved against, so the pointer stays
// valid for as long as the span is alive. `Memory` is `Send + Sync`, and the
// bytes are written through `&self` by the transfer, which is the contract the
// runtime's `AsIoVec` states; they are not Rust state that needs exclusive access.
unsafe impl Send for Span {}
// SAFETY: as above.
unsafe impl Sync for Span {}

// SAFETY: as above: the span keeps the memory the range was resolved against.
unsafe impl AsIoVec for Span {
	fn as_iovec(&self) -> IoVec {
		self.resolved
	}
}
