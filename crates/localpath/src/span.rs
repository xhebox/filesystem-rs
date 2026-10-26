//! One contiguous byte range of guest or host memory, resolved to the pointer a
//! transfer names.
//!
//! A [`Span`] is what a read or a write is handed: it implements
//! [`completion::AsIoVec`], the one thing the runtime asks of a transfer's
//! memory. The range is resolved once, when the span is made, so a range the
//! memory does not back is refused there rather than at submission.

use std::io;
use std::sync::Arc;

use api::{Memory, ZeroCopyReader, ZeroCopyWriter};
use completion::{AsIoVec, IoVec};

/// The engine's failure as an I/O error: a failed call carries the `io::Error`
/// behind it, and a cancelled or stopped one has none.
pub(crate) fn engine_io(error: completion::Error) -> io::Error {
	io::Error::try_from(error).unwrap_or_else(io::Error::other)
}

/// Reads into `buffer` at `offset` until it is full or the file ends, returning
/// the bytes that landed.
///
/// The end of the file is not a failure: the error carries the bytes moved
/// before it, and that short count is what the guest gets.
pub(crate) async fn read_exact<M: AsIoVec>(
	file: &completion::File,
	buffer: M,
	offset: u64,
) -> io::Result<usize> {
	match file.read_exact_at(buffer, offset).await {
		Ok(count) => Ok(count),
		Err(error) => {
			let done = error.done();
			let error = engine_io(error);
			if error.kind() == io::ErrorKind::UnexpectedEof {
				Ok(done)
			} else {
				Err(error)
			}
		}
	}
}

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

/// Reads up to `size` bytes of `file` at `offset` into the reply body.
///
/// One call moves one extent: the engine's span resolves to one pointer, and
/// the reply's ranges are not contiguous. The calls are made in the order the
/// guest named them, so the file is read once and the reply's ranges are filled
/// in that order; the end of the file ends it, and the bytes moved by then are
/// a short read, not a failure.
pub(crate) async fn read_into(
	file: &completion::File,
	out: &dyn ZeroCopyWriter,
	size: usize,
	offset: u64,
) -> io::Result<usize> {
	let memory = out.memory();
	let mut room = size;
	let mut at = offset;
	let mut read = 0;
	for extent in out.extents() {
		let len = extent.len.min(room);
		if len == 0 {
			break;
		}
		let Ok(span) = Span::new(Arc::clone(&memory), extent.offset as usize, len) else {
			break;
		};
		// A call that stops early returns what it did read: the end of the file
		// is such a stop, the reply is a short read, and the range the call did
		// not fill stays unwritten.
		let count = read_exact(file, span, at).await?;
		read += count;
		if count < len {
			break;
		}
		at += len as u64;
		room -= len;
		if room == 0 {
			break;
		}
	}
	Ok(read)
}

/// Writes up to `size` request bytes into `file` at `offset`.
///
/// One call moves one extent, for the reason [`read_into`] gives; a call that
/// writes nothing stops it with the failure the guest must see.
pub(crate) async fn write_into(
	file: &completion::File,
	input: &dyn ZeroCopyReader,
	size: usize,
	offset: u64,
) -> io::Result<usize> {
	let memory = input.memory();
	let mut written = 0;
	let mut at = offset;
	// An empty extent carries no bytes: it is skipped rather than submitted.
	for extent in input
		.extents(size)
		.into_iter()
		.filter(|extent| extent.len != 0)
	{
		let Ok(span) = Span::new(Arc::clone(&memory), extent.offset as usize, extent.len) else {
			break;
		};
		let count = file.write_all_at(span, at).await.map_err(engine_io)?;
		written += count;
		at += count as u64;
	}
	Ok(written)
}
