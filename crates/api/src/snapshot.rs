//! Point-in-time [`Snapshot`] lifecycle trait for [`Fuse`](crate::Fuse) and
//! [`Volume`](crate::Volume) back-ends.

use std::io;

use crate::fuse::unsupported;

/// Point-in-time snapshots and writable branches of a [`Fuse`](crate::Fuse) or
/// [`Volume`](crate::Volume) back-end.
///
/// Every method defaults to `ENOSYS`, so a back-end implements only the
/// lifecycle operations its storage supports.
#[allow(async_fn_in_trait)]
pub trait Snapshot: Sized {
	type Id;

	/// Captures the current state as a snapshot.
	async fn snapshot(&self) -> io::Result<Self::Id> {
		Err(unsupported())
	}

	/// Forks a new writable instance from snapshot `id`.
	async fn branch(&self, _id: &Self::Id) -> io::Result<Self> {
		Err(unsupported())
	}

	/// Restores this instance's state to snapshot `id`.
	async fn restore(&self, _id: &Self::Id) -> io::Result<()> {
		Err(unsupported())
	}

	/// Deletes snapshot `id`.
	async fn delete(&self, _id: &Self::Id) -> io::Result<()> {
		Err(unsupported())
	}
}
