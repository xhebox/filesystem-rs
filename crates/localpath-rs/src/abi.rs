//! The FUSE protocol values the passthrough back-end names: attribute-valid
//! bits, open flags, capability bits and the root inode. They are the kernel's
//! own numbers, as `include/uapi/linux/fuse.h` spells them.

/// `FUSE_SETATTR` valid bits: which fields of a SETATTR request are set.
pub(crate) const FATTR_MODE: u32 = 1 << 0;
pub(crate) const FATTR_UID: u32 = 1 << 1;
pub(crate) const FATTR_GID: u32 = 1 << 2;
pub(crate) const FATTR_SIZE: u32 = 1 << 3;
pub(crate) const FATTR_ATIME: u32 = 1 << 4;
pub(crate) const FATTR_MTIME: u32 = 1 << 5;
pub(crate) const FATTR_ATIME_NOW: u32 = 1 << 7;
pub(crate) const FATTR_MTIME_NOW: u32 = 1 << 8;
#[cfg(target_os = "linux")]
pub(crate) const FATTR_CTIME: u32 = 1 << 10;

/// `fuse_open_out.open_flags`: direct I/O bypasses the guest's page cache.
pub(crate) const FOPEN_DIRECT_IO: u32 = 1 << 0;

/// `fuse_init_in` / `fuse_init_out` capability bits.
pub(crate) const FUSE_ASYNC_READ: u32 = 1 << 0;
pub(crate) const FUSE_BIG_WRITES: u32 = 1 << 5;
#[cfg(target_os = "linux")]
pub(crate) const FUSE_MAX_PAGES: u32 = 1 << 22;

/// The inode the mounted root directory is served as.
pub(crate) const ROOT_ID: u64 = 1;
