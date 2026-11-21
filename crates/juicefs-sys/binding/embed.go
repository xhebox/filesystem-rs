// The C surface the VMM links against.
//
// The archive is linked into the VMM's own process, so there is no transport
// here and no FUSE wire: the host's virtio-fs engine parses the guest's FUSE
// messages itself and calls one function per operation. Each takes the fields
// the operation needs and fills in values of its own, and each returns a host
// errno (0 for success) that the Rust side translates to the guest's.
//
// The layouts below are the C ABI. `juicefs_attr` is `meta.Attr`, field for
// field, so the attributes the VFS carries cross unchanged. The rest describe an
// entry, a context and a directory record. Nothing here encodes or decodes a
// FUSE message.
package main

/*
#include <stdint.h>
#include <stddef.h>

typedef struct {
	uint8_t flags;
	uint8_t typ;
	uint16_t mode;
	uint32_t uid;
	uint32_t gid;
	uint32_t rdev;
	int64_t atime;
	int64_t mtime;
	int64_t ctime;
	uint32_t atimensec;
	uint32_t mtimensec;
	uint32_t ctimensec;
	uint32_t nlink;
	uint64_t length;
	uint64_t parent;
	uint8_t full;
	uint8_t keep_cache;
	uint32_t access_acl;
	uint32_t default_acl;
	uint8_t tier;
} juicefs_attr;

typedef struct {
	uint64_t ino;
	juicefs_attr attr;
} juicefs_entry;

typedef struct {
	uint32_t uid;
	uint32_t gid;
	uint32_t pid;
} juicefs_ctx;

typedef struct {
	uint64_t ino;
	juicefs_attr attr;
	uint32_t namelen;
	char name[256];
} juicefs_dirent;

typedef struct {
	uint64_t total;
	uint64_t avail;
	uint64_t files;
	uint64_t favail;
} juicefs_statvfs;

typedef struct {
	const char *cache_dir;
	const char *subdir;

	uint64_t open_cache_ns;
	uint64_t open_cache_limit;
	uint64_t heartbeat_ns;
	uint64_t skip_dir_mtime_ns;
	uint64_t buffer_size;
	uint64_t max_readahead;
	uint64_t cache_size;
	uint64_t cache_items;
	uint64_t cache_scan_interval_ns;
	uint64_t cache_expire_ns;
	uint64_t upload_limit_bps;
	uint64_t download_limit_bps;
	uint64_t get_timeout_ns;
	uint64_t put_timeout_ns;
	uint64_t backup_meta_ns;

	uint32_t io_retries;
	uint32_t max_deletes;
	uint32_t skip_dir_nlink;
	uint32_t prefetch;
	uint32_t max_uploads;
	uint32_t max_downloads;

	uint16_t free_space_permille;

	uint8_t read_only;
	uint8_t hide_internal;
	uint8_t no_bgjob;
	uint8_t fast_statfs;
	uint8_t sort_dir;
	uint8_t cache_full_block;
	uint8_t cache_checksum;
	uint8_t cache_eviction;
	uint8_t writeback;
	uint8_t backup_skip_trash;
} juicefs_mount_options;

typedef void (*juicefs_task_fn)(void *arg);

static inline void juicefs_call_task(juicefs_task_fn fn, void *arg) {
	fn(arg);
}
*/
import "C"

import (
	"path"
	"runtime/cgo"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/object"
	"github.com/juicedata/juicefs/pkg/vfs"
)

const (
	dispatchWorkers   = 64
	dispatchQueueSize = 1024
	blockingLockLimit = 64
)

type dispatchTask struct {
	fn  C.juicefs_task_fn
	arg unsafe.Pointer
}

// One mounted volume. The VFS tracks its own inodes and handles.
type session struct {
	v       *vfs.VFS
	blob    object.ObjectStorage
	mu      sync.RWMutex
	closing atomic.Bool
	jobs    chan dispatchTask
	lockSem chan struct{}
	wg      sync.WaitGroup
}

func newSession(v *vfs.VFS, blob object.ObjectStorage) *session {
	s := &session{
		v:       v,
		blob:    blob,
		jobs:    make(chan dispatchTask, dispatchQueueSize),
		lockSem: make(chan struct{}, blockingLockLimit),
	}
	s.wg.Add(dispatchWorkers)
	for range dispatchWorkers {
		go func() {
			defer s.wg.Done()
			for t := range s.jobs {
				C.juicefs_call_task(t.fn, t.arg)
			}
		}()
	}
	return s
}

// juicefs_format formats or initializes one volume at `payload`. Returns 0 on
// success; on failure returns a non-zero errno and writes the error message
// handle into `err`.
//
//export juicefs_format
func juicefs_format(payload, name, storage, bucket, accessKey, secretKey, sessionToken *C.char, force C.int, err *C.uintptr_t) C.int {
	fmtErr := formatVolume(
		C.GoString(payload),
		C.GoString(name),
		C.GoString(storage),
		C.GoString(bucket),
		C.GoString(accessKey),
		C.GoString(secretKey),
		C.GoString(sessionToken),
		force != 0,
	)
	if fmtErr != nil {
		*err = newBytes([]byte(fmtErr.Error()))
		return C.int(syscall.EIO)
	}
	return 0
}

// juicefs_mount mounts one volume and returns its handle. A handle of 0 means
// failure, and `err` is then a bytes handle holding the message, which the
// caller reads with the `juicefs_bytes_*` functions and releases. Options and
// their strings are borrowed only for the call; NULL selects defaults.
//
//export juicefs_mount
func juicefs_mount(payload *C.char, options *C.juicefs_mount_options, err *C.uintptr_t) C.uintptr_t {
	opts := defaultMountOptions()
	if options != nil {
		opts = mountOptions{
			cacheDir:          C.GoString(options.cache_dir),
			subdir:            C.GoString(options.subdir),
			readOnly:          options.read_only != 0,
			hideInternal:      options.hide_internal != 0,
			noBGJob:           options.no_bgjob != 0,
			ioRetries:         int(options.io_retries),
			maxDeletes:        int(options.max_deletes),
			openCache:         time.Duration(options.open_cache_ns),
			openCacheLimit:    uint64(options.open_cache_limit),
			heartbeat:         time.Duration(options.heartbeat_ns),
			skipDirNlink:      int(options.skip_dir_nlink),
			skipDirMtime:      time.Duration(options.skip_dir_mtime_ns),
			fastStatfs:        options.fast_statfs != 0,
			sortDir:           options.sort_dir != 0,
			bufferSize:        uint64(options.buffer_size),
			maxReadahead:      int(options.max_readahead),
			prefetch:          int(options.prefetch),
			cacheSize:         uint64(options.cache_size),
			cacheItems:        int64(options.cache_items),
			freeSpacePermille: uint16(options.free_space_permille),
			cacheFullBlock:    options.cache_full_block != 0,
			cacheChecksum:     uint8(options.cache_checksum),
			cacheEviction:     uint8(options.cache_eviction),
			cacheScanInterval: time.Duration(options.cache_scan_interval_ns),
			cacheExpire:       time.Duration(options.cache_expire_ns),
			writeback:         options.writeback != 0,
			maxUploads:        int(options.max_uploads),
			maxDownloads:      int(options.max_downloads),
			uploadLimitBps:    int64(options.upload_limit_bps),
			downloadLimitBps:  int64(options.download_limit_bps),
			getTimeout:        time.Duration(options.get_timeout_ns),
			putTimeout:        time.Duration(options.put_timeout_ns),
			backupMeta:        time.Duration(options.backup_meta_ns),
			backupSkipTrash:   options.backup_skip_trash != 0,
		}
	}
	v, blob, mountErr := buildVFS(C.GoString(payload), opts)
	if mountErr != nil {
		*err = newBytes([]byte(mountErr.Error()))
		return 0
	}
	return C.uintptr_t(cgo.NewHandle(newSession(v, blob)))
}

// juicefs_dispatch schedules `fn(arg)` onto the session's bounded Go goroutine
// pool without blocking the caller. Returns 0 when queued, `EAGAIN` when the
// bounded queue or blocking-lock quota is full, or `ESHUTDOWN` when unmounting.
//
//export juicefs_dispatch
func juicefs_dispatch(h C.uintptr_t, fn C.juicefs_task_fn, arg unsafe.Pointer, isBlockingLock C.int) C.int {
	s := lookup(h)
	if s == nil || fn == nil {
		return C.int(syscall.EINVAL)
	}
	s.mu.RLock()
	if s.closing.Load() {
		s.mu.RUnlock()
		return C.int(syscall.ESHUTDOWN)
	}
	if isBlockingLock != 0 {
		select {
		case s.lockSem <- struct{}{}:
			s.wg.Add(1)
			s.mu.RUnlock()
			go func() {
				defer s.wg.Done()
				defer func() { <-s.lockSem }()
				C.juicefs_call_task(fn, arg)
			}()
			return 0
		default:
			s.mu.RUnlock()
			return C.int(syscall.EAGAIN)
		}
	}
	select {
	case s.jobs <- dispatchTask{fn: fn, arg: arg}:
		s.mu.RUnlock()
		return 0
	default:
		s.mu.RUnlock()
		return C.int(syscall.EAGAIN)
	}
}

// juicefs_unmount drops one volume's session. The handle is not reused.
//
//export juicefs_unmount
func juicefs_unmount(h C.uintptr_t) {
	if h == 0 {
		return
	}
	if s := lookup(h); s != nil {
		s.mu.Lock()
		if !s.closing.Swap(true) {
			close(s.jobs)
		}
		s.mu.Unlock()
		s.wg.Wait()
		if s.v != nil {
			_ = s.v.FlushAll("")
			_ = s.v.Meta.CloseSession()
			_ = s.v.Meta.Shutdown()
		}
		if s.blob != nil {
			object.Shutdown(s.blob)
		}
	}
	cgo.Handle(h).Delete()
}

// lookup returns the session behind a handle, or nil for the null handle.
func lookup(h C.uintptr_t) *session {
	if h == 0 {
		return nil
	}
	s, _ := cgo.Handle(h).Value().(*session)
	return s
}

// recoverErr turns a panic into EIO. The request comes from a guest, and a
// panic must not take the VMM and every guest on it down with it.
func recoverErr(ret *C.int) {
	if panicked := recover(); panicked != nil {
		*ret = C.int(syscall.EIO)
	}
}

// guard runs one operation on the session behind `h`. It is what every export
// shares: the handle lookup, EBADF for a handle that is not a live session, and
// the panic-to-EIO recovery of `recoverErr`.
func guard(h C.uintptr_t, operation func(s *session) C.int) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	return operation(s)
}

// context is the credentials a request carries.
func (s *session) context(ctx *C.juicefs_ctx) vfs.LogContext {
	return vfs.NewLogContext(meta.NewContext(uint32(ctx.pid), uint32(ctx.uid), []uint32{uint32(ctx.gid)}))
}

// attr copies a meta attribute into the C layout, field for field. The type and
// the permission bits stay apart, as meta keeps them: combining them is the
// FUSE layer's business.
func attr(a *meta.Attr) C.juicefs_attr {
	return C.juicefs_attr{
		flags:       C.uint8_t(a.Flags),
		typ:         C.uint8_t(a.Typ),
		mode:        C.uint16_t(a.Mode),
		uid:         C.uint32_t(a.Uid),
		gid:         C.uint32_t(a.Gid),
		rdev:        C.uint32_t(a.Rdev),
		atime:       C.int64_t(a.Atime),
		mtime:       C.int64_t(a.Mtime),
		ctime:       C.int64_t(a.Ctime),
		atimensec:   C.uint32_t(a.Atimensec),
		mtimensec:   C.uint32_t(a.Mtimensec),
		ctimensec:   C.uint32_t(a.Ctimensec),
		nlink:       C.uint32_t(a.Nlink),
		length:      C.uint64_t(a.Length),
		parent:      C.uint64_t(a.Parent),
		full:        boolByte(a.Full),
		keep_cache:  boolByte(a.KeepCache),
		access_acl:  C.uint32_t(a.AccessACL),
		default_acl: C.uint32_t(a.DefaultACL),
		tier:        C.uint8_t(a.Tier),
	}
}

func boolByte(b bool) C.uint8_t {
	if b {
		return 1
	}
	return 0
}

// entry is a name's inode plus its attributes.
func entry(e *meta.Entry) C.juicefs_entry {
	return C.juicefs_entry{ino: C.uint64_t(e.Inode), attr: attr(e.Attr)}
}

// entryReply is the reply every operation that resolves a name gives: the VFS's
// entry as it is.
func entryReply(e *meta.Entry, out *C.juicefs_entry) C.int {
	*out = entry(e)
	return 0
}

//export juicefs_lookup
func juicefs_lookup(h C.uintptr_t, ctx *C.juicefs_ctx, parent C.uint64_t, name *C.char, out *C.juicefs_entry) C.int {
	return guard(h, func(s *session) C.int {
		c, ino, n := s.context(ctx), meta.Ino(parent), C.GoString(name)
		if s.v.Conf.Subdir != "" && ino == meta.RootInode && n == meta.TrashName {
			// Bypass the virtual trash entry; a real file with this name can
			// still exist in the mounted directory.
			var e meta.Entry
			e.Attr = new(meta.Attr)
			if err := s.v.Meta.Lookup(c, ino, n, &e.Inode, e.Attr, true); err != 0 {
				return C.int(err)
			}
			return entryReply(&e, out)
		}
		e, err := s.v.Lookup(c, ino, n)
		if err != 0 {
			return C.int(err)
		}
		return entryReply(e, out)
	})
}

//export juicefs_getattr
func juicefs_getattr(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, opened C.int, out *C.juicefs_attr) C.int {
	return guard(h, func(s *session) C.int {
		e, err := s.v.GetAttr(s.context(ctx), meta.Ino(ino), uint8(opened))
		if err != 0 {
			return C.int(err)
		}
		*out = attr(e.Attr)
		return 0
	})
}

// juicefs_setattr sets the attributes `valid` names, as the VFS takes them.
//
//export juicefs_setattr
func juicefs_setattr(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, valid C.uint32_t, fh C.uint64_t,
	mode, uid, gid C.uint32_t, atime, mtime C.int64_t, atimensec, mtimensec C.uint32_t,
	size C.uint64_t, out *C.juicefs_attr) C.int {
	return guard(h, func(s *session) C.int {
		e, err := opSetAttr(s.v, s.context(ctx), meta.Ino(ino), int(valid), uint64(fh),
			uint32(mode), uint32(uid), uint32(gid),
			int64(atime), int64(mtime), uint32(atimensec), uint32(mtimensec), uint64(size))
		if err != 0 {
			return C.int(err)
		}
		*out = attr(e.Attr)
		return 0
	})
}

//export juicefs_symlink
func juicefs_symlink(h C.uintptr_t, ctx *C.juicefs_ctx, target *C.char, parent C.uint64_t, name *C.char, out *C.juicefs_entry) C.int {
	return guard(h, func(s *session) C.int {
		e, err := s.v.Symlink(s.context(ctx), C.GoString(target), meta.Ino(parent), C.GoString(name))
		if err != 0 {
			return C.int(err)
		}
		return entryReply(e, out)
	})
}

//export juicefs_mknod
func juicefs_mknod(h C.uintptr_t, ctx *C.juicefs_ctx, parent C.uint64_t, name *C.char, mode, rdev, umask C.uint32_t, out *C.juicefs_entry) C.int {
	return guard(h, func(s *session) C.int {
		e, err := s.v.Mknod(s.context(ctx), meta.Ino(parent), C.GoString(name), uint16(mode), uint16(umask), uint32(rdev))
		if err != 0 {
			return C.int(err)
		}
		return entryReply(e, out)
	})
}

//export juicefs_mkdir
func juicefs_mkdir(h C.uintptr_t, ctx *C.juicefs_ctx, parent C.uint64_t, name *C.char, mode, umask C.uint32_t, out *C.juicefs_entry) C.int {
	return guard(h, func(s *session) C.int {
		e, err := s.v.Mkdir(s.context(ctx), meta.Ino(parent), C.GoString(name), uint16(mode), uint16(umask))
		if err != 0 {
			return C.int(err)
		}
		return entryReply(e, out)
	})
}

//export juicefs_unlink
func juicefs_unlink(h C.uintptr_t, ctx *C.juicefs_ctx, parent C.uint64_t, name *C.char) C.int {
	return guard(h, func(s *session) C.int {
		return C.int(s.v.Unlink(s.context(ctx), meta.Ino(parent), C.GoString(name)))
	})
}

//export juicefs_rmdir
func juicefs_rmdir(h C.uintptr_t, ctx *C.juicefs_ctx, parent C.uint64_t, name *C.char) C.int {
	return guard(h, func(s *session) C.int {
		return C.int(s.v.Rmdir(s.context(ctx), meta.Ino(parent), C.GoString(name)))
	})
}

//export juicefs_rename
func juicefs_rename(h C.uintptr_t, ctx *C.juicefs_ctx, parent C.uint64_t, name *C.char,
	newparent C.uint64_t, newname *C.char, flags C.uint32_t) C.int {
	return guard(h, func(s *session) C.int {
		return C.int(s.v.Rename(s.context(ctx), meta.Ino(parent), C.GoString(name),
			meta.Ino(newparent), C.GoString(newname), uint32(flags)))
	})
}

//export juicefs_link
func juicefs_link(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, parent C.uint64_t, name *C.char, out *C.juicefs_entry) C.int {
	return guard(h, func(s *session) C.int {
		e, err := s.v.Link(s.context(ctx), meta.Ino(ino), meta.Ino(parent), C.GoString(name))
		if err != 0 {
			return C.int(err)
		}
		return entryReply(e, out)
	})
}

// juicefs_open opens a file. `out` gets the entry the VFS returns, with the
// attributes that say whether the file's pages may stay cached.
//
//export juicefs_open
func juicefs_open(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, flags C.uint32_t, out *C.juicefs_entry, fh *C.uint64_t) C.int {
	return guard(h, func(s *session) C.int {
		e, handle, err := s.v.Open(s.context(ctx), meta.Ino(ino), uint32(flags))
		if err != 0 {
			return C.int(err)
		}
		*fh = C.uint64_t(handle)
		*out = entry(e)
		return 0
	})
}

//export juicefs_create
func juicefs_create(h C.uintptr_t, ctx *C.juicefs_ctx, parent C.uint64_t, name *C.char,
	mode, umask, flags C.uint32_t, out *C.juicefs_entry, fh *C.uint64_t) C.int {
	return guard(h, func(s *session) C.int {
		e, handle, err := s.v.Create(s.context(ctx), meta.Ino(parent), C.GoString(name),
			uint16(mode), uint16(umask), uint32(flags))
		if err != 0 {
			return C.int(err)
		}
		*fh = C.uint64_t(handle)
		return entryReply(e, out)
	})
}

// juicefs_read reads up to `size` bytes at `off` into `buf`, and reports how
// many it read. The VFS copies out of its cache and keeps no reference to the
// buffer, so `buf` can be the caller's own memory.
//
//export juicefs_read
func juicefs_read(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh C.uint64_t, off C.uint64_t,
	buf *C.char, size C.size_t, n *C.size_t) C.int {
	return guard(h, func(s *session) C.int {
		got, err := s.v.Read(s.context(ctx), meta.Ino(ino), unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(size)), uint64(off), uint64(fh))
		*n = C.size_t(got)
		return C.int(err)
	})
}

// juicefs_write writes `size` bytes from `buf` at `off`. The VFS may keep the
// slice it is given past the call, so the bytes are copied into Go memory
// first; `buf` is only read during the call.
//
//export juicefs_write
func juicefs_write(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh C.uint64_t, off C.uint64_t,
	buf *C.char, size C.size_t) C.int {
	return guard(h, func(s *session) C.int {
		data := make([]byte, int(size))
		copy(data, unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(size)))
		return C.int(s.v.Write(s.context(ctx), meta.Ino(ino), data, uint64(off), uint64(fh)))
	})
}

//export juicefs_flush
func juicefs_flush(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh, lockOwner C.uint64_t) C.int {
	return guard(h, func(s *session) C.int {
		return C.int(s.v.Flush(s.context(ctx), meta.Ino(ino), uint64(fh), uint64(lockOwner)))
	})
}

//export juicefs_fsync
func juicefs_fsync(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh C.uint64_t, datasync C.int) C.int {
	return guard(h, func(s *session) C.int {
		return C.int(s.v.Fsync(s.context(ctx), meta.Ino(ino), int(datasync), uint64(fh)))
	})
}

//export juicefs_release
func juicefs_release(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh C.uint64_t) C.int {
	return guard(h, func(s *session) C.int {
		s.v.Release(s.context(ctx), meta.Ino(ino), uint64(fh))
		return 0
	})
}

// juicefs_fallocate preallocates or punches a range, as the VFS does.
//
//export juicefs_fallocate
func juicefs_fallocate(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh C.uint64_t, mode C.uint8_t,
	off, length C.int64_t) C.int {
	return guard(h, func(s *session) C.int {
		return C.int(s.v.Fallocate(s.context(ctx), meta.Ino(ino), uint8(mode), int64(off), int64(length), uint64(fh)))
	})
}

// juicefs_statfs returns the VFS's totals for the volume.
//
//export juicefs_statfs
func juicefs_statfs(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, out *C.juicefs_statvfs) C.int {
	return guard(h, func(s *session) C.int {
		total, avail, files, favail, err := opStatFS(s.v, s.context(ctx), meta.Ino(ino))
		if err != 0 {
			return C.int(err)
		}
		*out = C.juicefs_statvfs{
			total:  C.uint64_t(total),
			avail:  C.uint64_t(avail),
			files:  C.uint64_t(files),
			favail: C.uint64_t(favail),
		}
		return 0
	})
}

//export juicefs_access
func juicefs_access(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, mask C.uint32_t) C.int {
	return guard(h, func(s *session) C.int {
		return C.int(opAccess(s.v, s.context(ctx), meta.Ino(ino), int(mask)))
	})
}

//export juicefs_opendir
func juicefs_opendir(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, flags C.uint32_t, fh *C.uint64_t) C.int {
	return guard(h, func(s *session) C.int {
		handle, err := s.v.Opendir(s.context(ctx), meta.Ino(ino), uint32(flags))
		if err != 0 {
			return C.int(err)
		}
		*fh = C.uint64_t(handle)
		return 0
	})
}

//export juicefs_releasedir
func juicefs_releasedir(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh C.uint64_t) C.int {
	return guard(h, func(s *session) C.int {
		s.v.Releasedir(s.context(ctx), meta.Ino(ino), uint64(fh))
		return 0
	})
}

//export juicefs_setxattr
func juicefs_setxattr(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, name *C.char,
	value unsafe.Pointer, length C.size_t, flags C.uint32_t) C.int {
	return guard(h, func(s *session) C.int {
		var data []byte
		if length > 0 {
			data = make([]byte, int(length))
			copy(data, unsafe.Slice((*byte)(value), int(length)))
		}
		return C.int(s.v.SetXattr(s.context(ctx), meta.Ino(ino), C.GoString(name), data, uint32(flags)))
	})
}

//export juicefs_removexattr
func juicefs_removexattr(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, name *C.char) C.int {
	return guard(h, func(s *session) C.int {
		return C.int(s.v.RemoveXattr(s.context(ctx), meta.Ino(ino), C.GoString(name)))
	})
}

// juicefs_truncate sets a file's length. `out` gets the attributes the metadata
// engine reports after the change.
//
//export juicefs_truncate
func juicefs_truncate(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, size C.longlong, fh C.uint64_t, out *C.juicefs_attr) C.int {
	return guard(h, func(s *session) C.int {
		var a meta.Attr
		if err := s.v.Truncate(s.context(ctx), meta.Ino(ino), int64(size), uint64(fh), &a); err != 0 {
			return C.int(err)
		}
		*out = attr(&a)
		return 0
	})
}

// juicefs_copy_file_range copies `size` bytes between two open files and
// reports how many were copied.
//
//export juicefs_copy_file_range
func juicefs_copy_file_range(h C.uintptr_t, ctx *C.juicefs_ctx, inoIn, fhIn, offIn, inoOut, fhOut, offOut, size C.uint64_t, flags C.uint32_t, copied *C.uint64_t) C.int {
	return guard(h, func(s *session) C.int {
		n, err := s.v.CopyFileRange(s.context(ctx), meta.Ino(inoIn), uint64(fhIn), uint64(offIn),
			meta.Ino(inoOut), uint64(fhOut), uint64(offOut), uint64(size), uint32(flags))
		*copied = C.uint64_t(n)
		return C.int(err)
	})
}

// juicefs_flush_all writes out the buffered data under `path`. A failure returns
// nonzero and sets `message`, a bytes handle the caller reads and releases.
//
//export juicefs_flush_all
func juicefs_flush_all(h C.uintptr_t, path *C.char, message *C.uintptr_t) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		*message = newBytes([]byte("the volume is not mounted"))
		return 1
	}
	if err := s.v.FlushAll(C.GoString(path)); err != nil {
		*message = newBytes([]byte(err.Error()))
		return 1
	}
	return 0
}

// juicefs_modified_since reports whether `ino` changed after `start`, given in
// Unix nanoseconds. A panic reads as unmodified, the answer that changes least.
//
//export juicefs_modified_since
func juicefs_modified_since(h C.uintptr_t, ino C.uint64_t, start C.longlong) (ret C.int) {
	defer func() {
		if recover() != nil {
			ret = 0
		}
	}()
	s := lookup(h)
	if s == nil {
		return 0
	}
	if s.v.ModifiedSince(meta.Ino(ino), time.Unix(0, int64(start))) {
		return 1
	}
	return 0
}

// juicefs_release_handler drops one open handle's state in the VFS.
//
//export juicefs_release_handler
func juicefs_release_handler(h C.uintptr_t, ino, fh C.uint64_t) {
	s := lookup(h)
	if s == nil {
		return
	}
	s.v.ReleaseHandler(meta.Ino(ino), uint64(fh))
}

// juicefs_update_length refreshes an attribute's length from the chunk store,
// as the VFS does before it caches one. `length` is read and written back.
//
//export juicefs_update_length
func juicefs_update_length(h C.uintptr_t, ino C.uint64_t, full C.int, typ C.uint8_t, length *C.uint64_t) {
	s := lookup(h)
	if s == nil {
		return
	}
	a := meta.Attr{Full: full != 0, Typ: uint8(typ), Length: uint64(*length)}
	s.v.UpdateLength(meta.Ino(ino), &a)
	*length = C.uint64_t(a.Length)
}

// juicefs_getlk tests for a conflicting POSIX lock. `start`, `length`, `typ`
// and `pid` are read for the query and written with the conflict, if any.
//
//export juicefs_getlk
func juicefs_getlk(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh, owner C.uint64_t, start, length *C.uint64_t, typ, pid *C.uint32_t) C.int {
	return guard(h, func(s *session) C.int {
		return C.int(opGetlk(s.v, s.context(ctx), meta.Ino(ino), uint64(fh), uint64(owner),
			(*uint64)(unsafe.Pointer(start)), (*uint64)(unsafe.Pointer(length)),
			(*uint32)(unsafe.Pointer(typ)), (*uint32)(unsafe.Pointer(pid))))
	})
}

// juicefs_setlk takes or releases a POSIX lock; `block` waits for a conflict.
//
//export juicefs_setlk
func juicefs_setlk(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh, owner, start, end C.uint64_t, typ, pid C.uint32_t, block C.int) C.int {
	return guard(h, func(s *session) C.int {
		return C.int(opSetlk(s.v, s.context(ctx), meta.Ino(ino), uint64(fh), uint64(owner),
			uint64(start), uint64(end), uint32(typ), uint32(pid), block != 0))
	})
}

// juicefs_flock takes or releases a BSD lock on the whole file; `block` waits
// for a conflict.
//
//export juicefs_flock
func juicefs_flock(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh, owner C.uint64_t, typ C.uint32_t, block C.int) C.int {
	return guard(h, func(s *session) C.int {
		return C.int(opFlock(s.v, s.context(ctx), meta.Ino(ino), uint64(fh), uint64(owner), uint32(typ), block != 0))
	})
}

// juicefs_ioctl runs one ioctl. `in` and `out` are guest buffers of the given
// lengths; the VFS fills `out` in place.
//
//export juicefs_ioctl
func juicefs_ioctl(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, cmd C.uint32_t, arg C.uint64_t,
	in unsafe.Pointer, inLen C.size_t, out unsafe.Pointer, outLen C.size_t) C.int {
	return guard(h, func(s *session) C.int {
		var bufIn, bufOut []byte
		if inLen > 0 {
			bufIn = unsafe.Slice((*byte)(in), int(inLen))
		}
		if outLen > 0 {
			bufOut = unsafe.Slice((*byte)(out), int(outLen))
		}
		return C.int(opIoctl(s.v, s.context(ctx), meta.Ino(ino), uint32(cmd), uint64(arg), bufIn, bufOut))
	})
}

// Replies that a fixed C struct cannot carry travel as handles to Go memory.
// The caller reads a handle with the accessors below and releases it with the
// matching free. Nothing is allocated in C, so there is nothing to free twice or
// to leak on one side only.

// newBytes hands `data` out as a bytes handle.
func newBytes(data []byte) C.uintptr_t {
	return C.uintptr_t(cgo.NewHandle(data))
}

// juicefs_bytes_len is the length of a bytes handle.
//
//export juicefs_bytes_len
func juicefs_bytes_len(b C.uintptr_t) C.size_t {
	return C.size_t(len(cgo.Handle(b).Value().([]byte)))
}

// juicefs_bytes_copy copies up to `capacity` bytes of a bytes handle into `buf`.
//
//export juicefs_bytes_copy
func juicefs_bytes_copy(b C.uintptr_t, buf *C.char, capacity C.size_t) {
	data := cgo.Handle(b).Value().([]byte)
	n := min(len(data), int(capacity))
	copy(unsafe.Slice((*byte)(unsafe.Pointer(buf)), n), data)
}

// juicefs_bytes_free releases a bytes handle.
//
//export juicefs_bytes_free
func juicefs_bytes_free(b C.uintptr_t) {
	cgo.Handle(b).Delete()
}

// juicefs_readlink returns a symbolic link's target, as a bytes handle.
//
//export juicefs_readlink
func juicefs_readlink(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, out *C.uintptr_t) C.int {
	return guard(h, func(s *session) C.int {
		path, err := s.v.Readlink(s.context(ctx), meta.Ino(ino))
		if err != 0 {
			return C.int(err)
		}
		*out = newBytes(path)
		return 0
	})
}

// juicefs_getxattr returns one extended attribute's value, as a bytes handle.
// `size` is the VFS's size argument: a non-zero size the value does not fit in
// is ERANGE.
//
//export juicefs_getxattr
func juicefs_getxattr(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, name *C.char, size C.uint32_t,
	out *C.uintptr_t) C.int {
	return guard(h, func(s *session) C.int {
		value, err := s.v.GetXattr(s.context(ctx), meta.Ino(ino), C.GoString(name), uint32(size))
		if err != 0 {
			return C.int(err)
		}
		*out = newBytes(value)
		return 0
	})
}

// juicefs_listxattr returns the attribute names of a file, as a bytes handle.
// `size` is the VFS's size argument, as for getxattr.
//
//export juicefs_listxattr
func juicefs_listxattr(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, size C.uint32_t, out *C.uintptr_t) C.int {
	return guard(h, func(s *session) C.int {
		data, err := s.v.ListXattr(s.context(ctx), meta.Ino(ino), int(size))
		if err != 0 {
			return C.int(err)
		}
		*out = newBytes(data)
		return 0
	})
}

// juicefs_readdir lists a directory from `off`, with the VFS's `size` and
// `plus`. The entries come back as a dirents handle in `list`, `count` of them,
// read with `juicefs_dirent_at` and released with `juicefs_dirents_free`. `read_at`
// is when the VFS read the directory, in Unix nanoseconds.
//
//export juicefs_readdir
func juicefs_readdir(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh C.uint64_t, off C.uint64_t, size C.uint32_t,
	plus C.int, list *C.uintptr_t, count *C.size_t, readAt *C.int64_t) C.int {
	return guard(h, func(s *session) C.int {
		entries, at, err := s.v.Readdir(s.context(ctx), meta.Ino(ino), uint32(size), int(off), uint64(fh), plus != 0)
		if err != 0 {
			return C.int(err)
		}
		*list = C.uintptr_t(cgo.NewHandle(entries))
		*count = C.size_t(len(entries))
		*readAt = C.int64_t(at.UnixNano())
		return 0
	})
}

// juicefs_dirent_at fills `out` with the i-th record of a dirents handle. A
// name longer than a record's fixed array cannot be written into it, and the
// VFS never names one that long: that is ENAMETOOLONG.
//
//export juicefs_dirent_at
func juicefs_dirent_at(list C.uintptr_t, i C.size_t, out *C.juicefs_dirent) (ret C.int) {
	defer recoverErr(&ret)
	e := cgo.Handle(list).Value().([]*meta.Entry)[i]
	if len(e.Name) > len(out.name) {
		return C.int(syscall.ENAMETOOLONG)
	}
	*out = C.juicefs_dirent{
		ino:     C.uint64_t(e.Inode),
		attr:    attr(e.Attr),
		namelen: C.uint32_t(len(e.Name)),
	}
	for j, b := range e.Name {
		out.name[j] = C.char(b)
	}
	return 0
}

// juicefs_dirents_free releases a dirents handle.
//
//export juicefs_dirents_free
func juicefs_dirents_free(list C.uintptr_t) {
	cgo.Handle(list).Delete()
}

// juicefs_update_readdir_offset records how far a directory handle has been
// read, so that the next read from `off` resumes there.
//
//export juicefs_update_readdir_offset
func juicefs_update_readdir_offset(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh C.uint64_t, off C.uint64_t) C.int {
	return guard(h, func(s *session) C.int {
		s.v.UpdateReaddirOffset(s.context(ctx), meta.Ino(ino), uint64(fh), int(off))
		return 0
	})
}

// juicefs_clone clones `srcIno` (whose parent is `srcParentIno`) into
// `dstParentIno` under `dstName` within the same mounted volume using
// `Meta.Clone`.
//
//export juicefs_clone
func juicefs_clone(
	h C.uintptr_t,
	ctx *C.juicefs_ctx,
	srcParentIno, srcIno, dstParentIno C.uint64_t,
	dstName *C.char,
	concurrency C.uint8_t,
) C.int {
	return guard(h, func(s *session) C.int {
		name := C.GoString(dstName)
		if name == "" {
			return C.int(syscall.EINVAL)
		}
		conc := uint8(concurrency)
		if conc == 0 {
			conc = meta.CLONE_DEFAULT_CONCURRENCY
		}
		var count, total uint64
		eno := s.v.Meta.Clone(
			s.context(ctx),
			meta.Ino(srcParentIno),
			meta.Ino(srcIno),
			meta.Ino(dstParentIno),
			name,
			meta.CLONE_MODE_PRESERVE_ATTR|meta.CLONE_MODE_PRESERVE_HARDLINKS,
			0,
			conc,
			&count,
			&total,
		)
		return C.int(eno)
	})
}

// juicefs_remove_tree recursively removes `name` under `parentIno` using
// `Meta.Remove`.
//
//export juicefs_remove_tree
func juicefs_remove_tree(
	h C.uintptr_t,
	ctx *C.juicefs_ctx,
	parentIno C.uint64_t,
	name *C.char,
	skipTrash C.uint8_t,
	numThreads C.int,
) C.int {
	return guard(h, func(s *session) C.int {
		goName := C.GoString(name)
		if goName == "" {
			return C.int(syscall.EINVAL)
		}
		threads := int(numThreads)
		if threads <= 0 {
			threads = 8
		}
		var count uint64
		eno := s.v.Meta.Remove(
			s.context(ctx),
			meta.Ino(parentIno),
			goName,
			skipTrash != 0,
			threads,
			&count,
		)
		if eno == 0 && s.v.InvalidateEntry != nil {
			_ = s.v.InvalidateEntry(meta.Ino(parentIno), goName)
		}
		return C.int(eno)
	})
}

// juicefs_resolve resolves a `/`-separated path relative to the mounted root
// (respecting `subdir` if configured) in a single metadata call via
// `Meta.Resolve`.
//
//export juicefs_resolve
func juicefs_resolve(
	h C.uintptr_t,
	ctx *C.juicefs_ctx,
	relPath *C.char,
	out *C.juicefs_entry,
) C.int {
	return guard(h, func(s *session) C.int {
		p := C.GoString(relPath)
		if s.v.Conf != nil && s.v.Conf.Subdir != "" {
			p = path.Join(s.v.Conf.Subdir, p)
		}
		for len(p) > 0 && p[0] == '/' {
			p = p[1:]
		}
		if p == "" {
			e, err := s.v.GetAttr(s.context(ctx), 1, 0)
			if err != 0 {
				return C.int(err)
			}
			*out = entry(e)
			return 0
		}
		var ino meta.Ino
		var a meta.Attr
		eno := s.v.Meta.Resolve(s.context(ctx), 1, p, &ino, &a, true)
		if eno != 0 {
			return C.int(eno)
		}
		*out = C.juicefs_entry{
			ino:  C.uint64_t(ino),
			attr: attr(&a),
		}
		return 0
	})
}
