// The C surface the VMM links against.
//
// The archive is linked into the VMM's own process, so there is no transport
// here and no FUSE wire: the host's virtio-fs engine parses the guest's FUSE
// messages itself and calls one function per operation. Each takes the fields
// the operation needs and fills in values of its own, and each returns a host
// errno (0 for success) that the Rust side translates to the guest's.
//
// The layouts below are the C ABI. `juicefs_attr` is `struct fuse_attr`, so
// the attributes the VFS already carries cross without a conversion table on
// the Rust side; the rest describe an entry, a context, an I/O vector and a
// directory record. Nothing here encodes or decodes a FUSE message.
package main

/*
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

typedef struct {
	uint64_t ino;
	uint64_t size;
	uint64_t blocks;
	uint64_t atime;
	uint64_t mtime;
	uint64_t ctime;
	uint32_t atimensec;
	uint32_t mtimensec;
	uint32_t ctimensec;
	uint32_t mode;
	uint32_t nlink;
	uint32_t uid;
	uint32_t gid;
	uint32_t rdev;
	uint32_t blksize;
	uint32_t flags;
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
	void *base;
	size_t len;
} juicefs_iovec;

typedef struct {
	uint64_t ino;
	juicefs_attr attr;
	uint32_t namelen;
	char name[256];
} juicefs_dirent;

typedef struct {
	uint64_t blocks;
	uint64_t bfree;
	uint64_t bavail;
	uint64_t files;
	uint64_t ffree;
	uint32_t bsize;
	uint32_t namelen;
	uint32_t frsize;
} juicefs_kstatfs;
*/
import "C"

import (
	"runtime/cgo"
	"syscall"
	"time"
	"unsafe"

	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/vfs"
)

// One mounted volume. The VFS tracks its own inodes and handles.
type session struct {
	v *vfs.VFS
}

// juicefs_mount mounts one volume and returns its handle. A handle of 0 means
// failure, and `err` is then set to a message the caller owns and must release
// with `juicefs_free`; on success it is left alone.
//
//export juicefs_mount
func juicefs_mount(payload, cacheDir *C.char, attrTTLms, entryTTLms C.longlong, err **C.char) C.uintptr_t {
	attrTTL := time.Duration(attrTTLms) * time.Millisecond
	entryTTL := time.Duration(entryTTLms) * time.Millisecond
	v, mountErr := buildVFS(C.GoString(payload), attrTTL, entryTTL, C.GoString(cacheDir))
	if mountErr != nil {
		*err = C.CString(mountErr.Error())
		return 0
	}
	return C.uintptr_t(cgo.NewHandle(&session{v: v}))
}

// juicefs_unmount drops one volume's session. The handle is not reused.
//
//export juicefs_unmount
func juicefs_unmount(h C.uintptr_t) {
	if h == 0 {
		return
	}
	cgo.Handle(h).Delete()
}

// juicefs_free releases a message `juicefs_mount` returned.
//
//export juicefs_free
func juicefs_free(message *C.char) {
	C.free(unsafe.Pointer(message))
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

// context is the credentials a request carries.
func (s *session) context(ctx *C.juicefs_ctx) vfs.LogContext {
	return vfs.NewLogContext(meta.NewContext(uint32(ctx.pid), uint32(ctx.uid), []uint32{uint32(ctx.gid)}))
}

// attr fills the wire layout from a meta attr. Length is only meaningful for
// the types that have one, as `pkg/fuse`'s attrToStat does it.
func attr(e *meta.Entry) C.juicefs_attr {
	a := e.Attr
	w := C.juicefs_attr{
		ino:       C.uint64_t(e.Inode),
		atime:     C.uint64_t(a.Atime),
		mtime:     C.uint64_t(a.Mtime),
		ctime:     C.uint64_t(a.Ctime),
		atimensec: C.uint32_t(a.Atimensec),
		mtimensec: C.uint32_t(a.Mtimensec),
		ctimensec: C.uint32_t(a.Ctimensec),
		mode:      C.uint32_t(a.SMode()),
		nlink:     C.uint32_t(a.Nlink),
		uid:       C.uint32_t(a.Uid),
		gid:       C.uint32_t(a.Gid),
		rdev:      C.uint32_t(a.Rdev),
		blksize:   0x10000,
	}
	switch a.Typ {
	case meta.TypeDirectory, meta.TypeSymlink, meta.TypeFile:
		w.size = C.uint64_t(a.Length)
		w.blocks = C.uint64_t((a.Length + 511) / 512)
	}
	return w
}

// entry is a name's inode plus its attributes.
func entry(e *meta.Entry) C.juicefs_entry {
	return C.juicefs_entry{ino: C.uint64_t(e.Inode), attr: attr(e)}
}

// entryReply is the shared tail of every operation that resolves a name: the
// chunk store knows the length before the client caches the attribute.
func (s *session) entryReply(e *meta.Entry, out *C.juicefs_entry) C.int {
	s.v.UpdateLength(e.Inode, e.Attr)
	*out = entry(e)
	return 0
}

//export juicefs_lookup
func juicefs_lookup(h C.uintptr_t, ctx *C.juicefs_ctx, parent C.uint64_t, name *C.char, out *C.juicefs_entry) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	e, err := s.v.Lookup(s.context(ctx), meta.Ino(parent), C.GoString(name))
	if err != 0 {
		return C.int(err)
	}
	return s.entryReply(e, out)
}

//export juicefs_getattr
func juicefs_getattr(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, opened C.int, out *C.juicefs_attr) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	e, err := s.v.GetAttr(s.context(ctx), meta.Ino(ino), uint8(opened))
	if err != 0 {
		return C.int(err)
	}
	*out = attr(e)
	return 0
}

//export juicefs_setattr
func juicefs_setattr(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, valid C.uint32_t, fh C.uint64_t,
	mode, uid, gid C.uint32_t, atime, mtime C.int64_t, atimensec, mtimensec C.uint32_t,
	size C.uint64_t, out *C.juicefs_attr) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	if valid&meta.SetAttrAtimeNow != 0 {
		now := time.Now()
		atime, atimensec = C.int64_t(now.Unix()), C.uint32_t(now.Nanosecond())
	}
	if valid&meta.SetAttrMtimeNow != 0 {
		now := time.Now()
		mtime, mtimensec = C.int64_t(now.Unix()), C.uint32_t(now.Nanosecond())
	}
	e, err := s.v.SetAttr(s.context(ctx), meta.Ino(ino), int(valid), uint64(fh),
		uint32(mode), uint32(uid), uint32(gid),
		int64(atime), int64(mtime), uint32(atimensec), uint32(mtimensec), uint64(size))
	if err != 0 {
		return C.int(err)
	}
	*out = attr(e)
	return 0
}

//export juicefs_readlink
func juicefs_readlink(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, buf *C.char, capacity C.size_t, length *C.size_t) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	path, err := s.v.Readlink(s.context(ctx), meta.Ino(ino))
	if err != 0 {
		return C.int(err)
	}
	if len(path) > int(capacity) {
		return C.int(syscall.ERANGE)
	}
	if len(path) > 0 {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(buf)), len(path)), path)
	}
	*length = C.size_t(len(path))
	return 0
}

//export juicefs_symlink
func juicefs_symlink(h C.uintptr_t, ctx *C.juicefs_ctx, target *C.char, parent C.uint64_t, name *C.char, out *C.juicefs_entry) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	e, err := s.v.Symlink(s.context(ctx), C.GoString(target), meta.Ino(parent), C.GoString(name))
	if err != 0 {
		return C.int(err)
	}
	return s.entryReply(e, out)
}

//export juicefs_mknod
func juicefs_mknod(h C.uintptr_t, ctx *C.juicefs_ctx, parent C.uint64_t, name *C.char, mode, rdev, umask C.uint32_t, out *C.juicefs_entry) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	e, err := s.v.Mknod(s.context(ctx), meta.Ino(parent), C.GoString(name), uint16(mode), uint16(umask), uint32(rdev))
	if err != 0 {
		return C.int(err)
	}
	return s.entryReply(e, out)
}

//export juicefs_mkdir
func juicefs_mkdir(h C.uintptr_t, ctx *C.juicefs_ctx, parent C.uint64_t, name *C.char, mode, umask C.uint32_t, out *C.juicefs_entry) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	e, err := s.v.Mkdir(s.context(ctx), meta.Ino(parent), C.GoString(name), uint16(mode), uint16(umask))
	if err != 0 {
		return C.int(err)
	}
	return s.entryReply(e, out)
}

//export juicefs_unlink
func juicefs_unlink(h C.uintptr_t, ctx *C.juicefs_ctx, parent C.uint64_t, name *C.char) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	return C.int(s.v.Unlink(s.context(ctx), meta.Ino(parent), C.GoString(name)))
}

//export juicefs_rmdir
func juicefs_rmdir(h C.uintptr_t, ctx *C.juicefs_ctx, parent C.uint64_t, name *C.char) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	return C.int(s.v.Rmdir(s.context(ctx), meta.Ino(parent), C.GoString(name)))
}

//export juicefs_rename
func juicefs_rename(h C.uintptr_t, ctx *C.juicefs_ctx, parent C.uint64_t, name *C.char,
	newparent C.uint64_t, newname *C.char, flags C.uint32_t) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	return C.int(s.v.Rename(s.context(ctx), meta.Ino(parent), C.GoString(name),
		meta.Ino(newparent), C.GoString(newname), uint32(flags)))
}

//export juicefs_link
func juicefs_link(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, parent C.uint64_t, name *C.char, out *C.juicefs_entry) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	e, err := s.v.Link(s.context(ctx), meta.Ino(ino), meta.Ino(parent), C.GoString(name))
	if err != 0 {
		return C.int(err)
	}
	return s.entryReply(e, out)
}

//export juicefs_open
func juicefs_open(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, flags C.uint32_t, fh *C.uint64_t, keepCache *C.int) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	e, handle, err := s.v.Open(s.context(ctx), meta.Ino(ino), uint32(flags))
	if err != 0 {
		return C.int(err)
	}
	*fh = C.uint64_t(handle)
	*keepCache = keepCacheFlag(e.Attr.KeepCache)
	return 0
}

//export juicefs_create
func juicefs_create(h C.uintptr_t, ctx *C.juicefs_ctx, parent C.uint64_t, name *C.char,
	mode, umask, flags C.uint32_t, out *C.juicefs_entry, fh *C.uint64_t, keepCache *C.int) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	e, handle, err := s.v.Create(s.context(ctx), meta.Ino(parent), C.GoString(name),
		uint16(mode), uint16(umask), uint32(flags))
	if err != 0 {
		return C.int(err)
	}
	*fh = C.uint64_t(handle)
	*keepCache = keepCacheFlag(e.Attr.KeepCache)
	return s.entryReply(e, out)
}

// keepCacheFlag is whether the file's pages may stay cached. The Rust side
// turns 0 into FOPEN_DIRECT_IO and 1 into FOPEN_KEEP_CACHE.
func keepCacheFlag(keep bool) C.int {
	if keep {
		return 1
	}
	return 0
}

//export juicefs_read
func juicefs_read(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh C.uint64_t, off C.uint64_t,
	iov *C.juicefs_iovec, iovcnt C.size_t, n *C.size_t) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	// Read straight into each range: the VFS copies out of the chunk cache and
	// never keeps the buffer, and the caller keeps the memory alive for the
	// whole call.
	lctx := s.context(ctx)
	var total int
	for _, vec := range unsafe.Slice(iov, int(iovcnt)) {
		if vec.len == 0 {
			continue
		}
		buf := unsafe.Slice((*byte)(vec.base), int(vec.len))
		got, err := s.v.Read(lctx, meta.Ino(ino), buf, uint64(off)+uint64(total), uint64(fh))
		total += got
		if err != 0 {
			return C.int(err)
		}
		if got < len(buf) {
			break
		}
	}
	*n = C.size_t(total)
	return 0
}

//export juicefs_write
func juicefs_write(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh C.uint64_t, off C.uint64_t,
	iov *C.juicefs_iovec, iovcnt C.size_t) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	// The bytes are copied into a Go-owned slice first: `vfs.Write` hands the
	// buffer to the chunk writer, which may carry it into a goroutine that
	// outlives this call, and Go may not keep a foreign pointer.
	vecs := unsafe.Slice(iov, int(iovcnt))
	size := 0
	for _, vec := range vecs {
		size += int(vec.len)
	}
	buf := make([]byte, 0, size)
	for _, vec := range vecs {
		buf = append(buf, unsafe.Slice((*byte)(vec.base), int(vec.len))...)
	}
	return C.int(s.v.Write(s.context(ctx), meta.Ino(ino), buf, uint64(off), uint64(fh)))
}

//export juicefs_flush
func juicefs_flush(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh, lockOwner C.uint64_t) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	return C.int(s.v.Flush(s.context(ctx), meta.Ino(ino), uint64(fh), uint64(lockOwner)))
}

//export juicefs_fsync
func juicefs_fsync(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh C.uint64_t, datasync C.int) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	return C.int(s.v.Fsync(s.context(ctx), meta.Ino(ino), int(datasync), uint64(fh)))
}

//export juicefs_release
func juicefs_release(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh C.uint64_t) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	s.v.Release(s.context(ctx), meta.Ino(ino), uint64(fh))
	return 0
}

//export juicefs_fallocate
func juicefs_fallocate(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh C.uint64_t, mode C.uint32_t,
	off, length C.int64_t) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	return C.int(s.v.Fallocate(s.context(ctx), meta.Ino(ino), uint8(mode), int64(off), int64(length), uint64(fh)))
}

//export juicefs_statfs
func juicefs_statfs(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, out *C.juicefs_kstatfs) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	st, err := s.v.StatFS(s.context(ctx), meta.Ino(ino))
	if err != 0 {
		return C.int(err)
	}
	const bsize = 4096
	blocks := (st.Total + bsize - 1) / bsize
	avail := st.Avail / bsize
	if blocks < 1 {
		blocks = 1
	}
	if avail > blocks {
		avail = blocks
	}
	*out = C.juicefs_kstatfs{
		blocks:  C.uint64_t(blocks),
		bfree:   C.uint64_t(avail),
		bavail:  C.uint64_t(avail),
		files:   C.uint64_t(st.Files),
		ffree:   C.uint64_t(st.Favail),
		bsize:   bsize,
		namelen: 255,
		frsize:  bsize,
	}
	return 0
}

//export juicefs_access
func juicefs_access(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, mask C.uint32_t) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	return C.int(s.v.Access(s.context(ctx), meta.Ino(ino), int(mask)))
}

//export juicefs_opendir
func juicefs_opendir(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, flags C.uint32_t, fh *C.uint64_t) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	handle, err := s.v.Opendir(s.context(ctx), meta.Ino(ino), uint32(flags))
	if err != 0 {
		return C.int(err)
	}
	*fh = C.uint64_t(handle)
	return 0
}

// juicefs_readdir fills up to `cap` records at `out`, reporting how many in
// `count` and whether the VFS had more in `more`. The caller sizes `cap` to
// what its reply buffer can hold; the offsets it builds are the VFS's own
// entry indices, so the next call resumes where this one stopped.
//
//export juicefs_readdir
func juicefs_readdir(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh C.uint64_t, off C.uint64_t,
	plus C.int, out *C.juicefs_dirent, capacity C.size_t, count *C.size_t, more *C.int) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	entries, _, err := s.v.Readdir(s.context(ctx), meta.Ino(ino), 0, int(off), uint64(fh), plus != 0)
	if err != 0 {
		return C.int(err)
	}
	slots := int(capacity)
	n := 0
	var batch []C.juicefs_dirent
	if slots > 0 {
		batch = unsafe.Slice(out, slots)
	}
	for _, e := range entries {
		if n >= slots {
			break
		}
		if plus != 0 {
			s.v.UpdateLength(e.Inode, e.Attr)
		}
		slot := &batch[n]
		slot.ino = C.uint64_t(e.Inode)
		slot.attr = attr(e)
		name := e.Name
		if len(name) > len(slot.name)-1 {
			name = name[:len(slot.name)-1]
		}
		slot.namelen = C.uint32_t(len(name))
		for i := range slot.name {
			slot.name[i] = 0
		}
		if len(name) > 0 {
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&slot.name[0])), len(name)), name)
		}
		n++
	}
	*count = C.size_t(n)
	if n < len(entries) {
		*more = 1
	} else {
		*more = 0
	}
	return 0
}

// juicefs_readdir_offset tells the directory handle how far the client got
// when its reply buffer filled before the batch was exhausted. Without it the
// next call would start the batch over.
//
//export juicefs_readdir_offset
func juicefs_readdir_offset(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh C.uint64_t, off C.uint64_t) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	s.v.UpdateReaddirOffset(s.context(ctx), meta.Ino(ino), uint64(fh), int(off))
	return 0
}

//export juicefs_releasedir
func juicefs_releasedir(h C.uintptr_t, ctx *C.juicefs_ctx, ino, fh C.uint64_t) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	s.v.Releasedir(s.context(ctx), meta.Ino(ino), uint64(fh))
	return 0
}

// juicefs_getxattr writes the value into `buf` when `size` is non-zero, and
// reports its length; with `size` zero it only reports the length, which is
// the kernel's size probe.
//
//export juicefs_getxattr
func juicefs_getxattr(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, name *C.char, size C.uint32_t,
	buf *C.char, capacity C.size_t, length *C.size_t) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	value, err := s.v.GetXattr(s.context(ctx), meta.Ino(ino), C.GoString(name), uint32(size))
	if err != 0 {
		return C.int(err)
	}
	if size == 0 {
		*length = C.size_t(len(value))
		return 0
	}
	if len(value) > int(capacity) {
		return C.int(syscall.ERANGE)
	}
	if len(value) > 0 {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(buf)), len(value)), value)
	}
	*length = C.size_t(len(value))
	return 0
}

//export juicefs_listxattr
func juicefs_listxattr(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, size C.uint32_t,
	buf *C.char, capacity C.size_t, length *C.size_t) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	data, err := s.v.ListXattr(s.context(ctx), meta.Ino(ino), int(size))
	if err != 0 {
		return C.int(err)
	}
	if size == 0 {
		*length = C.size_t(len(data))
		return 0
	}
	if len(data) > int(capacity) {
		return C.int(syscall.ERANGE)
	}
	if len(data) > 0 {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(buf)), len(data)), data)
	}
	*length = C.size_t(len(data))
	return 0
}

//export juicefs_setxattr
func juicefs_setxattr(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, name *C.char,
	value unsafe.Pointer, length C.size_t, flags C.uint32_t) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	var data []byte
	if length > 0 {
		data = unsafe.Slice((*byte)(value), int(length))
	}
	return C.int(s.v.SetXattr(s.context(ctx), meta.Ino(ino), C.GoString(name), data, uint32(flags)))
}

//export juicefs_removexattr
func juicefs_removexattr(h C.uintptr_t, ctx *C.juicefs_ctx, ino C.uint64_t, name *C.char) (ret C.int) {
	defer recoverErr(&ret)
	s := lookup(h)
	if s == nil {
		return C.int(syscall.EBADF)
	}
	return C.int(s.v.RemoveXattr(s.context(ctx), meta.Ino(ino), C.GoString(name)))
}
