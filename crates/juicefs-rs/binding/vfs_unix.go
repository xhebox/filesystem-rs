//go:build !windows

package main

import (
	"syscall"

	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/vfs"
)

// The operations below are the VFS methods that only Unix builds have: the
// `vfs_unix.go` file of the VFS is excluded on Windows. Each one forwards to the
// VFS as it is; `vfs_windows.go` answers them with ENOSYS there.

func opSetAttr(v *vfs.VFS, ctx vfs.LogContext, ino meta.Ino, valid int, fh uint64, mode, uid, gid uint32,
	atime, mtime int64, atimensec, mtimensec uint32, size uint64) (*meta.Entry, syscall.Errno) {
	return v.SetAttr(ctx, ino, valid, fh, mode, uid, gid, atime, mtime, atimensec, mtimensec, size)
}

// opStatFS returns the VFS's four totals, as `Statfs` reports them.
func opStatFS(v *vfs.VFS, ctx vfs.LogContext, ino meta.Ino) (total, avail, files, favail uint64, err syscall.Errno) {
	st, err := v.StatFS(ctx, ino)
	if err != 0 {
		return 0, 0, 0, 0, err
	}
	return st.Total, st.Avail, st.Files, st.Favail, 0
}

func opAccess(v *vfs.VFS, ctx vfs.LogContext, ino meta.Ino, mask int) syscall.Errno {
	return v.Access(ctx, ino, mask)
}

func opGetlk(v *vfs.VFS, ctx vfs.LogContext, ino meta.Ino, fh, owner uint64, start, length *uint64, typ, pid *uint32) syscall.Errno {
	return v.Getlk(ctx, ino, fh, owner, start, length, typ, pid)
}

func opSetlk(v *vfs.VFS, ctx vfs.LogContext, ino meta.Ino, fh, owner, start, end uint64, typ, pid uint32, block bool) syscall.Errno {
	return v.Setlk(ctx, ino, fh, owner, start, end, typ, pid, block)
}

func opFlock(v *vfs.VFS, ctx vfs.LogContext, ino meta.Ino, fh, owner uint64, typ uint32, block bool) syscall.Errno {
	return v.Flock(ctx, ino, fh, owner, typ, block)
}

func opIoctl(v *vfs.VFS, ctx vfs.LogContext, ino meta.Ino, cmd uint32, arg uint64, in, out []byte) syscall.Errno {
	return v.Ioctl(ctx, ino, cmd, arg, in, out)
}
