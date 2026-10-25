//go:build windows

package main

import (
	"syscall"

	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/vfs"
)

// On Windows the VFS has none of the operations in `vfs_unix.go`, so they are
// answered with ENOSYS, the errno the guest sees for an operation the volume
// does not implement. The C surface is the same on every platform.

func opSetAttr(_ *vfs.VFS, _ vfs.LogContext, _ meta.Ino, _ int, _ uint64, _, _, _ uint32,
	_, _ int64, _, _ uint32, _ uint64) (*meta.Entry, syscall.Errno) {
	return nil, syscall.ENOSYS
}

func opStatFS(_ *vfs.VFS, _ vfs.LogContext, _ meta.Ino) (total, avail, files, favail uint64, err syscall.Errno) {
	return 0, 0, 0, 0, syscall.ENOSYS
}

func opAccess(_ *vfs.VFS, _ vfs.LogContext, _ meta.Ino, _ int) syscall.Errno {
	return syscall.ENOSYS
}

func opGetlk(_ *vfs.VFS, _ vfs.LogContext, _ meta.Ino, _, _ uint64, _, _ *uint64, _, _ *uint32) syscall.Errno {
	return syscall.ENOSYS
}

func opSetlk(_ *vfs.VFS, _ vfs.LogContext, _ meta.Ino, _, _, _, _ uint64, _, _ uint32, _ bool) syscall.Errno {
	return syscall.ENOSYS
}

func opFlock(_ *vfs.VFS, _ vfs.LogContext, _ meta.Ino, _, _ uint64, _ uint32, _ bool) syscall.Errno {
	return syscall.ENOSYS
}

func opIoctl(_ *vfs.VFS, _ vfs.LogContext, _ meta.Ino, _ uint32, _ uint64, _, _ []byte) syscall.Errno {
	return syscall.ENOSYS
}
