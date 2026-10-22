// juicefs embeds a JuiceFS volume in the VMM's own process.
//
// The C surface the host calls is `embed.go`, one function per VFS operation;
// this file is mounting a volume — metadata client, object storage, chunk
// cache, VFS — with the daemonizing, flag-plumbing and background-task
// machinery of the upstream `juicefs mount` left out, since the VMM owns this
// process and its lifetime. Nothing here speaks FUSE: the VMM parses the
// guest's FUSE messages and calls into the VFS directly.
package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/juicedata/juicefs/pkg/chunk"
	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/object"
	"github.com/juicedata/juicefs/pkg/vfs"
	"github.com/prometheus/client_golang/prometheus"
)

// main is never called: this package is built as an archive and linked into
// another program, which starts the Go runtime itself (see `embed.go`). The
// linker still wants a `main` in a `main` package.
func main() {}

// buildVFS replicates the essential stage-3 mount flow of upstream
// cmd/mount.go: meta client, object storage, cached chunk store, VFS.
func buildVFS(payload string, cacheDir string) (*vfs.VFS, error) {
	metaConf := meta.DefaultConf()
	metaConf.NoBGJob = true
	metaConf.MountPoint = "/jfs" // log wording only; nothing is mounted

	metaCli := meta.NewClient(payload, metaConf)
	format, err := metaCli.Load(true)
	if err != nil {
		return nil, fmt.Errorf("load volume format: %w", err)
	}
	if st := metaCli.Chroot(meta.Background(), ""); st != 0 {
		return nil, fmt.Errorf("chroot: %d", st)
	}
	if err := metaCli.NewSession(true); err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}

	if err := format.Decrypt(); err != nil {
		return nil, fmt.Errorf("format decrypt: %w", err)
	}
	object.UserAgent = "juicefs"
	blob, err := object.CreateStorage(strings.ToLower(format.Storage), format.Bucket, format.AccessKey, format.SecretKey, format.SessionToken)
	if err != nil {
		return nil, fmt.Errorf("object storage: %w", err)
	}

	if cacheDir == "" {
		cacheDir = filepath.Join(os.TempDir(), "juicefs", url.PathEscape(format.Name))
	}
	chunkConf := &chunk.Config{
		BlockSize:      int(format.BlockSize) * 1024,
		Compress:       format.Compression,
		HashPrefix:     format.HashPrefix,
		GetTimeout:     60 * time.Second,
		PutTimeout:     60 * time.Second,
		MaxUpload:      20,
		MaxRetries:     30,
		Prefetch:       1,
		BufferSize:     300 << 20,
		CacheDir:       cacheDir,
		CacheSize:      100 << 20,
		CacheMode:      0600,
		CacheFullBlock: true,
		CacheChecksum:  "full",
		CacheEviction:  "2-random",
		FreeSpace:      0.1,
		AutoCreate:     true,
		OSCache:        true,
	}
	chunkConf.SelfCheck(format.UUID)

	registry := prometheus.NewRegistry()
	store := chunk.NewCachedStore(blob, *chunkConf, registry)

	// Chunk lifecycle: deletions and compaction route through the store.
	metaCli.OnMsg(meta.DeleteSlice, func(args ...interface{}) error {
		return store.Remove(args[0].(uint64), int(args[1].(uint32)))
	})
	metaCli.OnMsg(meta.CompactChunk, func(args ...interface{}) error {
		return vfs.Compact(*chunkConf, store, args[0].([]meta.Slice), args[1].(uint64), args[2].(uint8))
	})

	vfsConf := &vfs.Config{
		Meta:    metaConf,
		Format:  *format,
		Chunk:   chunkConf,
		Version: "juicefs",
	}
	return vfs.NewVFS(vfsConf, metaCli, store, registry, registry), nil
}
