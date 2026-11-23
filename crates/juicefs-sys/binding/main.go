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
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/juicedata/juicefs/pkg/chunk"
	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/object"
	"github.com/juicedata/juicefs/pkg/utils"
	"github.com/juicedata/juicefs/pkg/vfs"
	"github.com/prometheus/client_golang/prometheus"
)

// main is never called: this package is built as an archive and linked into
// another program, which starts the Go runtime itself (see `embed.go`). The
// linker still wants a `main` in a `main package.
func main() {}

// The archive is a library inside another process. JuiceFS's CLI-oriented
// defaults must not write into the host application's stdout or stderr.
func init() {
	utils.SetOutput(io.Discard)
	log.SetOutput(io.Discard)
}

// formatVolume initializes or updates the volume metadata at `payload` using
// `metaCli.Init`. When `force` is false and the volume is already formatted, it
// returns nil without overwriting the existing format.
func formatVolume(payload, name, storage, bucket, accessKey, secretKey, sessionToken string, force bool) error {
	metaConf := meta.DefaultConf()
	metaConf.NoBGJob = true
	metaConf.MountPoint = "/jfs"

	metaCli := meta.NewClient(payload, metaConf)
	defer func() { _ = metaCli.Shutdown() }()

	existing, err := metaCli.Load(false)
	if err == nil && !force {
		return nil
	}
	if err != nil && !strings.HasPrefix(err.Error(), "database is not formatted") && !force {
		return fmt.Errorf("load metadata: %w", err)
	}
	if storage == "" {
		storage = "file"
	}
	if storage == "file" || storage == "sqlite3" {
		abs, absErr := filepath.Abs(bucket)
		if absErr != nil {
			return fmt.Errorf("resolve bucket path %q: %w", bucket, absErr)
		}
		bucket = abs
		if storage == "file" && !strings.HasSuffix(bucket, "/") {
			bucket += "/"
		}
	}
	volUUID := uuid.New().String()
	if existing != nil && existing.UUID != "" {
		volUUID = existing.UUID
	}
	format := &meta.Format{
		Name:             name,
		UUID:             volUUID,
		Storage:          storage,
		Tiers:            object.NewTiers(""),
		Bucket:           bucket,
		AccessKey:        accessKey,
		SecretKey:        secretKey,
		SessionToken:     sessionToken,
		BlockSize:        4096,
		Compression:      "none",
		EncryptAlgo:      "aes256gcm-rsa",
		TrashDays:        0,
		DirStats:         true,
		MetaVersion:      meta.MaxVersion,
		MinClientVersion: "1.1.0-A",
	}
	if err := format.Encrypt(); err != nil {
		return fmt.Errorf("encrypt format: %w", err)
	}
	if err := metaCli.Init(format, force); err != nil {
		return fmt.Errorf("init format: %w", err)
	}
	return nil
}

type mountOptions struct {
	cacheDir          string
	subdir            string
	readOnly          bool
	hideInternal      bool
	noBGJob           bool
	ioRetries         int
	maxDeletes        int
	openCache         time.Duration
	openCacheLimit    uint64
	heartbeat         time.Duration
	skipDirNlink      int
	skipDirMtime      time.Duration
	fastStatfs        bool
	sortDir           bool
	bufferSize        uint64
	maxReadahead      int
	prefetch          int
	cacheSize         uint64
	cacheItems        int64
	freeSpacePermille uint16
	cacheFullBlock    bool
	cacheChecksum     uint8
	cacheEviction     uint8
	cacheScanInterval time.Duration
	cacheExpire       time.Duration
	writeback         bool
	maxUploads        int
	maxDownloads      int
	uploadLimitBps    int64
	downloadLimitBps  int64
	getTimeout        time.Duration
	putTimeout        time.Duration
	backupMeta        time.Duration
	backupSkipTrash   bool
	restoreState      []byte
}

const snapshotVersion uint32 = 1

type snapshotEnvelope struct {
	Version  uint32          `json:"version"`
	Sid      uint64          `json:"sid"`
	VfsState json.RawMessage `json:"vfs_state"`
}

type dumpedVfsHandles struct {
	Handler map[uint64]struct {
		Inode uint64
		Flags uint32
	}
}

// vfsNewMu serializes vfs.NewVFS calls because upstream NewVFS reads process
// environment `_FUSE_STATE_PATH` (defaulting to `/tmp/state<ppid>.json`) to
// reload open handles.
var vfsNewMu sync.Mutex

func createTempStateFile(preferredDir string) (*os.File, error) {
	if preferredDir != "" {
		if err := os.MkdirAll(preferredDir, 0o700); err == nil {
			if f, err := os.CreateTemp(preferredDir, ".juicefs-state-*.json"); err == nil {
				return f, nil
			}
		}
	}
	return os.CreateTemp("", "juicefs-state-*.json")
}

func defaultMountOptions() mountOptions {
	return mountOptions{
		noBGJob:           true,
		ioRetries:         10,
		maxDeletes:        2,
		heartbeat:         12 * time.Second,
		bufferSize:        300 << 20,
		prefetch:          1,
		cacheSize:         100 << 20,
		freeSpacePermille: 100,
		cacheFullBlock:    true,
		cacheChecksum:     1, // full
		cacheEviction:     1, // 2-random
		maxUploads:        20,
		maxDownloads:      200,
		getTimeout:        60 * time.Second,
		putTimeout:        60 * time.Second,
	}
}

func cacheChecksumName(v uint8) string {
	switch v {
	case 0:
		return chunk.CsNone
	case 1:
		return chunk.CsFull
	case 2:
		return chunk.CsShrink
	case 3:
		return chunk.CsExtend
	default:
		return chunk.CsFull
	}
}

func cacheEvictionName(v uint8) string {
	switch v {
	case 0:
		return chunk.EvictionNone
	case 1:
		return chunk.Eviction2Random
	case 2:
		return chunk.EvictionLRU
	default:
		return chunk.Eviction2Random
	}
}

// subdirMeta hides the virtual trash entry for this mount. Setting
// meta.Config.Subdir in this version would mutate vfs's global internal nodes.
type subdirMeta struct{ meta.Meta }

func (m subdirMeta) NewDirHandler(ctx meta.Context, ino meta.Ino, plus bool, entries []*meta.Entry) (meta.DirHandler, syscall.Errno) {
	entries = slices.DeleteFunc(entries, func(e *meta.Entry) bool { return e.Inode == meta.TrashInode })
	return m.Meta.NewDirHandler(ctx, ino, plus, entries)
}

// buildVFS replicates the essential stage-3 mount flow of upstream
// cmd/mount.go: meta client, object storage, cached chunk store, VFS.
func buildVFS(payload string, opts mountOptions) (*vfs.VFS, object.ObjectStorage, error) {
	var restored *snapshotEnvelope
	if len(opts.restoreState) > 0 {
		var env snapshotEnvelope
		if err := json.Unmarshal(opts.restoreState, &env); err != nil {
			return nil, nil, fmt.Errorf("decode juicefs snapshot state: %w", err)
		}
		if env.Version != snapshotVersion {
			return nil, nil, fmt.Errorf("unsupported juicefs snapshot version %d", env.Version)
		}
		if len(env.VfsState) == 0 {
			return nil, nil, fmt.Errorf("juicefs snapshot state carries empty vfs_state")
		}
		restored = &env
	}

	subdir := path.Clean("/" + opts.subdir)
	if subdir == "/" {
		subdir = ""
	}
	metaConf := meta.DefaultConf()
	metaConf.ReadOnly = opts.readOnly
	metaConf.NoBGJob = opts.noBGJob
	metaConf.Retries = opts.ioRetries
	metaConf.MaxDeletes = opts.maxDeletes
	metaConf.OpenCache = opts.openCache
	metaConf.OpenCacheLimit = opts.openCacheLimit
	metaConf.Heartbeat = opts.heartbeat
	metaConf.SkipDirNlink = opts.skipDirNlink
	metaConf.SkipDirMtime = opts.skipDirMtime
	metaConf.FastStatfs = opts.fastStatfs
	metaConf.SortDir = opts.sortDir
	metaConf.MountPoint = "/jfs" // log wording only; nothing is mounted
	if restored != nil && restored.Sid != 0 {
		metaConf.Sid = restored.Sid
	}

	metaCli := meta.NewClient(payload, metaConf)
	format, err := metaCli.Load(true)
	if err != nil {
		_ = metaCli.Shutdown()
		return nil, nil, fmt.Errorf("load volume format: %w", err)
	}
	if st := metaCli.Chroot(meta.Background(), subdir); st != 0 {
		_ = metaCli.Shutdown()
		return nil, nil, fmt.Errorf("chroot %q: %w", subdir, st)
	}
	if err := metaCli.NewSession(true); err != nil {
		_ = metaCli.Shutdown()
		return nil, nil, fmt.Errorf("new session: %w", err)
	}

	if err := format.Decrypt(); err != nil {
		_ = metaCli.CloseSession()
		_ = metaCli.Shutdown()
		return nil, nil, fmt.Errorf("format decrypt: %w", err)
	}
	object.UserAgent = "juicefs"
	blob, err := object.CreateStorage(strings.ToLower(format.Storage), format.Bucket, format.AccessKey, format.SecretKey, format.SessionToken)
	if err != nil {
		_ = metaCli.CloseSession()
		_ = metaCli.Shutdown()
		return nil, nil, fmt.Errorf("object storage: %w", err)
	}

	cacheDir := opts.cacheDir
	if cacheDir == "" {
		cacheDir = filepath.Join(os.TempDir(), "juicefs", url.PathEscape(format.Name))
	}
	blockSize := int(format.BlockSize) * 1024
	readahead := opts.maxReadahead
	if readahead == 0 {
		readahead = 8 * blockSize
	}
	uploadLimit := opts.uploadLimitBps
	if uploadLimit == 0 {
		uploadLimit = format.UploadLimit * 1e6 / 8
	}
	downloadLimit := opts.downloadLimitBps
	if downloadLimit == 0 {
		downloadLimit = format.DownloadLimit * 1e6 / 8
	}
	chunkConf := &chunk.Config{
		BlockSize:         blockSize,
		Compress:          format.Compression,
		HashPrefix:        format.HashPrefix,
		GetTimeout:        opts.getTimeout,
		PutTimeout:        opts.putTimeout,
		MaxUpload:         opts.maxUploads,
		MaxDownload:       opts.maxDownloads,
		MaxRetries:        opts.ioRetries,
		UploadLimit:       uploadLimit,
		DownloadLimit:     downloadLimit,
		Prefetch:          opts.prefetch,
		Readahead:         readahead,
		BufferSize:        opts.bufferSize,
		CacheDir:          cacheDir,
		CacheSize:         opts.cacheSize,
		CacheItems:        opts.cacheItems,
		CacheMode:         0600,
		CacheFullBlock:    opts.cacheFullBlock,
		CacheChecksum:     cacheChecksumName(opts.cacheChecksum),
		CacheEviction:     cacheEvictionName(opts.cacheEviction),
		CacheScanInterval: opts.cacheScanInterval,
		CacheExpire:       opts.cacheExpire,
		FreeSpace:         float32(opts.freeSpacePermille) / 1000.0,
		Writeback:         opts.writeback,
		AutoCreate:        true,
		OSCache:           true,
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
	metaCli.OnReload(func(fmt *meta.Format) {
		if chunkConf.UploadLimit > 0 {
			fmt.UploadLimit = chunkConf.UploadLimit
		}
		if chunkConf.DownloadLimit > 0 {
			fmt.DownloadLimit = chunkConf.DownloadLimit
		}
		store.UpdateLimit(fmt.UploadLimit, fmt.DownloadLimit)
	})

	vfsConf := &vfs.Config{
		Meta:            metaConf,
		Format:          *format,
		Chunk:           chunkConf,
		Version:         "juicefs",
		Subdir:          subdir,
		HideInternal:    opts.hideInternal,
		BackupMeta:      opts.backupMeta,
		BackupSkipTrash: opts.backupSkipTrash,
	}
	if !opts.readOnly && !opts.noBGJob && opts.backupMeta > 0 {
		// Upstream's loop runs for the life of the process and has no stop
		// channel, so it outlives this volume's session and then keeps failing
		// its metadata calls. It is off by default, and enabling it is only
		// worth it for a long-lived volume.
		go vfs.Backup(metaCli, blob, opts.backupMeta, opts.backupSkipTrash)
	}
	if subdir != "" {
		metaCli = subdirMeta{metaCli}
	}

	var restorePath string
	if restored != nil {
		var parsed dumpedVfsHandles
		if err := json.Unmarshal(restored.VfsState, &parsed); err != nil {
			_ = metaCli.Shutdown()
			object.Shutdown(blob)
			return nil, nil, fmt.Errorf("invalid juicefs vfs handle table: %w", err)
		}
		tmpFile, err := createTempStateFile(cacheDir)
		if err != nil {
			_ = metaCli.Shutdown()
			object.Shutdown(blob)
			return nil, nil, fmt.Errorf("stage juicefs restore state: %w", err)
		}
		restorePath = tmpFile.Name()
		if _, err := tmpFile.Write(restored.VfsState); err != nil {
			_ = tmpFile.Close()
			_ = os.Remove(restorePath)
			_ = metaCli.Shutdown()
			object.Shutdown(blob)
			return nil, nil, fmt.Errorf("write juicefs restore state: %w", err)
		}
		if err := tmpFile.Close(); err != nil {
			_ = os.Remove(restorePath)
			_ = metaCli.Shutdown()
			object.Shutdown(blob)
			return nil, nil, fmt.Errorf("close juicefs restore state: %w", err)
		}
		const clearCreateFlags = ^uint32(syscall.O_CREAT | syscall.O_EXCL | syscall.O_TRUNC)
		for _, h := range parsed.Handler {
			var a meta.Attr
			if metaCli.GetAttr(meta.Background(), meta.Ino(h.Inode), &a) == 0 && a.Typ == meta.TypeFile {
				_ = metaCli.Open(meta.Background(), meta.Ino(h.Inode), h.Flags&clearCreateFlags, &a)
			}
		}
	}

	vfsNewMu.Lock()
	prevStateEnv, hadStateEnv := os.LookupEnv("_FUSE_STATE_PATH")
	stateEnv := restorePath
	if stateEnv == "" {
		stateEnv = filepath.Join(cacheDir, ".juicefs-nostate-"+uuid.NewString()+".json")
	}
	_ = os.Setenv("_FUSE_STATE_PATH", stateEnv)
	v := vfs.NewVFS(vfsConf, metaCli, store, registry, registry)
	if hadStateEnv {
		_ = os.Setenv("_FUSE_STATE_PATH", prevStateEnv)
	} else {
		_ = os.Unsetenv("_FUSE_STATE_PATH")
	}
	vfsNewMu.Unlock()

	if restorePath != "" {
		_ = os.Remove(restorePath)
		_ = os.Remove(restorePath + ".bak")
	}
	return v, blob, nil
}
