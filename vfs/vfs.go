// Package vfs provides local and remote filesystems support
package vfs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/eikenb/pipeat"

	"github.com/drakkan/sftpgo/logger"
)

const dirMimeType = "inode/directory"

var validAzAccessTier = []string{"", "Archive", "Hot", "Cool"}

// Fs defines the interface for filesystem backends
type Fs interface {
	Name() string
	ConnectionID() string
	Stat(name string) (os.FileInfo, error)
	Lstat(name string) (os.FileInfo, error)
	Open(name string, offset int64) (File, *pipeat.PipeReaderAt, func(), error)
	Create(name string, flag int) (File, *PipeWriter, func(), error)
	Rename(source, target string) error
	Remove(name string, isDir bool) error
	Mkdir(name string) error
	Symlink(source, target string) error
	Chown(name string, uid int, gid int) error
	Chmod(name string, mode os.FileMode) error
	Chtimes(name string, atime, mtime time.Time) error
	Truncate(name string, size int64) error
	ReadDir(dirname string) ([]os.FileInfo, error)
	Readlink(name string) (string, error)
	IsUploadResumeSupported() bool
	IsAtomicUploadSupported() bool
	CheckRootPath(username string, uid int, gid int) bool
	ResolvePath(sftpPath string) (string, error)
	IsNotExist(err error) bool
	IsPermission(err error) bool
	IsNotSupported(err error) bool
	ScanRootDirContents() (int, int64, error)
	GetDirSize(dirname string) (int, int64, error)
	GetAtomicUploadPath(name string) string
	GetRelativePath(name string) string
	Walk(root string, walkFn filepath.WalkFunc) error
	Join(elem ...string) string
	HasVirtualFolders() bool
	GetMimeType(name string) (string, error)
}

// File defines an interface representing a SFTPGo file
type File interface {
	io.Reader
	io.Writer
	io.Closer
	io.ReaderAt
	io.WriterAt
	io.Seeker
	Stat() (os.FileInfo, error)
	Name() string
	Truncate(size int64) error
}

// ErrVfsUnsupported defines the error for an unsupported VFS operation
var ErrVfsUnsupported = errors.New("Not supported")

// QuotaCheckResult defines the result for a quota check
type QuotaCheckResult struct {
	HasSpace     bool
	AllowedSize  int64
	AllowedFiles int
	UsedSize     int64
	UsedFiles    int
	QuotaSize    int64
	QuotaFiles   int
}

// GetRemainingSize returns the remaining allowed size
func (q *QuotaCheckResult) GetRemainingSize() int64 {
	if q.QuotaSize > 0 {
		return q.QuotaSize - q.UsedSize
	}
	return 0
}

// GetRemainingFiles returns the remaining allowed files
func (q *QuotaCheckResult) GetRemainingFiles() int {
	if q.QuotaFiles > 0 {
		return q.QuotaFiles - q.UsedFiles
	}
	return 0
}

// PipeWriter defines a wrapper for pipeat.PipeWriterAt.
type PipeWriter struct {
	writer *pipeat.PipeWriterAt
	err    error
	done   chan bool
}

// NewPipeWriter initializes a new PipeWriter
func NewPipeWriter(w *pipeat.PipeWriterAt) *PipeWriter {
	return &PipeWriter{
		writer: w,
		err:    nil,
		done:   make(chan bool),
	}
}

// Close waits for the upload to end, closes the pipeat.PipeWriterAt and returns an error if any.
func (p *PipeWriter) Close() error {
	p.writer.Close() //nolint:errcheck // the returned error is always null
	<-p.done
	return p.err
}

// Done unlocks other goroutines waiting on Close().
// It must be called when the upload ends
func (p *PipeWriter) Done(err error) {
	p.err = err
	p.done <- true
}

// WriteAt is a wrapper for pipeat WriteAt
func (p *PipeWriter) WriteAt(data []byte, off int64) (int, error) {
	return p.writer.WriteAt(data, off)
}

// Write is a wrapper for pipeat Write
func (p *PipeWriter) Write(data []byte) (int, error) {
	return p.writer.Write(data)
}

// IsDirectory checks if a path exists and is a directory
func IsDirectory(fs Fs, path string) (bool, error) {
	fileInfo, err := fs.Stat(path)
	if err != nil {
		return false, err
	}
	return fileInfo.IsDir(), err
}

// IsLocalOsFs returns true if fs is the local filesystem implementation
func IsLocalOsFs(fs Fs) bool {
	return fs.Name() == osFsName
}

// SetPathPermissions calls fs.Chown.
// It does nothing for local filesystem on windows
func SetPathPermissions(fs Fs, path string, uid int, gid int) {
	if IsLocalOsFs(fs) {
		if runtime.GOOS == "windows" {
			return
		}
	}
	if err := fs.Chown(path, uid, gid); err != nil {
		fsLog(fs, logger.LevelWarn, "error chowning path %v: %v", path, err)
	}
}

func fsLog(fs Fs, level logger.LogLevel, format string, v ...interface{}) {
	logger.Log(level, fs.Name(), fs.ConnectionID(), format, v...)
}
