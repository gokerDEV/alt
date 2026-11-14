package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// maxUnixSocketPathLen leaves comfortable margin below macOS's 104-byte sockaddr_un.sun_path limit.
	maxUnixSocketPathLen = 96

	defaultLogMaxBytes   = 5 << 20 // 5 MiB per rotated log file
	defaultLogMaxBackups = 3
)

// LockInfo records diagnostic metadata inside the exclusive flock file.
type LockInfo struct {
	PID        int    `json:"pid"`
	StartedAt  string `json:"startedAt"`
	SocketPath string `json:"socketPath"`
	NetworkID  string `json:"networkId"`
}

// InstanceLock enforces single-instance daemon execution on a state directory via OS flock.
type InstanceLock struct {
	path string
	file *os.File
}

// ErrDaemonAlreadyRunning indicates another live daemon process holds the exclusive state lock.
var ErrDaemonAlreadyRunning = errors.New("daemon: another alt daemon instance is already running for this network")

// AcquireInstanceLock acquires a non-blocking exclusive flock on `<stateDir>/daemon.lock`
// and writes current process diagnostics. If held by another process, it returns ErrDaemonAlreadyRunning.
func AcquireInstanceLock(stateDir, networkID, socketPath string) (*InstanceLock, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("daemon: create state directory: %w", err)
	}
	lockPath := filepath.Join(stateDir, "daemon.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("daemon: open lock file %s: %w", lockPath, err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, err
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		var existing LockInfo
		if raw, rErr := os.ReadFile(lockPath); rErr == nil {
			_ = json.Unmarshal(raw, &existing)
		}
		_ = f.Close()
		if existing.PID > 0 {
			return nil, fmt.Errorf("%w (pid=%d, started=%s)", ErrDaemonAlreadyRunning, existing.PID, existing.StartedAt)
		}
		return nil, ErrDaemonAlreadyRunning
	}

	info := LockInfo{
		PID:        os.Getpid(),
		StartedAt:  time.Now().UTC().Format(time.RFC3339),
		SocketPath: socketPath,
		NetworkID:  networkID,
	}
	encoded, _ := json.MarshalIndent(info, "", "  ")
	encoded = append(encoded, '\n')
	_ = f.Truncate(0)
	_, _ = f.Seek(0, 0)
	_, _ = f.Write(encoded)
	_ = f.Sync()

	return &InstanceLock{
		path: lockPath,
		file: f,
	}, nil
}

// ReadLockInfo inspects `<stateDir>/daemon.lock` without acquiring the exclusive lock.
func ReadLockInfo(stateDir string) (*LockInfo, bool) {
	lockPath := filepath.Join(stateDir, "daemon.lock")
	raw, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, false
	}
	var info LockInfo
	if err := json.Unmarshal(raw, &info); err != nil || info.PID <= 0 {
		return nil, false
	}
	return &info, true
}

// Release unlocks and closes the instance lock file.
func (l *InstanceLock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	err := l.file.Close()
	l.file = nil
	return err
}

// ResolveSocketPath deterministically derives the Unix domain socket path for `stateDir`.
// When `<stateDir>/d.sock` fits within macOS's `sun_path` limit, it lives directly inside `stateDir`.
// Otherwise (for example inside deep macOS `t.TempDir()` paths), it uses a `0700` UID-verified
// directory under `/tmp/alt-<uid>/<hash>/d.sock` so CLI and daemon always agree safely.
func ResolveSocketPath(stateDir string) (string, error) {
	absDir, err := filepath.Abs(strings.TrimSpace(stateDir))
	if err != nil {
		return "", err
	}
	direct := filepath.Join(absDir, "d.sock")
	if len(direct) <= maxUnixSocketPathLen {
		if err := ensureSecureDir(absDir); err != nil {
			return "", err
		}
		return direct, nil
	}

	uid := os.Getuid()
	sum := sha256.Sum256([]byte(absDir))
	shortHash := hex.EncodeToString(sum[:8])
	userRoot := filepath.Join("/tmp", "alt-"+strconv.Itoa(uid))
	if err := ensureSecureDir(userRoot); err != nil {
		return "", err
	}
	sockDir := filepath.Join(userRoot, shortHash)
	if err := ensureSecureDir(sockDir); err != nil {
		return "", err
	}
	return filepath.Join(sockDir, "d.sock"), nil
}

func ensureSecureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("daemon: create secure directory %s: %w", dir, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || (info.Mode()&os.ModeSymlink) != 0 {
		return fmt.Errorf("daemon: refusing symlink or non-directory socket parent %s", dir)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if int(stat.Uid) != os.Getuid() {
			return fmt.Errorf("daemon: socket directory %s is owned by uid %d, expected %d", dir, stat.Uid, os.Getuid())
		}
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// RotatingLogWriter is a concurrency-safe, size-bounded log file writer (`0600` permissions)
// for production daemon stdout/stderr/diagnostic logging.
type RotatingLogWriter struct {
	path       string
	maxBytes   int64
	maxBackups int

	mu   sync.Mutex
	file *os.File
	size int64
}

// NewRotatingLogWriter opens `<path>` inside a `0700` parent directory and rotates at `maxBytes`.
func NewRotatingLogWriter(path string, maxBytes int64, maxBackups int) (*RotatingLogWriter, error) {
	absPath, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return nil, err
	}
	if maxBytes <= 0 {
		maxBytes = defaultLogMaxBytes
	}
	if maxBackups <= 0 {
		maxBackups = defaultLogMaxBackups
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o700); err != nil {
		return nil, err
	}
	w := &RotatingLogWriter{
		path:       absPath,
		maxBytes:   maxBytes,
		maxBackups: maxBackups,
	}
	if err := w.openLocked(); err != nil {
		return nil, err
	}
	return w, nil
}

// Path returns the active log file path.
func (w *RotatingLogWriter) Path() string {
	if w == nil {
		return ""
	}
	return w.path
}

// Write appends p to the log file, rotating backups if size exceeds maxBytes.
func (w *RotatingLogWriter) Write(p []byte) (int, error) {
	if w == nil {
		return len(p), nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		if err := w.openLocked(); err != nil {
			return 0, err
		}
	}
	if w.size+int64(len(p)) > w.maxBytes && w.size > 0 {
		if err := w.rotateLocked(); err != nil {
			return 0, err
		}
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

// Close flushes and closes the active log file.
func (w *RotatingLogWriter) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	_ = w.file.Sync()
	err := w.file.Close()
	w.file = nil
	return err
}

func (w *RotatingLogWriter) openLocked() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_ = f.Chmod(0o600)
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	w.file = f
	w.size = info.Size()
	return nil
}

func (w *RotatingLogWriter) rotateLocked() error {
	if w.file != nil {
		_ = w.file.Sync()
		_ = w.file.Close()
		w.file = nil
	}
	for i := w.maxBackups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", w.path, i)
		dst := fmt.Sprintf("%s.%d", w.path, i+1)
		if _, err := os.Stat(src); err == nil {
			_ = os.Rename(src, dst)
		}
	}
	_ = os.Rename(w.path, fmt.Sprintf("%s.1", w.path))
	return w.openLocked()
}
