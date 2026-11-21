package flock

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
)

var (
	locksMu sync.Mutex
	locks   = make(map[string]*sync.RWMutex)
)

func canonicalLockKey(targetPath string) string {
	clean := filepath.Clean(targetPath)
	if abs, err := filepath.Abs(clean); err == nil {
		return abs + ".lock"
	}
	return clean + ".lock"
}

func getPathMutex(key string) *sync.RWMutex {
	locksMu.Lock()
	defer locksMu.Unlock()
	mu, ok := locks[key]
	if !ok {
		mu = &sync.RWMutex{}
		locks[key] = mu
	}
	return mu
}

// WithExclusive acquires an in-process write lock and an OS exclusive file lock
// on <targetPath>.lock before running fn. The sidecar lockfile is never deleted.
func WithExclusive(targetPath string, perm os.FileMode, fn func() error) error {
	if targetPath == "" {
		return errors.New("flock: target path is required")
	}
	if fn == nil {
		return nil
	}
	if perm == 0 {
		perm = 0600
	}

	lockPath := filepath.Clean(targetPath) + ".lock"
	mu := getPathMutex(canonicalLockKey(targetPath))
	mu.Lock()
	defer mu.Unlock()

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, perm)
	if err != nil {
		return err
	}
	if err := lockFile(f, true); err != nil {
		_ = f.Close()
		return err
	}
	defer func() {
		_ = unlockFile(f)
		_ = f.Close()
	}()

	return fn()
}

// WithShared acquires an in-process read lock and an OS shared file lock on
// <targetPath>.lock before running fn. When allowReadOnlyFallback is true and
// creating/opening the lockfile fails due to read-only permissions or missing
// parent directory, fn runs under the in-process read lock without an OS lock.
func WithShared(targetPath string, perm os.FileMode, allowReadOnlyFallback bool, fn func() error) error {
	if targetPath == "" {
		return errors.New("flock: target path is required")
	}
	if fn == nil {
		return nil
	}
	if perm == 0 {
		perm = 0600
	}

	lockPath := filepath.Clean(targetPath) + ".lock"
	mu := getPathMutex(canonicalLockKey(targetPath))
	mu.RLock()
	defer mu.RUnlock()

	f, err := os.OpenFile(lockPath, os.O_RDONLY, 0)
	if err != nil && os.IsNotExist(err) {
		f, err = os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, perm)
	}
	if err != nil {
		if allowReadOnlyFallback && (os.IsPermission(err) || isReadOnlyFS(err) || os.IsNotExist(err)) {
			return fn()
		}
		return err
	}

	if err := lockFile(f, false); err != nil {
		_ = f.Close()
		return err
	}
	defer func() {
		_ = unlockFile(f)
		_ = f.Close()
	}()

	return fn()
}
