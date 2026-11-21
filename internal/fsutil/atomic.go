package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteAtomic writes data to path via a 0600 temporary file, fsync, chmod,
// and atomic rename, refusing pre-existing symlinks at dir or path.
func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink output directory: %s", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("output parent is not a directory: %s", dir)
	}

	if targetInfo, err := os.Lstat(path); err == nil {
		if targetInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write through symlink: %s", path)
		}
		if targetInfo.IsDir() {
			return fmt.Errorf("refusing to overwrite directory: %s", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".shuna.tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if n, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	} else if n != len(data) {
		cleanup()
		return fmt.Errorf("short write: %d of %d bytes", n, len(data))
	}
	if err := tmp.Chmod(perm); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
