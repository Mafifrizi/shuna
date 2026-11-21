//go:build windows

package flock

import (
	"errors"
	"os"
	"runtime"

	"golang.org/x/sys/windows"
)

func lockFile(f *os.File, exclusive bool) error {
	var flags uint32
	if exclusive {
		flags = windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	var ol windows.Overlapped
	err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, &ol)
	runtime.KeepAlive(f)
	return err
}

func unlockFile(f *os.File) error {
	var ol windows.Overlapped
	err := windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &ol)
	runtime.KeepAlive(f)
	return err
}

func isReadOnlyFS(err error) bool {
	return errors.Is(err, windows.ERROR_WRITE_PROTECT)
}
