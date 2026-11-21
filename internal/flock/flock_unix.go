//go:build unix

package flock

import (
	"errors"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func lockFile(f *os.File, exclusive bool) error {
	how := unix.LOCK_SH
	if exclusive {
		how = unix.LOCK_EX
	}
	fd := int(f.Fd())
	for {
		err := unix.Flock(fd, how)
		runtime.KeepAlive(f)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

func unlockFile(f *os.File) error {
	fd := int(f.Fd())
	for {
		err := unix.Flock(fd, unix.LOCK_UN)
		runtime.KeepAlive(f)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

func isReadOnlyFS(err error) bool {
	return errors.Is(err, unix.EROFS)
}
