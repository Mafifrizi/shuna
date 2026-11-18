//go:build linux

package kdf

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// madviseDontDump aligns [b[0], b[len-1]] to OS page boundaries because Linux
// madvise(2) requires page-aligned start addresses (otherwise returning EINVAL).
func madviseDontDump(b []byte) error {
	pageSize := uintptr(os.Getpagesize())
	start := uintptr(unsafe.Pointer(&b[0])) &^ (pageSize - 1)
	end := (uintptr(unsafe.Pointer(&b[len(b)-1])) + 1 + pageSize - 1) &^ (pageSize - 1)
	_, _, errno := unix.Syscall(unix.SYS_MADVISE, start, end-start, uintptr(unix.MADV_DONTDUMP))
	runtime.KeepAlive(b)
	if errno != 0 {
		return errno
	}
	return nil
}

// LockSensitiveMemory pins b into physical RAM and excludes it from Linux core dumps.
// When strict is false, an mlock or madvise failure returns a non-fatal warning and nil error.
func LockSensitiveMemory(b []byte, strict bool) (string, error) {
	if len(b) == 0 {
		return "", nil
	}

	var warnings []string
	mlockOK := false
	if err := unix.Mlock(b); err != nil {
		if strict {
			return "", fmt.Errorf("mlock failed in strict mode: %w", err)
		}
		warnings = append(warnings, fmt.Sprintf("mlock unavailable (continuing unlocked): %v", err))
	} else {
		mlockOK = true
	}

	if err := madviseDontDump(b); err != nil {
		if strict {
			if mlockOK {
				_ = unix.Munlock(b)
			}
			return "", fmt.Errorf("madvise(MADV_DONTDUMP) failed in strict mode: %w", err)
		}
		warnings = append(warnings, fmt.Sprintf("madvise(MADV_DONTDUMP) unavailable: %v", err))
	}

	return strings.Join(warnings, "; "), nil
}

// UnlockSensitiveMemory unpins b from physical RAM. Callers should call WipeBytes(b) beforehand.
func UnlockSensitiveMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Munlock(b)
}
