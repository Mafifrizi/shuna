//go:build linux

package kdf

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// LockSensitiveMemory pins b into physical RAM and excludes it from Linux core dumps.
// When strict is false, an mlock failure (e.g. RLIMIT_MEMLOCK) returns a non-fatal warning and nil error.
func LockSensitiveMemory(b []byte, strict bool) (string, error) {
	if len(b) == 0 {
		return "", nil
	}

	var warn string
	if err := unix.Mlock(b); err != nil {
		if strict {
			return "", fmt.Errorf("mlock failed in strict mode: %w", err)
		}
		warn = fmt.Sprintf("mlock unavailable (continuing unlocked): %v", err)
	}

	if err := unix.Madvise(b, unix.MADV_DONTDUMP); err != nil {
		if strict && warn == "" {
			_ = unix.Munlock(b)
			return "", fmt.Errorf("madvise(MADV_DONTDUMP) failed in strict mode: %w", err)
		}
		if warn == "" {
			warn = fmt.Sprintf("madvise(MADV_DONTDUMP) unavailable: %v", err)
		}
	}

	return warn, nil
}

// UnlockSensitiveMemory unpins b from physical RAM. Callers should call WipeBytes(b) beforehand.
func UnlockSensitiveMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Munlock(b)
}
