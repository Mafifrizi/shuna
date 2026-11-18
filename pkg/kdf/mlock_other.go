//go:build !linux

package kdf

import "errors"

// LockSensitiveMemory is a non-Linux fallback stub.
// When strict is true, it fails closed because memory pinning is unsupported.
func LockSensitiveMemory(b []byte, strict bool) (string, error) {
	if len(b) == 0 {
		return "", nil
	}
	if strict {
		return "", errors.New("mlock/MADV_DONTDUMP unsupported on this platform in strict mode")
	}
	return "mlock/MADV_DONTDUMP unsupported on this platform (continuing unlocked)", nil
}

// UnlockSensitiveMemory is a no-op on non-Linux platforms.
func UnlockSensitiveMemory(b []byte) error {
	return nil
}
