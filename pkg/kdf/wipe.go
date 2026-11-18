package kdf

import "runtime"

// WipeBytes overwrites b with zeros in a way resistant to compiler dead-store elimination.
//
//go:noinline
func WipeBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	clear(b)
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
