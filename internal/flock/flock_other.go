//go:build !unix && !windows

package flock

import "os"

func lockFile(*os.File, bool) error {
	return nil
}

func unlockFile(*os.File) error {
	return nil
}

func isReadOnlyFS(error) bool {
	return false
}
