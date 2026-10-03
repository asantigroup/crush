//go:build linux

package update

import (
	"fmt"
	"os"
)

// selfUpdateSupported reports whether this platform can replace the running
// executable. Only Linux is supported.
func selfUpdateSupported() bool { return true }

// replaceExecutable atomically replaces the binary at dst with the one at
// src. On Linux, rename(2) over a running executable is safe: the running
// process keeps its open inode while the next launch picks up the new file.
func replaceExecutable(src, dst string) error {
	if err := os.Chmod(src, 0o755); err != nil {
		return fmt.Errorf("failed to mark new binary executable: %w", err)
	}
	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("failed to replace binary: %w", err)
	}
	return nil
}
