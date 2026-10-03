//go:build !linux

package update

// selfUpdateSupported reports whether this platform can replace the running
// executable. Only Linux is supported.
func selfUpdateSupported() bool { return false }

// replaceExecutable is only implemented on Linux; elsewhere callers get
// [ErrUnsupportedPlatform] before any download happens.
func replaceExecutable(_, _ string) error {
	return ErrUnsupportedPlatform
}
