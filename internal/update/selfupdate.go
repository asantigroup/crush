package update

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// binaryName is the name of the crush executable inside release
	// archives.
	binaryName = "crush"

	// checksumsAsset is the name of the checksum file goreleaser attaches
	// to GitHub releases.
	checksumsAsset = "checksums.txt"

	// maxAssetSize bounds downloads to guard against corrupted responses
	// and decompression bombs.
	maxAssetSize = 200 << 20 // 200 MiB
)

// ErrUnsupportedPlatform is returned when self-updating is not supported on
// the current platform.
var ErrUnsupportedPlatform = errors.New("self-update is only supported on Linux")

// Upgrade checks for a newer release and installs it in place of the running
// executable. The returned Info reports the outcome: Upgraded is true when
// the binary was replaced and a restart is needed to run the new version.
func Upgrade(ctx context.Context, current string, client Client) (Info, error) {
	info, err := Check(ctx, current, client)
	if err != nil {
		return info, err
	}
	return Install(ctx, info, client)
}

// Install downloads and verifies the release archive described by info and
// replaces the running executable with the binary it contains. It is a no-op
// when no update is available or the current version is a development build.
func Install(ctx context.Context, info Info, client Client) (Info, error) {
	exePath, err := os.Executable()
	if err != nil {
		return info, fmt.Errorf("failed to resolve executable path: %w", err)
	}
	return installTo(ctx, info, client, exePath)
}

// installTo is [Install] with an explicit target path, for tests.
func installTo(ctx context.Context, info Info, client Client, exePath string) (Info, error) {
	if !info.Available() || info.IsDevelopment() {
		return info, nil
	}
	if !selfUpdateSupported() {
		return info, ErrUnsupportedPlatform
	}

	archive, err := findAsset(info.Assets, archiveAssetName(info.Latest, runtime.GOOS, runtime.GOARCH))
	if err != nil {
		return info, err
	}
	checksums, err := findAsset(info.Assets, checksumsAsset)
	if err != nil {
		return info, err
	}

	archivePath, err := downloadVerified(ctx, client, archive, checksums)
	if err != nil {
		return info, err
	}
	defer os.Remove(archivePath) //nolint:errcheck

	// The new binary must land on the same filesystem as the executable
	// so the final rename is atomic.
	newPath, err := os.CreateTemp(filepath.Dir(exePath), ".crush-new-")
	if err != nil {
		return info, fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(newPath.Name()) //nolint:errcheck
	if err := newPath.Close(); err != nil {
		return info, fmt.Errorf("failed to close temporary file: %w", err)
	}

	if err := extractBinary(archivePath, newPath.Name()); err != nil {
		return info, err
	}

	if err := replaceExecutable(newPath.Name(), exePath); err != nil {
		return info, err
	}

	info.Upgraded = true
	return info, nil
}

// findAsset returns the release asset with the given name.
func findAsset(assets []Asset, name string) (Asset, error) {
	for _, asset := range assets {
		if asset.Name == name {
			return asset, nil
		}
	}
	return Asset{}, fmt.Errorf("release asset %q not found", name)
}

// archiveAssetName returns the goreleaser archive name for the given
// version, OS, and architecture, e.g. crush_0.9.1_Linux_x86_64.tar.gz.
func archiveAssetName(version, goos, goarch string) string {
	osName := strings.ToUpper(goos[:1]) + goos[1:]
	archName := goarch
	switch goarch {
	case "amd64":
		archName = "x86_64"
	case "386":
		archName = "i386"
	case "arm":
		archName = "armv7"
	}
	return fmt.Sprintf("crush_%s_%s_%s.tar.gz", version, osName, archName)
}

// downloadVerified downloads the release archive while hashing it, verifies
// the checksum, and returns the path it was written to.
func downloadVerified(ctx context.Context, client Client, archive, checksums Asset) (string, error) {
	expected, err := fetchChecksum(ctx, client, checksums, archive.Name)
	if err != nil {
		return "", err
	}

	rc, err := client.Download(ctx, archive.DownloadURL)
	if err != nil {
		return "", fmt.Errorf("failed to download %s: %w", archive.Name, err)
	}
	defer rc.Close() //nolint:errcheck

	f, err := os.CreateTemp("", "crush-update-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %w", err)
	}
	path := f.Name()

	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(f, hasher), io.LimitReader(rc, maxAssetSize+1))
	if err != nil {
		f.Close()       //nolint:errcheck
		os.Remove(path) //nolint:errcheck
		return "", fmt.Errorf("failed to download %s: %w", archive.Name, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path) //nolint:errcheck
		return "", fmt.Errorf("failed to write %s: %w", archive.Name, err)
	}
	if written > maxAssetSize {
		os.Remove(path) //nolint:errcheck
		return "", fmt.Errorf("release asset %s exceeds %d bytes", archive.Name, maxAssetSize)
	}

	got := hex.EncodeToString(hasher.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(got)) != 1 {
		os.Remove(path) //nolint:errcheck
		return "", fmt.Errorf("checksum mismatch for %s: expected %s, got %s", archive.Name, expected, got)
	}
	return path, nil
}

// fetchChecksum downloads checksums.txt and returns the hex digest recorded
// for the named asset.
func fetchChecksum(ctx context.Context, client Client, checksums Asset, name string) (string, error) {
	rc, err := client.Download(ctx, checksums.DownloadURL)
	if err != nil {
		return "", fmt.Errorf("failed to download %s: %w", checksums.Name, err)
	}
	defer rc.Close() //nolint:errcheck

	bts, err := io.ReadAll(io.LimitReader(rc, 1<<20))
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", checksums.Name, err)
	}
	for line := range strings.SplitSeq(string(bts), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		// Tolerate the "./" prefix `sha256sum ./*` emits and the "*"
		// binary-mode marker.
		file := strings.TrimPrefix(strings.TrimPrefix(fields[1], "*"), "./")
		if file == name {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("no checksum found for %s in %s", name, checksums.Name)
}

// extractBinary copies the crush binary out of the release archive to dst.
func extractBinary(archivePath, dst string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open archive: %w", err)
	}
	defer f.Close() //nolint:errcheck

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("failed to decompress archive: %w", err)
	}
	defer gz.Close() //nolint:errcheck

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Base(filepath.FromSlash(hdr.Name)) != binaryName {
			continue
		}
		if hdr.Size > maxAssetSize {
			return fmt.Errorf("archive entry %q exceeds %d bytes", hdr.Name, maxAssetSize)
		}
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return fmt.Errorf("failed to write binary: %w", err)
		}
		if _, err := io.CopyN(out, tr, hdr.Size); err != nil {
			out.Close() //nolint:errcheck
			return fmt.Errorf("failed to write binary: %w", err)
		}
		return out.Close()
	}
	return fmt.Errorf("binary %q not found in archive", binaryName)
}
