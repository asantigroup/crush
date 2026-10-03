package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckForUpdate_Old(t *testing.T) {
	info, err := Check(t.Context(), "v0.10.0", testClient{tag: "v0.11.0"})
	require.NoError(t, err)
	require.NotNil(t, info)
	require.True(t, info.Available())
}

func TestCheckForUpdate_Beta(t *testing.T) {
	t.Run("current is stable", func(t *testing.T) {
		info, err := Check(t.Context(), "v0.10.0", testClient{tag: "v0.11.0-beta.1"})
		require.NoError(t, err)
		require.NotNil(t, info)
		require.False(t, info.Available())
	})

	t.Run("current is also beta", func(t *testing.T) {
		info, err := Check(t.Context(), "v0.11.0-beta.1", testClient{tag: "v0.11.0-beta.2"})
		require.NoError(t, err)
		require.NotNil(t, info)
		require.True(t, info.Available())
	})

	t.Run("current is beta, latest isn't", func(t *testing.T) {
		info, err := Check(t.Context(), "v0.11.0-beta.1", testClient{tag: "v0.11.0"})
		require.NoError(t, err)
		require.NotNil(t, info)
		require.True(t, info.Available())
	})
}

func TestArchiveAssetName(t *testing.T) {
	t.Parallel()
	require.Equal(t, "crush_0.9.1_Linux_x86_64.tar.gz", archiveAssetName("0.9.1", "linux", "amd64"))
	require.Equal(t, "crush_0.9.1_Linux_arm64.tar.gz", archiveAssetName("0.9.1", "linux", "arm64"))
	require.Equal(t, "crush_0.9.1_Linux_armv7.tar.gz", archiveAssetName("0.9.1", "linux", "arm"))
	require.Equal(t, "crush_0.9.1_Linux_i386.tar.gz", archiveAssetName("0.9.1", "linux", "386"))
}

func TestInstallTo_Noop(t *testing.T) {
	t.Parallel()

	t.Run("no update available", func(t *testing.T) {
		t.Parallel()
		info, err := installTo(t.Context(), Info{Current: "1.0.0", Latest: "1.0.0"}, testClient{tag: "v1.0.0"}, "/nope")
		require.NoError(t, err)
		require.False(t, info.Upgraded)
	})

	t.Run("development build", func(t *testing.T) {
		t.Parallel()
		info, err := installTo(t.Context(), Info{Current: "devel", Latest: "1.0.0"}, testClient{tag: "v1.0.0"}, "/nope")
		require.NoError(t, err)
		require.False(t, info.Upgraded)
	})
}

func TestInstallTo_Upgrade(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("self-update is only supported on Linux")
	}

	const newBinary = "#!/bin/sh\necho new crush\n"

	srv, client := newReleaseServer(t, "v1.1.0", map[string][]byte{
		"crush": []byte(newBinary),
	})
	t.Cleanup(srv.Close)

	info, err := Check(t.Context(), "v1.0.0", client)
	require.NoError(t, err)
	require.True(t, info.Available())
	require.NotEmpty(t, info.Assets)

	dir := t.TempDir()
	exePath := filepath.Join(dir, "crush")
	require.NoError(t, os.WriteFile(exePath, []byte("old"), 0o755))

	info, err = installTo(t.Context(), info, client, exePath)
	require.NoError(t, err)
	require.True(t, info.Upgraded)

	got, err := os.ReadFile(exePath)
	require.NoError(t, err)
	require.Equal(t, newBinary, string(got))

	fi, err := os.Stat(exePath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), fi.Mode().Perm())

	// No leftover temporary files next to the executable.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "crush", entries[0].Name())
}

func TestInstallTo_ChecksumMismatch(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("self-update is only supported on Linux")
	}

	srv, client := newReleaseServer(t, "v1.1.0", map[string][]byte{
		"crush": []byte("new"),
	})
	t.Cleanup(srv.Close)
	client.corruptChecksum = true

	info, err := Check(t.Context(), "v1.0.0", client)
	require.NoError(t, err)

	dir := t.TempDir()
	exePath := filepath.Join(dir, "crush")
	require.NoError(t, os.WriteFile(exePath, []byte("old"), 0o755))

	_, err = installTo(t.Context(), info, client, exePath)
	require.ErrorContains(t, err, "checksum mismatch")

	got, err := os.ReadFile(exePath)
	require.NoError(t, err)
	require.Equal(t, "old", string(got), "binary must be untouched on failure")

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "no leftover temporary files")
}

func TestInstallTo_MissingAsset(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("self-update is only supported on Linux")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"tag_name": "v1.1.0",
			"assets": []map[string]any{
				{"name": "checksums.txt", "browser_download_url": "http://invalid.invalid/checksums.txt"},
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := &testClient{tag: "v1.1.0", apiURL: srv.URL + "/releases/latest"}

	dir := t.TempDir()
	exePath := filepath.Join(dir, "crush")
	require.NoError(t, os.WriteFile(exePath, []byte("old"), 0o755))

	info, err := Check(t.Context(), "v1.0.0", client)
	require.NoError(t, err)

	_, err = installTo(t.Context(), info, client, exePath)
	require.ErrorContains(t, err, "release asset")
}

// newReleaseServer serves a fake GitHub API with a latest release pointing
// at generated archive and checksum assets for the current platform.
func newReleaseServer(t *testing.T, tag string, files map[string][]byte) (*httptest.Server, *testClient) {
	t.Helper()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)

	archiveName := archiveAssetName("1.1.0", runtime.GOOS, runtime.GOARCH)

	var archiveBts []byte
	{
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		for name, content := range files {
			require.NoError(t, tw.WriteHeader(&tar.Header{
				Name: "crush/" + name,
				Mode: 0o755,
				Size: int64(len(content)),
			}))
			_, err := tw.Write(content)
			require.NoError(t, err)
		}
		require.NoError(t, tw.Close())
		require.NoError(t, gz.Close())
		archiveBts = buf.Bytes()
	}

	sum := sha256.Sum256(archiveBts)
	checksums := fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), archiveName)

	client := &testClient{tag: tag, apiURL: srv.URL + "/releases/latest"}

	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"tag_name": tag,
			"assets": []map[string]any{
				{"name": archiveName, "browser_download_url": srv.URL + "/dl/" + archiveName},
				{"name": "checksums.txt", "browser_download_url": srv.URL + "/dl/checksums.txt"},
			},
		})
	})
	mux.HandleFunc("/dl/checksums.txt", func(w http.ResponseWriter, _ *http.Request) {
		if client.corruptChecksum {
			_, _ = w.Write([]byte("0000000000000000000000000000000000000000000000000000000000000000  " + archiveName + "\n"))
			return
		}
		_, _ = w.Write([]byte(checksums))
	})
	mux.HandleFunc("/dl/"+archiveName, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archiveBts)
	})

	return srv, client
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

type testClient struct {
	tag string
	// apiURL overrides the GitHub API endpoint (tests point it at an
	// httptest server).
	apiURL string
	// corruptChecksum makes checksum lookups return a wrong digest.
	corruptChecksum bool
}

func httpGet(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req) //nolint:gosec
}

// Latest implements [Client].
func (t testClient) Latest(ctx context.Context) (*Release, error) {
	if t.apiURL == "" {
		return &Release{
			TagName: t.tag,
			HTMLURL: "https://example.org",
		}, nil
	}
	resp, err := httpGet(ctx, t.apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}
	return &release, nil
}

// Download implements [Client].
func (t testClient) Download(ctx context.Context, url string) (io.ReadCloser, error) {
	resp, err := httpGet(ctx, url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s returned %d", url, resp.StatusCode)
	}
	return resp.Body, nil
}
