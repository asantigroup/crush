package update

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// isolateTokenEnv points gh's config at an empty directory and clears all
// token environment variables, so tests only see what they set themselves.
func isolateTokenEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GH_CONFIG_DIR", t.TempDir())
	for _, key := range tokenEnvVars {
		t.Setenv(key, "")
	}
}

func TestGithubToken_EnvPrecedence(t *testing.T) {
	isolateTokenEnv(t)

	t.Setenv("GITHUB_TOKEN", "from-github")
	require.Equal(t, "from-github", githubToken())

	t.Setenv("GH_TOKEN", "from-gh")
	require.Equal(t, "from-gh", githubToken())

	t.Setenv("CRUSH_GITHUB_TOKEN", "from-crush")
	require.Equal(t, "from-crush", githubToken())
}

func TestGithubToken_None(t *testing.T) {
	isolateTokenEnv(t)
	require.Empty(t, githubToken())
}

func TestGithubToken_GhHosts(t *testing.T) {
	isolateTokenEnv(t)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(`github.com:
    git_protocol: ssh
    users:
        someone:
            oauth_token: ghp_nested
    oauth_token: ghp_host
    user: someone
ghe.example.com:
    oauth_token: ghp_other
`), 0o600))
	t.Setenv("GH_CONFIG_DIR", dir)

	require.Equal(t, "ghp_host", githubToken())
}

func TestGithubToken_GhHostsQuoted(t *testing.T) {
	isolateTokenEnv(t)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(`gist.github.com:
    oauth_token: ghp_gist
github.com:
    oauth_token: "ghp_quoted"
`), 0o600))
	t.Setenv("GH_CONFIG_DIR", dir)

	require.Equal(t, "ghp_quoted", githubToken())
}

func TestGitHubLatest_SendsAuthorization(t *testing.T) {
	isolateTokenEnv(t)
	t.Setenv("CRUSH_GITHUB_TOKEN", "testtoken")

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		writeJSON(w, map[string]any{
			"tag_name": "v1.2.3",
			"assets":   []map[string]any{},
		})
	}))
	t.Cleanup(srv.Close)

	origURL := githubApiUrl
	githubApiUrl = srv.URL + "/releases/latest"
	t.Cleanup(func() { githubApiUrl = origURL })

	release, err := (&github{}).Latest(t.Context())
	require.NoError(t, err)
	require.NotNil(t, release)
	require.Equal(t, "v1.2.3", release.TagName)
	require.Equal(t, "Bearer testtoken", gotAuth)
}

func TestGitHubLatest_NoTokenWhenUnset(t *testing.T) {
	isolateTokenEnv(t)

	gotAuth := "sentinel"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		writeJSON(w, map[string]any{"tag_name": "v1.2.3"})
	}))
	t.Cleanup(srv.Close)

	origURL := githubApiUrl
	githubApiUrl = srv.URL + "/releases/latest"
	t.Cleanup(func() { githubApiUrl = origURL })

	_, err := (&github{}).Latest(t.Context())
	require.NoError(t, err)
	require.Empty(t, gotAuth)
}
