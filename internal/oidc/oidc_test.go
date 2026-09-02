package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/charmbracelet/crush/internal/oauth"
	"github.com/stretchr/testify/require"
)

func TestDiscover(t *testing.T) {
	t.Parallel()

	t.Run("origin metadata", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/oauth-authorization-server" {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 "https://ignored-issuer",
				"authorization_endpoint": srv2url(r) + "/_auth/authorize",
				"token_endpoint":         srv2url(r) + "/_auth/token",
			})
		}))
		t.Cleanup(srv.Close)

		meta, err := Discover(context.Background(), srv.URL+"/golem/llm/v1")
		require.NoError(t, err)
		require.Contains(t, meta.AuthorizationEndpoint, "/_auth/authorize")
		require.Contains(t, meta.TokenEndpoint, "/_auth/token")
		require.False(t, meta.SupportsDeviceFlow())
	})

	t.Run("openid configuration fallback", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/openid-configuration" {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 "https://ignored-issuer",
				"authorization_endpoint": srv2url(r) + "/authorize",
				"token_endpoint":         srv2url(r) + "/token",
			})
		}))
		t.Cleanup(srv.Close)

		meta, err := Discover(context.Background(), srv.URL)
		require.NoError(t, err)
		require.Equal(t, srv.URL+"/token", meta.TokenEndpoint)
	})

	t.Run("nothing found", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.NotFoundHandler())
		t.Cleanup(srv.Close)

		_, err := Discover(context.Background(), srv.URL)
		require.ErrorContains(t, err, "no OAuth authorization server found")
	})
}

// srv2url rebuilds the server base URL from an incoming request, for
// handlers that need to reference their own host.
func srv2url(r *http.Request) string {
	u := url.URL{Scheme: "http", Host: r.Host}
	return u.String()
}

func TestDiscoveryCandidateOrder(t *testing.T) {
	t.Parallel()

	u, err := url.Parse("https://agent.asanti.dev/golem/llm/v1")
	require.NoError(t, err)

	got := discoveryCandidates(u)
	require.Equal(t, []string{
		"https://agent.asanti.dev/.well-known/oauth-authorization-server",
		"https://agent.asanti.dev/golem/llm/.well-known/oauth-authorization-server",
		"https://agent.asanti.dev/golem/.well-known/oauth-authorization-server",
		"https://agent.asanti.dev/.well-known/openid-configuration",
	}, got)
}

func TestParseManualCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		line  string
		code  string
		state string
	}{
		{"full callback URL", "http://127.0.0.1:8765/callback?code=abc&state=xyz", "abc", "xyz"},
		{"bare fragment", "code=abc&state=xyz", "abc", "xyz"},
		{"bare code", "  abc-def_ghi  ", "abc-def_ghi", ""},
		{"empty", "", "", ""},
		{"prose ignored", "this is not a code", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			code, state, err := parseManualCode(tt.line)
			require.NoError(t, err)
			require.Equal(t, tt.code, code)
			require.Equal(t, tt.state, state)
		})
	}
}

func TestRefreshToken(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		mu.Lock()
		gotForm = r.PostForm
		mu.Unlock()
		_, _ = w.Write([]byte(`{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`))
	}))
	t.Cleanup(srv.Close)

	token := &oauth.Token{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		Client: &oauth.OAuthClient{
			ClientID: "cid",
			AuthURL:  srv.URL + "/_auth/authorize",
			TokenURL: srv.URL + "/_auth/token",
		},
	}

	refreshed, err := RefreshToken(context.Background(), token, "https://unused.example")
	require.NoError(t, err)
	require.Equal(t, "new-access", refreshed.AccessToken)
	require.Equal(t, "new-refresh", refreshed.RefreshToken)
	require.Equal(t, "cid", refreshed.Client.ClientID)
	require.False(t, refreshed.IsExpired())

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"old-refresh"},
		"client_id":     {"cid"},
	}, gotForm)
}

func TestRefreshTokenKeepsRefreshWhenOmitted(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"new-access","expires_in":3600}`))
	}))
	t.Cleanup(srv.Close)

	token := &oauth.Token{
		RefreshToken: "old-refresh",
		Client:       &oauth.OAuthClient{ClientID: "cid", TokenURL: srv.URL + "/token"},
	}
	refreshed, err := RefreshToken(context.Background(), token, "")
	require.NoError(t, err)
	require.Equal(t, "old-refresh", refreshed.RefreshToken)
}

// fakeAuthServer is a minimal RFC 8414 + RFC 7591 + PKCE authorization
// server. The URL is only known after the server starts, so handlers
// read it through the server method at request time.
type fakeAuthServer struct {
	srv        *httptest.Server
	clientID   string
	withDevice bool

	mu                   sync.Mutex
	registered           map[string]any
	authParams           url.Values
	tokenRequest         url.Values
	tokenCalls           int
	challenge            bool
	crossOriginChallenge bool
}

func newFakeAuthServer(t *testing.T, withDevice bool) *fakeAuthServer {
	t.Helper()
	f := &fakeAuthServer{clientID: "registered-client", withDevice: withDevice}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		meta := map[string]any{
			"issuer":                           "https://fake.example",
			"authorization_endpoint":           f.url() + "/_auth/authorize",
			"token_endpoint":                   f.url() + "/_auth/token",
			"registration_endpoint":            f.url() + "/_auth/register",
			"code_challenge_methods_supported": []string{"S256"},
			"scopes_supported":                 []string{"openid"},
		}
		if withDevice {
			meta["device_authorization_endpoint"] = f.url() + "/_auth/device"
		}
		_ = json.NewEncoder(w).Encode(meta)
	})
	mux.HandleFunc("/_auth/register", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		f.mu.Lock()
		f.registered = body
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"client_id": f.clientID})
	})
	mux.HandleFunc("/_auth/authorize", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.authParams = r.URL.Query()
		f.mu.Unlock()
		http.Redirect(w, r, "https://fake.example/approved", http.StatusFound)
	})
	mux.HandleFunc("/_auth/device", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"device_code":"dev-1","user_code":"ABCD-EFGH","verification_uri":"https://fake.example/device","expires_in":300,"interval":1}`))
	})
	mux.HandleFunc("/_auth/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		f.mu.Lock()
		defer f.mu.Unlock()
		f.tokenRequest = r.PostForm
		f.tokenCalls++
		// In device mode the first poll reports pending, the second
		// succeeds; in authorization code mode every exchange succeeds.
		if withDevice && r.PostForm.Get("grant_type") == deviceGrantType && f.tokenCalls == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"the-access-token","refresh_token":"the-refresh-token","expires_in":3600}`))
	})

	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		challenge := f.challenge
		cross := f.crossOriginChallenge
		f.mu.Unlock()
		if !challenge {
			http.NotFound(w, r)
			return
		}
		metadataURL := f.url() + "/golem/llm/.well-known/oauth-protected-resource"
		if cross {
			metadataURL = "https://evil.example/.well-known/oauth-protected-resource"
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="invalid_token", resource_metadata=%q`, metadataURL))
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	})
	mux.HandleFunc("/golem/llm/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":                 "https://fake.example/golem/llm",
			"authorization_servers":    []string{f.url()},
			"bearer_methods_supported": []string{"header"},
		})
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAuthServer) url() string {
	return f.srv.URL
}

// stubBrowser replaces the openBrowser hook for the duration of the test.
func stubBrowser(t *testing.T, fn func(u string) error) {
	t.Helper()
	orig := openBrowser
	openBrowser = fn
	t.Cleanup(func() { openBrowser = orig })
}

// TestLoginAuthorizationCodeFlow drives the full flow without a browser:
// the browser stub "opens" the authorization URL by parsing it and hitting
// the loopback callback with a matching code and state.
func TestLoginAuthorizationCodeFlow(t *testing.T) {
	f := newFakeAuthServer(t, false)

	stubBrowser(t, func(u string) error {
		parsed, err := url.Parse(u)
		require.NoError(t, err)

		// A real browser would visit the authorization endpoint first;
		// the fake server records that request and redirects.
		noRedirect := &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := noRedirect.Get(u) //nolint:gosec
		require.NoError(t, err)
		require.Equal(t, http.StatusFound, resp.StatusCode)
		_ = resp.Body.Close() //nolint:errcheck

		// Then it follows the redirect to the loopback callback.
		q := parsed.Query()
		callback := q.Get("redirect_uri") + "?code=fake-code&state=" + url.QueryEscape(q.Get("state"))
		cbResp, err := http.Get(callback) //nolint:gosec
		require.NoError(t, err)
		defer cbResp.Body.Close() //nolint:errcheck
		body, _ := io.ReadAll(cbResp.Body)
		require.Contains(t, string(body), "</html>")
		return nil
	})

	token, err := Login(context.Background(), Options{APIBaseURL: f.url() + "/v1"})
	require.NoError(t, err)

	require.Equal(t, "the-access-token", token.AccessToken)
	require.Equal(t, "the-refresh-token", token.RefreshToken)
	require.False(t, token.IsExpired())

	f.mu.Lock()
	defer f.mu.Unlock()

	// Dynamic registration happened with the loopback redirect and no
	// client authentication.
	require.Equal(t, "crush", f.registered["client_name"])
	require.Equal(t, "none", f.registered["token_endpoint_auth_method"])
	require.Equal(t, f.clientID, token.Client.ClientID)
	require.Equal(t, f.url()+"/_auth/token", token.Client.TokenURL)

	// The authorization request carried PKCE and the registered client.
	require.Equal(t, f.clientID, f.authParams.Get("client_id"))
	require.Equal(t, "S256", f.authParams.Get("code_challenge_method"))
	require.NotEmpty(t, f.authParams.Get("code_challenge"))
	require.Equal(t, "openid", f.authParams.Get("scope"))

	// The token exchange proved possession of the verifier matching the
	// challenge sent to the authorization endpoint.
	verifier := f.tokenRequest.Get("code_verifier")
	require.NotEmpty(t, verifier)
	require.Equal(t, generateCodeChallenge(verifier), f.authParams.Get("code_challenge"))
	require.Equal(t, "fake-code", f.tokenRequest.Get("code"))
}

// TestLoginPastedCode verifies the no-browser fallback: the browser never
// opens, a paste with a mismatching state is ignored, and a bare pasted
// code completes the flow.
func TestLoginPastedCode(t *testing.T) {
	f := newFakeAuthServer(t, false)

	stubBrowser(t, func(string) error {
		t.Error("browser must not open in NoBrowser mode")
		return nil
	})

	stdinR, stdinW := io.Pipe()
	go func() {
		_, _ = stdinW.Write([]byte("http://127.0.0.1:1/callback?code=wrong&state=bogus\n"))
		_, _ = stdinW.Write([]byte("pastable-code\n"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	token, err := Login(ctx, Options{
		APIBaseURL: f.url() + "/v1",
		NoBrowser:  true,
		Stdin:      stdinR,
		Stdout:     io.Discard,
	})
	require.NoError(t, err)
	require.Equal(t, "the-access-token", token.AccessToken)

	f.mu.Lock()
	defer f.mu.Unlock()
	require.Equal(t, "pastable-code", f.tokenRequest.Get("code"))
}

// TestLoginDeviceFlow covers the RFC 8628 path taken when the server
// advertises device authorization and no browser is available.
func TestLoginDeviceFlow(t *testing.T) {
	f := newFakeAuthServer(t, true)

	stubBrowser(t, func(string) error { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	token, err := Login(ctx, Options{
		APIBaseURL: f.url() + "/v1",
		NoBrowser:  true,
		Stdout:     io.Discard,
	})
	require.NoError(t, err)
	require.Equal(t, "the-access-token", token.AccessToken)
	require.Equal(t, f.clientID, token.Client.ClientID)
	require.Equal(t, "urn:ietf:params:oauth:grant-type:device_code", deviceGrantType)
}

func TestGenerateCodeChallenge(t *testing.T) {
	t.Parallel()

	verifier := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	challenge := generateCodeChallenge(verifier)
	require.Len(t, challenge, 43)
	require.NotContains(t, challenge, "=")
}

func TestBearerChallengeParam(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers []string
		want    string
	}{
		{
			"simple",
			[]string{`Bearer resource_metadata="https://a.example/.well-known/oauth-protected-resource"`},
			"https://a.example/.well-known/oauth-protected-resource",
		},
		{
			"with error params first",
			[]string{`Bearer error="invalid_token", error_description="token expired", resource_metadata="https://a.example/prm"`},
			"https://a.example/prm",
		},
		{
			"other scheme ignored",
			[]string{`Basic realm="x"`, `Bearer resource_metadata="https://a.example/prm"`},
			"https://a.example/prm",
		},
		{
			"no challenge",
			[]string{`Bearer realm="x"`},
			"",
		},
		{
			"no header",
			nil,
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, bearerChallengeParam(tt.headers, "resource_metadata"))
		})
	}
}

// TestLoginViaProtectedResourceChallenge covers the RFC 9725 path: the
// API challenges an unauthenticated probe, the challenge names protected
// resource metadata, and the resource URI flows into the authorize and
// token requests plus the persisted client.
func TestLoginViaProtectedResourceChallenge(t *testing.T) {
	f := newFakeAuthServer(t, false)

	// The API surface challenges unauthenticated requests.
	f.mu.Lock()
	f.challenge = true
	f.mu.Unlock()

	stubBrowser(t, func(u string) error {
		parsed, err := url.Parse(u)
		require.NoError(t, err)
		q := parsed.Query()
		require.Equal(t, "https://fake.example/golem/llm", q.Get("resource"))
		callback := q.Get("redirect_uri") + "?code=fake-code&state=" + url.QueryEscape(q.Get("state"))
		resp, err := http.Get(callback) //nolint:gosec
		require.NoError(t, err)
		_ = resp.Body.Close() //nolint:errcheck
		return nil
	})

	token, err := Login(context.Background(), Options{APIBaseURL: f.url() + "/v1", Stdout: io.Discard})
	require.NoError(t, err)
	require.Equal(t, "the-access-token", token.AccessToken)

	f.mu.Lock()
	require.Equal(t, []string{"https://fake.example/golem/llm"}, f.tokenRequest["resource"])
	require.Equal(t, []string{"https://fake.example/golem/llm"}, token.Client.Resources)
	f.mu.Unlock()

	// Refresh keeps sending the resource indicator.
	refreshed, err := RefreshToken(context.Background(), token, "")
	require.NoError(t, err)
	require.Equal(t, "the-access-token", refreshed.AccessToken)

	f.mu.Lock()
	defer f.mu.Unlock()
	require.Equal(t, []string{"https://fake.example/golem/llm"}, f.tokenRequest["resource"])
}

// TestLoginIgnoresCrossOriginChallenge verifies that a resource_metadata
// URL on a different origin is ignored and well-known discovery is used
// instead, with no resource indicator sent.
func TestLoginIgnoresCrossOriginChallenge(t *testing.T) {
	f := newFakeAuthServer(t, false)

	f.mu.Lock()
	f.challenge = true
	f.crossOriginChallenge = true
	f.mu.Unlock()

	stubBrowser(t, func(u string) error {
		parsed, err := url.Parse(u)
		require.NoError(t, err)
		require.Empty(t, parsed.Query().Get("resource"))
		q := parsed.Query()
		callback := q.Get("redirect_uri") + "?code=fake-code&state=" + url.QueryEscape(q.Get("state"))
		resp, err := http.Get(callback) //nolint:gosec
		require.NoError(t, err)
		_ = resp.Body.Close() //nolint:errcheck
		return nil
	})

	token, err := Login(context.Background(), Options{APIBaseURL: f.url() + "/v1", Stdout: io.Discard})
	require.NoError(t, err)
	require.Empty(t, token.Client.Resources)
}
