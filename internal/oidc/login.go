package oidc

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"

	"github.com/charmbracelet/crush/internal/oauth"
	"github.com/charmbracelet/crush/internal/oauth/callback"
	"github.com/pkg/browser"
)

// DefaultCallbackPort is the fixed loopback port used for the OAuth
// redirect. A fixed port matters for remote use: `ssh -L 8765:127.0.0.1:8765`
// lets a browser on the workstation complete a login running on the remote
// machine. When the port is already taken and the client is being
// dynamically registered, an ephemeral port is used instead.
const DefaultCallbackPort = 8765

// CallbackPath is the path component of the loopback redirect URI.
const CallbackPath = "/callback"

// openBrowser opens a URL in the user's browser. It is a variable so
// tests can stub the browser away.
var openBrowser = browser.OpenURL

// Options configures a login attempt. Only APIBaseURL is required; every
// other value is discovered, registered, or defaulted automatically.
type Options struct {
	// APIBaseURL is the provider's API base URL. The authorization server
	// is discovered from its origin (and path prefixes) via RFC 8414.
	APIBaseURL string

	// ClientID reuses a previously registered client, e.g. the one stored
	// in a prior token's Client field. Empty means the client registers
	// itself dynamically (RFC 7591) when the server supports it.
	ClientID string

	// ClientSecret pairs with ClientID for confidential clients.
	ClientSecret string

	// Scopes are requested at the authorization endpoint. Empty defaults
	// to the server-advertised scopes, or "openid" when the server does
	// not advertise any.
	Scopes []string

	// NoBrowser forces the manual path: print the authorization URL and
	// accept a pasted code instead of opening a browser. Detected
	// automatically when no graphical session is available.
	NoBrowser bool

	// Stdin supplies pasted authorization codes for the manual fallback.
	// Nil disables the paste path.
	Stdin io.Reader

	// Stdout receives URLs, codes, and instructions. Defaults to
	// os.Stdout.
	Stdout io.Writer
}

func (o Options) stdout() io.Writer {
	if o.Stdout != nil {
		return o.Stdout
	}
	return os.Stdout
}

// Login authenticates against the authorization server discovered for the
// provider's API base URL and returns a token carrying enough client state
// (Client field) to refresh later without re-running discovery.
func Login(ctx context.Context, opts Options) (*oauth.Token, error) {
	meta, resources, err := resolveAuthorizationServer(ctx, opts.APIBaseURL)
	if err != nil {
		return nil, err
	}

	useDevice := meta.SupportsDeviceFlow() && (opts.NoBrowser || !browserAvailable())
	if useDevice {
		return deviceLogin(ctx, meta, opts, resources)
	}
	return authorizationCodeLogin(ctx, meta, opts, resources)
}

// authorizationCodeLogin runs the authorization code flow with PKCE over
// a loopback redirect, falling back to a printed URL plus pasted code when
// no browser can be opened.
func authorizationCodeLogin(ctx context.Context, meta *ServerMetadata, opts Options, resources []string) (*oauth.Token, error) {
	listener, err := listenLoopback(opts.ClientID == "")
	if err != nil {
		return nil, err
	}
	defer listener.Close() //nolint:errcheck

	redirectURI := fmt.Sprintf("http://127.0.0.1:%d%s", listener.Addr().(*net.TCPAddr).Port, CallbackPath)

	clientID := opts.ClientID
	clientSecret := opts.ClientSecret
	if clientID == "" {
		clientID, clientSecret, err = register(ctx, meta, redirectURI)
		if err != nil {
			return nil, err
		}
	}

	verifier, err := generateCodeVerifier()
	if err != nil {
		return nil, err
	}
	state, err := generateState()
	if err != nil {
		return nil, err
	}

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(resolveScopes(opts.Scopes, meta), " ")},
		"state":                 {state},
		"code_challenge":        {generateCodeChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	for _, resource := range resources {
		params.Add("resource", resource)
	}
	authURL := meta.AuthorizationEndpoint + "?" + params.Encode()

	resultCh := make(chan callbackResult, 2)
	serveCallback(ctx, listener, resultCh, state)

	opened := !opts.NoBrowser && browserAvailable()
	if opened {
		fmt.Fprintln(opts.stdout(), "Opening your browser to authorize...")
		if err := openBrowser(authURL); err != nil {
			opened = false
		}
	}
	if !opened {
		printManualInstructions(opts.stdout(), authURL, listener.Addr().(*net.TCPAddr).Port)
	}

	if opts.Stdin != nil {
		go readPastedCodes(opts.Stdin, opts.stdout(), resultCh, state)
	}

	select {
	case result := <-resultCh:
		if result.err != nil {
			return nil, result.err
		}
		token, err := exchangeCode(ctx, meta.TokenEndpoint, clientID, clientSecret, result.code, verifier, redirectURI, resources)
		if err != nil {
			return nil, err
		}
		attachClient(token, meta, clientID, clientSecret, resources)
		return token, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// serveCallback handles the loopback redirect, reporting the outcome on
// resultCh and rendering a friendly page in the browser.
func serveCallback(ctx context.Context, listener net.Listener, resultCh chan<- callbackResult, expectedState string) {
	mux := http.NewServeMux()
	mux.HandleFunc(CallbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		result := callbackResult{}
		switch {
		case q.Get("error") != "":
			result.err = fmt.Errorf("authorization error: %s: %s", q.Get("error"), q.Get("error_description"))
		case q.Get("state") != expectedState:
			result.err = fmt.Errorf("state mismatch in OAuth callback")
		case q.Get("code") == "":
			result.err = fmt.Errorf("OAuth callback did not include an authorization code")
		default:
			result.code = q.Get("code")
		}

		page := callback.Result{ErrorCode: q.Get("error"), ErrorDescription: q.Get("error_description")}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if result.err != nil {
			w.WriteHeader(http.StatusBadRequest)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_ = callback.Write(w, page) //nolint:errcheck

		select {
		case resultCh <- result:
		default:
		}
	})

	server := &http.Server{Handler: mux} //nolint:gosec
	go func() {
		_ = server.Serve(listener)
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*defaultShutdownGrace)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
}

// readPastedCodes scans stdin for a pasted authorization code, delivered
// either as the full loopback redirect URL (whose load failure in a remote
// browser still leaves the code visible in the address bar), as a bare
// code=... fragment, or as a bare code displayed by the server's consent
// page when the redirect cannot land. Unrecognized lines are ignored so a
// user in browser mode can type without breaking anything.
func readPastedCodes(stdin io.Reader, stdout io.Writer, resultCh chan<- callbackResult, expectedState string) {
	scanner := bufio.NewScanner(stdin)
	for scanner.Scan() {
		code, state, err := parseManualCode(scanner.Text())
		if err != nil {
			fmt.Fprintln(stdout, err)
			continue
		}
		if code == "" {
			continue
		}
		if state != "" && state != expectedState {
			fmt.Fprintln(stdout, "Pasted code belongs to a different login attempt; ignoring.")
			continue
		}
		select {
		case resultCh <- callbackResult{code: code}:
		default:
		}
		return
	}
}

// parseManualCode extracts an authorization code from a pasted line. It
// returns the code, the state when the paste included one, and an error
// for a paste that looks like a callback URL but is malformed.
func parseManualCode(line string) (code, state string, err error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", nil
	}
	if strings.Contains(line, "code=") {
		var (
			query    url.Values
			parseErr error
		)
		if strings.Contains(line, "?") || strings.Contains(line, "://") {
			u, err := url.Parse(line)
			if err != nil {
				return "", "", fmt.Errorf("could not parse the pasted URL: %w", err)
			}
			query = u.Query()
		} else {
			query, parseErr = url.ParseQuery(line)
		}
		if parseErr != nil {
			return "", "", fmt.Errorf("could not parse the pasted code: %w", parseErr)
		}
		return query.Get("code"), query.Get("state"), nil
	}
	if !strings.ContainsAny(line, " \t") {
		return line, "", nil
	}
	return "", "", nil
}

// printManualInstructions explains how to finish authorization without a
// local browser: forward the callback port over SSH, or open the URL
// anywhere and paste the resulting code back.
func printManualInstructions(w io.Writer, authURL string, port int) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "No browser available. To authorize manually, either:")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  1. From an SSH session, forward the callback port first:")
	fmt.Fprintf(w, "     ssh -L %d:127.0.0.1:%d <this-host>, then open:", port, port)
	fmt.Fprintln(w)
	fmt.Fprintln(w, authURL)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  2. Or open the URL on any device, then paste the code you are")
	fmt.Fprintln(w, "     shown (or the localhost URL you land on) back here.")
	fmt.Fprintln(w)
}

// register performs RFC 7591 dynamic client registration and returns the
// issued client id and secret. redirectURI may be empty for flows that
// need no redirect (device flow).
func register(ctx context.Context, meta *ServerMetadata, redirectURI string) (clientID, clientSecret string, err error) {
	if meta.RegistrationEndpoint == "" {
		return "", "", fmt.Errorf("server %s supports neither a stored client nor dynamic registration; cannot log in", meta.Issuer)
	}
	registration := map[string]any{
		"client_name":                "crush",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}
	if redirectURI != "" {
		registration["redirect_uris"] = []string{redirectURI}
	}
	body, err := json.Marshal(registration)
	if err != nil {
		return "", "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.RegistrationEndpoint, strings.NewReader(string(body)))
	if err != nil {
		return "", "", fmt.Errorf("create registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("register OAuth client: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", fmt.Errorf("read registration response: %w", err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("registration endpoint returned status %d: %s", resp.StatusCode, string(respBody))
	}
	var registered struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret,omitempty"`
	}
	if err := json.Unmarshal(respBody, &registered); err != nil || registered.ClientID == "" {
		return "", "", fmt.Errorf("registration response did not contain a client_id")
	}
	return registered.ClientID, registered.ClientSecret, nil
}

// listenLoopback binds the callback listener, preferring the fixed
// DefaultCallbackPort. An ephemeral port is allowed only when the client
// will be dynamically registered with whatever redirect URI results,
// because a pre-registered client id is bound to the exact port.
func listenLoopback(allowEphemeral bool) (net.Listener, error) {
	if listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", DefaultCallbackPort)); err == nil {
		return listener, nil
	}
	if !allowEphemeral {
		return nil, fmt.Errorf("callback port %d is unavailable; free it or remove the stored OAuth client so crush can re-register", DefaultCallbackPort)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen on loopback for OAuth callback: %w", err)
	}
	return listener, nil
}

// attachClient records the registration, endpoints, and resource
// indicators on the token so later refreshes need no discovery.
func attachClient(token *oauth.Token, meta *ServerMetadata, clientID, clientSecret string, resources []string) {
	token.Client = &oauth.OAuthClient{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      meta.AuthorizationEndpoint,
		TokenURL:     meta.TokenEndpoint,
		Resources:    resources,
	}
}

// resolveScopes picks the scopes to request: explicit ones, the server's
// advertised set, or "openid" as the bare default.
func resolveScopes(requested []string, meta *ServerMetadata) []string {
	if len(requested) > 0 {
		return requested
	}
	if len(meta.ScopesSupported) > 0 {
		return meta.ScopesSupported
	}
	return []string{"openid"}
}

// browserAvailable reports whether this process can probably open a
// browser. On un*X graphics-less sessions there is nothing to open, which
// is the signal to switch to the manual or device flow.
func browserAvailable() bool {
	switch runtime.GOOS {
	case "linux", "freebsd", "netbsd", "openbsd", "dragonfly":
		return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	default:
		return true
	}
}

// --- PKCE helpers ---

func generateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate code verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
