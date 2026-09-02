// Package oidc implements a discovery-driven OAuth2 client for LLM
// providers.
//
// The client assumes nothing about a provider beyond its API base URL:
// the authorization server is located via RFC 8414 metadata discovered at
// the base URL's origin (with path-inserted fallbacks), the client
// identifier is obtained through RFC 7591 dynamic registration when the
// server supports it, and the authorization code flow runs with PKCE over
// a loopback redirect (RFC 8252). When no browser is reachable, the same
// flow degrades to printing the authorization URL and accepting a pasted
// code, and to RFC 8628 device flow when the server advertises one.
//
// Everything needed to refresh later (client id, endpoints) is captured in
// the returned token's Client field, so refreshes never re-run discovery.
package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ServerMetadata is the subset of RFC 8414 authorization server metadata
// (also compatible with OIDC discovery documents) that this client uses.
type ServerMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	RegistrationEndpoint          string   `json:"registration_endpoint,omitempty"`
	DeviceAuthorizationEndpoint   string   `json:"device_authorization_endpoint,omitempty"`
	GrantTypesSupported           []string `json:"grant_types_supported,omitempty"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
	ScopesSupported               []string `json:"scopes_supported,omitempty"`
}

// SupportsDeviceFlow reports whether the server advertises RFC 8628 device
// authorization.
func (m *ServerMetadata) SupportsDeviceFlow() bool {
	return m.DeviceAuthorizationEndpoint != ""
}

// Discover finds the authorization server for an API base URL by fetching
// RFC 8414 (and OIDC) metadata. The origin is tried first, then each path
// prefix of the base URL longest-first, matching RFC 8414's path-insertion
// rule for issuers mounted under a path.
func Discover(ctx context.Context, apiBaseURL string) (*ServerMetadata, error) {
	parsed, err := url.Parse(apiBaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse API base URL %q: %w", apiBaseURL, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("API base URL %q must be absolute", apiBaseURL)
	}

	var attempts []error
	for _, candidate := range discoveryCandidates(parsed) {
		meta, err := fetchMetadata(ctx, candidate)
		if err != nil {
			attempts = append(attempts, err)
			continue
		}
		return meta, nil
	}
	return nil, fmt.Errorf("no OAuth authorization server found for %s: %w", apiBaseURL, attempts[0])
}

// discoveryCandidates lists well-known metadata URLs for a parsed API base
// URL, most likely first: the origin, then each path prefix longest-first.
func discoveryCandidates(u *url.URL) []string {
	origin := url.URL{Scheme: u.Scheme, Host: u.Host}
	prefix := strings.Trim(u.Path, "/")

	candidates := []string{origin.String() + "/.well-known/oauth-authorization-server"}
	if prefix != "" {
		segments := strings.Split(prefix, "/")
		for i := len(segments) - 1; i > 0; i-- {
			p := origin.String() + "/" + strings.Join(segments[:i], "/")
			candidates = append(candidates, p+"/.well-known/oauth-authorization-server")
		}
	}
	candidates = append(candidates,
		origin.String()+"/.well-known/openid-configuration",
	)
	return candidates
}

// fetchMetadata GETs one well-known URL and validates that it names both
// endpoints this client needs.
func fetchMetadata(ctx context.Context, wellKnown string) (*ServerMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("create discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", wellKnown, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		_, _ = io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("%s returned status %d", wellKnown, resp.StatusCode)
	}

	var meta ServerMetadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&meta); err != nil {
		return nil, fmt.Errorf("decode metadata from %s: %w", wellKnown, err)
	}
	if meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" {
		return nil, fmt.Errorf("%s does not name authorization and token endpoints", wellKnown)
	}
	return &meta, nil
}

// httpClient is the HTTP client used for all OAuth requests. Tests may
// replace it, typically with one whose transport rewrites requests to an
// httptest server.
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}
