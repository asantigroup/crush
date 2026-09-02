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

// ProtectedResourceMetadata is the subset of RFC 9725 OAuth 2.0 Protected
// Resource Metadata that this client uses. A protected resource (the LLM
// API itself) publishes it at the well-known URL named in its
// WWW-Authenticate challenges.
type ProtectedResourceMetadata struct {
	// Resource is the resource's canonical URI, usable as an RFC 8707
	// resource indicator in authorization and token requests.
	Resource string `json:"resource"`
	// AuthorizationServers lists the issuer URLs of authorization
	// servers acceptable for this resource.
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
	// ScopesSupported are the scopes the resource recognizes.
	ScopesSupported []string `json:"scopes_supported,omitempty"`
	// BearerMethodsSupported lists the ways to carry bearer tokens.
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
}

// probeTimeout bounds the unauthenticated API probe; it must be short so
// a missing challenge does not delay login.
const probeTimeout = 5 * time.Second

// probePath is the conventional OpenAI-compatible endpoint probed
// unauthenticated to elicit a WWW-Authenticate challenge.
const probePath = "/models"

// resolveAuthorizationServer locates the authorization server for an API
// base URL, preferring the standards-based path: probe the API, follow a
// RFC 9725 WWW-Authenticate challenge to protected-resource metadata, and
// adopt the first of its authorization servers that answers RFC 8414
// discovery. The resource's canonical URI is returned alongside so callers
// can send it as an RFC 8707 resource indicator. When the API does not
// challenge (or nothing answers), discovery falls back to well-known URL
// probing and no resource indicator is sent.
func resolveAuthorizationServer(ctx context.Context, apiBaseURL string) (*ServerMetadata, []string, error) {
	if challengeURL := probeAPI(ctx, apiBaseURL); challengeURL != "" {
		if pr, err := fetchProtectedResourceMetadata(ctx, challengeURL, apiBaseURL); err == nil {
			for _, issuer := range pr.AuthorizationServers {
				if meta, err := Discover(ctx, issuer); err == nil {
					resources := []string{}
					if pr.Resource != "" {
						resources = append(resources, pr.Resource)
					}
					return meta, resources, nil
				}
			}
		}
	}
	meta, err := Discover(ctx, apiBaseURL)
	return meta, nil, err
}

// probeAPI requests the models endpoint unauthenticated and returns the
// resource_metadata URL from a Bearer WWW-Authenticate challenge, if the
// API issues one. Any other outcome returns "" so the caller falls back
// to well-known discovery.
func probeAPI(ctx context.Context, apiBaseURL string) string {
	probeURL := strings.TrimRight(apiBaseURL, "/") + probePath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return ""
	}
	client := &http.Client{Timeout: probeTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusUnauthorized {
		return ""
	}
	return bearerChallengeParam(resp.Header.Values("WWW-Authenticate"), "resource_metadata")
}

// fetchProtectedResourceMetadata GETs an RFC 9725 document. Per the spec
// the URL must be same-origin with the API that referenced it; anything
// else is ignored as a misconfiguration or forgery.
func fetchProtectedResourceMetadata(ctx context.Context, metadataURL, apiBaseURL string) (*ProtectedResourceMetadata, error) {
	if !sameOrigin(metadataURL, apiBaseURL) {
		return nil, fmt.Errorf("protected resource metadata %s is not same-origin with %s", metadataURL, apiBaseURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create protected resource metadata request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", metadataURL, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned status %d", metadataURL, resp.StatusCode)
	}
	var meta ProtectedResourceMetadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&meta); err != nil {
		return nil, fmt.Errorf("decode protected resource metadata: %w", err)
	}
	return &meta, nil
}

// sameOrigin reports whether two URLs share scheme and host (port
// included).
func sameOrigin(a, b string) bool {
	pa, errA := url.Parse(a)
	pb, errB := url.Parse(b)
	if errA != nil || errB != nil {
		return false
	}
	return pa.Scheme == pb.Scheme && pa.Host == pb.Host
}

// bearerChallengeParam extracts a parameter from the Bearer challenges in
// WWW-Authenticate header values. Challenge parameters are
// token68-or-quoted-string pairs; quoting per RFC 7235 is handled,
// multiple headers and multiple schemes per header are tolerated.
func bearerChallengeParam(headerValues []string, name string) string {
	name = strings.ToLower(name)
	for _, value := range headerValues {
		var (
			scheme string
			params = map[string]string{}
		)
		for _, item := range splitTopLevelCommas(value) {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if param, isParam := parseAuthItem(item); isParam {
				if strings.EqualFold(scheme, "bearer") {
					params[param[0]] = param[1]
				}
				continue
			}
			if strings.EqualFold(scheme, "bearer") {
				if v, ok := params[name]; ok {
					return v
				}
			}
			word, rest, _ := strings.Cut(item, " ")
			scheme = strings.TrimSpace(word)
			params = map[string]string{}
			if param, isParam := parseAuthItem(strings.TrimSpace(rest)); isParam {
				params[param[0]] = param[1]
			}
		}
		if strings.EqualFold(scheme, "bearer") {
			if v, ok := params[name]; ok {
				return v
			}
		}
	}
	return ""
}

// splitTopLevelCommas splits a header value on commas that are outside
// quoted strings.
func splitTopLevelCommas(value string) []string {
	var (
		items    []string
		current  strings.Builder
		inQuotes bool
		escaped  bool
	)
	for _, r := range value {
		switch {
		case escaped:
			escaped = false
			current.WriteRune(r)
		case inQuotes && r == '\\':
			escaped = true
			current.WriteRune(r)
		case r == '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case r == ',' && !inQuotes:
			items = append(items, strings.TrimSpace(current.String()))
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	if s := strings.TrimSpace(current.String()); s != "" {
		items = append(items, s)
	}
	return items
}

// parseAuthItem parses a "key=value" challenge parameter, where value
// may be a quoted string. It reports false when the item is a scheme
// word instead: the disambiguator is that in a parameter the '=' comes
// before any whitespace (`error="x"`, `Bearer error="x"`), while a
// scheme is a bare token followed by whitespace before any '='.
func parseAuthItem(item string) ([2]string, bool) {
	spaceIdx := strings.IndexAny(item, " \t")
	eqIdx := strings.Index(item, "=")
	if eqIdx < 0 || (spaceIdx >= 0 && spaceIdx < eqIdx) {
		return [2]string{}, false
	}
	key, value, _ := strings.Cut(item, "=")
	key = strings.ToLower(strings.TrimSpace(key))
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = strings.ReplaceAll(strings.ReplaceAll(value[1:len(value)-1], `\"`, `"`), `\\`, `\`)
	}
	return [2]string{key, value}, true
}
