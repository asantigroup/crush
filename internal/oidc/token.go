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

	"github.com/charmbracelet/crush/internal/oauth"
)

// defaultShutdownGrace bounds how long the loopback server waits to drain
// when the login context is cancelled.
const defaultShutdownGrace = 2 * time.Second

// callbackResult carries the outcome of either the loopback redirect or a
// pasted code.
type callbackResult struct {
	code string
	err  error
}

// exchangeCode trades an authorization code for tokens at the token
// endpoint, proving possession of the PKCE verifier.
func exchangeCode(ctx context.Context, tokenEndpoint, clientID, clientSecret, code, verifier, redirectURI string, resources []string) (*oauth.Token, error) {
	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}
	for _, resource := range resources {
		params.Add("resource", resource)
	}
	if clientSecret != "" {
		params.Set("client_secret", clientSecret)
	}
	return postToken(ctx, tokenEndpoint, params)
}

// postToken POSTs form parameters to a token endpoint and decodes the
// standard OAuth2 token response.
func postToken(ctx context.Context, tokenEndpoint string, params url.Values) (*oauth.Token, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &oauth.TokenExchangeError{StatusCode: resp.StatusCode, Body: string(body)}
	}

	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		ExpiresAt    int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if raw.AccessToken == "" {
		return nil, fmt.Errorf("token response did not contain an access_token")
	}
	token := &oauth.Token{
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
		ExpiresIn:    raw.ExpiresIn,
		ExpiresAt:    raw.ExpiresAt,
	}
	token.SetExpiresAt()
	return token, nil
}
