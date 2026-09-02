package oidc

import (
	"context"
	"fmt"
	"net/url"

	"github.com/charmbracelet/crush/internal/oauth"
)

// RefreshToken refreshes an access token using the client state captured
// at login time (token.Client). When the stored token predates that, the
// endpoints are re-derived by discovering the authorization server for
// apiBaseURL.
func RefreshToken(ctx context.Context, token *oauth.Token, apiBaseURL string) (*oauth.Token, error) {
	if token == nil {
		return nil, fmt.Errorf("no OAuth token to refresh")
	}

	client := token.Client
	var tokenEndpoint string
	switch {
	case client != nil && client.TokenURL != "" && client.ClientID != "":
		tokenEndpoint = client.TokenURL
	default:
		if apiBaseURL == "" {
			return nil, fmt.Errorf("token has no stored client and no API base URL to rediscover it from; log in again")
		}
		meta, err := Discover(ctx, apiBaseURL)
		if err != nil {
			return nil, err
		}
		tokenEndpoint = meta.TokenEndpoint
		if client == nil {
			client = &oauth.OAuthClient{}
		}
		if client.ClientID == "" {
			return nil, fmt.Errorf("token has no stored client id and it cannot be recovered; log in again")
		}
		client.AuthURL = meta.AuthorizationEndpoint
		client.TokenURL = meta.TokenEndpoint
	}

	params := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {token.RefreshToken},
		"client_id":     {client.ClientID},
	}
	for _, resource := range client.Resources {
		params.Add("resource", resource)
	}
	if client.ClientSecret != "" {
		params.Set("client_secret", client.ClientSecret)
	}

	refreshed, err := postToken(ctx, tokenEndpoint, params)
	if err != nil {
		return nil, err
	}
	// RFC 6749 allows the refresh response to omit the refresh token, in
	// which case the old one remains valid.
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = token.RefreshToken
	}
	refreshed.Client = client
	return refreshed, nil
}
