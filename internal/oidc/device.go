package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/charmbracelet/crush/internal/oauth"
)

// deviceGrantType is the RFC 8628 device authorization grant type URI.
const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// defaultDeviceInterval is the polling interval used when the device
// authorization response does not specify one.
const defaultDeviceInterval = 5 * time.Second

// deviceLogin runs the RFC 8628 device authorization flow: the user
// approves on any device with a browser, while this process polls the
// token endpoint.
func deviceLogin(ctx context.Context, meta *ServerMetadata, opts Options, resources []string) (*oauth.Token, error) {
	clientID := opts.ClientID
	if clientID == "" {
		registered, _, err := register(ctx, meta, "")
		if err != nil {
			return nil, err
		}
		clientID = registered
	}

	params := url.Values{
		"client_id": {clientID},
		"scope":     {strings.Join(resolveScopes(opts.Scopes, meta), " ")},
	}
	for _, resource := range resources {
		params.Add("resource", resource)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.DeviceAuthorizationEndpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create device authorization request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request device code: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read device authorization response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &oauth.TokenExchangeError{StatusCode: resp.StatusCode, Body: string(body)}
	}

	var device struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &device); err != nil || device.DeviceCode == "" || device.VerificationURI == "" {
		return nil, fmt.Errorf("device authorization response did not contain a device_code and verification_uri")
	}

	out := opts.stdout()
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Authorize by visiting:")
	fmt.Fprintln(out)
	fmt.Fprintln(out, device.VerificationURI)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "And entering this code:")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "    %s\n", device.UserCode)
	fmt.Fprintln(out)
	if !opts.NoBrowser && browserAvailable() {
		if err := openBrowser(device.VerificationURI); err == nil {
			fmt.Fprintln(out, "Opened the verification URL in your browser.")
		}
	}

	interval := defaultDeviceInterval
	if device.Interval > 0 {
		interval = time.Duration(device.Interval) * time.Second
	}
	deadline := time.Now().Add(time.Hour)
	if device.ExpiresIn > 0 {
		deadline = time.Now().Add(time.Duration(device.ExpiresIn) * time.Second)
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("device code expired")
		}

		poll := url.Values{
			"grant_type":  {deviceGrantType},
			"device_code": {device.DeviceCode},
			"client_id":   {clientID},
		}
		for _, resource := range resources {
			poll.Add("resource", resource)
		}
		token, err := postToken(ctx, meta.TokenEndpoint, poll)
		if err == nil {
			attachClient(token, meta, clientID, opts.ClientSecret, resources)
			return token, nil
		}
		var exchangeErr *oauth.TokenExchangeError
		if !errors.As(err, &exchangeErr) {
			return nil, err
		}
		switch {
		case strings.Contains(exchangeErr.Body, "authorization_pending"):
			continue
		case strings.Contains(exchangeErr.Body, "slow_down"):
			interval += defaultDeviceInterval
			continue
		case strings.Contains(exchangeErr.Body, "access_denied"):
			return nil, fmt.Errorf("device authorization was denied")
		default:
			return nil, err
		}
	}
}
