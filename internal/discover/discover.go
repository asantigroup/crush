package discover

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"charm.land/catwalk/pkg/catwalk"
)

// httpClient is shared across all discovery and enrichment calls. It
// has a reasonable timeout so individual requests cannot block forever
// even if the caller forgets to set a context deadline.
var httpClient = &http.Client{Timeout: 10 * time.Second}

// stripV1Suffix removes a trailing /v1 from a base URL. Enricher
// endpoints (e.g. Ollama's /api/show, LM Studio's /api/v1/models) are
// served at the server root, not under the OpenAI-compatible /v1
// prefix. Since provider configs typically include /v1 in the base URL
// for chat completions, enrichers must strip it before constructing
// their own request paths.
func stripV1Suffix(baseURL string) string {
	return strings.TrimSuffix(strings.TrimRight(baseURL, "/"), "/v1")
}

// doRequest builds and executes an authenticated HTTP request using the
// shared client. It resolves variable references in the base URL, API
// key, and extra headers via the provided Resolver. The path is joined
// to the base URL with proper slash handling.
func doRequest(ctx context.Context, method, baseURL, path, apiKey string, extraHeaders map[string]string, resolver Resolver, body any) (*http.Response, error) {
	resolvedBase, _ := resolver.ResolveValue(baseURL)
	resolvedKey, _ := resolver.ResolveValue(apiKey)

	url := strings.TrimRight(resolvedBase, "/") + "/" + strings.TrimLeft(path, "/")

	var reqBody *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshaling request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	var req *http.Request
	var err error
	if reqBody != nil {
		req, err = http.NewRequestWithContext(ctx, method, url, reqBody)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	}
	if err != nil {
		return nil, err
	}

	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if resolvedKey != "" {
		req.Header.Set("Authorization", "Bearer "+resolvedKey)
	}
	for k, v := range extraHeaders {
		resolved, err := resolver.ResolveValue(v)
		if err != nil || resolved == "" {
			continue
		}
		req.Header.Set(k, resolved)
	}

	return httpClient.Do(req)
}

// Config holds the provider configuration needed for model discovery.
type Config struct {
	ID           string
	BaseURL      string
	APIKey       string
	ExtraHeaders map[string]string
	// Existing models from config — IDs present in this list are skipped
	// during discovery (user-specified models win).
	ExistingModels []catwalk.Model
}

// Resolver resolves variable references (e.g. $ENV_VAR) in config values.
type Resolver interface {
	ResolveValue(val string) (string, error)
}

// modelPricing holds the per-1M-token pricing fields that some
// OpenAI-compatible providers include in the /v1/models response.
type modelPricing struct {
	Input  *float64 `json:"input"`
	Output *float64 `json:"output"`
}

// modelEntry is a single entry in the /v1/models listing response.
// Beyond the standard OpenAI fields (id, object, created, owned_by),
// many OpenAI-compatible providers expose extra metadata such as
// context_length, pricing, and reasoning capability. We parse every
// field we understand so discovered models carry real metadata instead
// of zero values.
type modelEntry struct {
	ID               string        `json:"id"`
	Object           string        `json:"object"`
	Created          int64         `json:"created"`
	OwnedBy          string        `json:"owned_by"`
	Name             string        `json:"name"`
	ContextLength    *int64        `json:"context_length"`
	MaxOutputTokens  *int64        `json:"max_output_tokens"`
	DefaultMaxTokens *int64        `json:"default_max_tokens"`
	CanReason        *bool         `json:"can_reason"`
	ReasoningLevels  []string      `json:"reasoning_levels"`
	Pricing          *modelPricing `json:"pricing"`
}

type modelsResponse struct {
	Data []modelEntry `json:"data"`
}

// DiscoverModels fetches available models from the provider's /models endpoint.
// It uses the provided context for cancellation and timeout; callers should set
// a deadline (e.g. context.WithTimeout) to avoid blocking indefinitely.
// Models whose IDs already appear in cfg.ExistingModels are skipped —
// user-specified models take precedence.
func DiscoverModels(ctx context.Context, cfg Config, resolver Resolver) ([]catwalk.Model, error) {
	resp, err := doRequest(ctx, http.MethodGet, cfg.BaseURL, "/models", cfg.APIKey, cfg.ExtraHeaders, resolver, nil)
	if err != nil {
		return nil, fmt.Errorf("discover models for provider %s: %w", cfg.ID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discover models for provider %s: %s", cfg.ID, resp.Status)
	}

	var modelsResp modelsResponse
	if err := json.NewDecoder(resp.Body).Decode(&modelsResp); err != nil {
		return nil, fmt.Errorf("discover models for provider %s: %w", cfg.ID, err)
	}

	// Build set of existing model IDs to skip.
	existing := make(map[string]struct{}, len(cfg.ExistingModels))
	for _, m := range cfg.ExistingModels {
		existing[m.ID] = struct{}{}
	}

	// Start with user-specified models.
	result := make([]catwalk.Model, len(cfg.ExistingModels))
	copy(result, cfg.ExistingModels)

	// Append discovered models not already in the list, populating any
	// metadata the provider included in the listing response.
	for _, e := range modelsResp.Data {
		if _, ok := existing[e.ID]; ok {
			continue
		}
		name := e.Name
		if name == "" {
			name = e.ID
		}
		m := catwalk.Model{
			ID:   e.ID,
			Name: name,
		}
		if e.ContextLength != nil && *e.ContextLength > 0 {
			m.ContextWindow = *e.ContextLength
		}
		if e.DefaultMaxTokens != nil && *e.DefaultMaxTokens > 0 {
			m.DefaultMaxTokens = *e.DefaultMaxTokens
		} else if e.MaxOutputTokens != nil && *e.MaxOutputTokens > 0 {
			m.DefaultMaxTokens = *e.MaxOutputTokens
		}
		if e.CanReason != nil {
			m.CanReason = *e.CanReason
		}
		if len(e.ReasoningLevels) > 0 {
			m.ReasoningLevels = e.ReasoningLevels
		}
		if e.Pricing != nil {
			if e.Pricing.Input != nil {
				m.CostPer1MIn = *e.Pricing.Input
			}
			if e.Pricing.Output != nil {
				m.CostPer1MOut = *e.Pricing.Output
			}
		}
		result = append(result, m)
	}

	return result, nil
}
