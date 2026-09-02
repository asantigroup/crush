package dialog

import (
	"context"
	"io"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/catwalk/pkg/catwalk"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/oidc"
	"github.com/charmbracelet/crush/internal/ui/common"
)

// AuthenticateModelID is a synthetic model ID used as a placeholder for
// providers that need authentication before their models can be discovered.
// Selecting it in the models dialog triggers the OAuth flow instead of a
// model selection.
const AuthenticateModelID = "__authenticate__"

// NewOAuthDiscovered creates an OAuth dialog that authenticates a provider
// through runtime discovery (RFC 8414 + RFC 7591 dynamic registration +
// PKCE loopback), the same path the `crush login` CLI uses. Only the
// provider's configured base URL is needed; client IDs and endpoints are
// discovered automatically.
func NewOAuthDiscovered(
	com *common.Common,
	isOnboarding bool,
	provider catwalk.Provider,
	model config.SelectedModel,
	modelType config.SelectedModelType,
) (*OAuth, tea.Cmd) {
	name := string(provider.ID)
	if provider.Name != "" {
		name = provider.Name
	}
	p := &OAuthDiscovered{providerName: name}

	if pc, ok := com.Config().Providers.Get(string(provider.ID)); ok {
		p.baseURL = pc.BaseURL
		if pc.OAuthToken != nil && pc.OAuthToken.Client != nil {
			p.clientID = pc.OAuthToken.Client.ClientID
			p.clientSecret = pc.OAuthToken.Client.ClientSecret
		}
	}

	return newOAuth(com, isOnboarding, provider, model, modelType, p)
}

// OAuthDiscovered implements OAuthProvider for discovery-driven OAuth. Unlike
// the hyper/copilot device-flow providers, the authorization server and
// endpoints are learned at runtime from the provider's base URL, so the
// entire flow (discovery, registration, browser auth, token exchange) runs
// to completion inside initiateAuth.
type OAuthDiscovered struct {
	providerName string
	baseURL      string
	clientID     string
	clientSecret string
	cancelFunc   context.CancelFunc
}

var _ OAuthProvider = (*OAuthDiscovered)(nil)

func (m *OAuthDiscovered) name() string {
	return m.providerName
}

// initiateAuth runs the full discovered OAuth flow to completion. The dialog
// shows its initializing spinner while the browser flow runs, then yields
// the finished token as ActionCompleteOAuth.
func (m *OAuthDiscovered) initiateAuth() tea.Msg {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	m.cancelFunc = cancel

	// Stdout is discarded so the discovery client's manual-authorization
	// instructions never scribble over the TUI. Stdin is nil so the GUI
	// never competes with the user's terminal input. The headless paste
	// path remains a CLI feature.
	token, err := oidc.Login(ctx, oidc.Options{
		APIBaseURL:   m.baseURL,
		ClientID:     m.clientID,
		ClientSecret: m.clientSecret,
		Stdout:       io.Discard,
	})
	if err != nil {
		return ActionOAuthErrored{Error: err}
	}
	return ActionCompleteOAuth{Token: token}
}

// startPolling is unused: the discovered flow completes in initiateAuth and
// reports its result as ActionCompleteOAuth directly.
func (m *OAuthDiscovered) startPolling(_ string, _ int) tea.Cmd {
	return nil
}

func (m *OAuthDiscovered) stopPolling() tea.Msg {
	if m.cancelFunc != nil {
		m.cancelFunc()
	}
	return nil
}
