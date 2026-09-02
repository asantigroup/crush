package cmd

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/login"
	"github.com/charmbracelet/crush/internal/oauth/copilot"
	"github.com/charmbracelet/crush/internal/oidc"
	"github.com/charmbracelet/crush/internal/workspace"
	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Aliases: []string{"auth"},
	Use:     "login [platform]",
	Short:   "Login Crush to a platform",
	Long: `Login Crush to a specified platform.
	Built-in platforms are: hyper, copilot, openai (chatgpt), grok (xai).
	Any other configured provider also works when its host serves OAuth
	authorization server metadata (RFC 8414): crush discovers the server,
	registers itself as an OAuth client, and opens the browser for you.`,
	Example: `
	# Authenticate with Charm Hyper
	crush login

	# Authenticate with GitHub Copilot
	crush login copilot

	# Authenticate with a ChatGPT (OpenAI) account
	crush login openai

	# Authenticate with a Grok (xAI) account
	crush login grok

	# Authenticate with a discovery-driven OAuth provider
	crush login golem

	# Force re-authentication even if already logged in
	crush login -f copilot
	`,
	ValidArgs: []cobra.Completion{
		"hyper",
		"copilot",
		"github",
		"github-copilot",
		"openai",
		"chatgpt",
		"grok",
		"xai",
	},
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ws, cleanup, err := setupWorkspaceWithProgressBar(cmd)
		if err != nil {
			return err
		}
		defer cleanup()

		provider := "hyper"
		if len(args) > 0 {
			provider = args[0]
		}
		force, _ := cmd.Flags().GetBool("force")
		switch provider {
		case "hyper":
			return loginHyper(ws, force)
		case "copilot", "github", "github-copilot":
			return loginCopilot(ws, force)
		case "openai", "chatgpt":
			return loginOpenAI(ws, force)
		case "grok", "xai":
			return loginGrok(ws, force)
		default:
			noBrowser, _ := cmd.Flags().GetBool("no-browser")
			return loginDiscovered(ws, provider, force, noBrowser)
		}
	},
}

func init() {
	loginCmd.Flags().BoolP("force", "f", false, "Force re-authentication even if already logged in")
	loginCmd.Flags().Bool("no-browser", false, "Print the authorization URL instead of opening a browser")
}

func loginHyper(ws workspace.Workspace, force bool) error {
	if !force {
		cfg := ws.Config()
		if cfg != nil {
			if pc, ok := cfg.Providers.Get("hyper"); ok && pc.OAuthToken != nil {
				fmt.Println("You are already logged in to Hyper.")
				fmt.Println("Use --force to re-authenticate.")
				return nil
			}
		}
	}

	ctx := getLoginContext()
	token, err := login.Run(ctx, login.PlatformHyper)
	if err != nil {
		return err
	}

	if err := ws.SetProviderAPIKey(config.ScopeGlobal, "hyper", token); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("You're now authenticated with Hyper!")
	return nil
}

func loginCopilot(ws workspace.Workspace, force bool) error {
	if !force {
		cfg := ws.Config()
		if cfg != nil {
			if pc, ok := cfg.Providers.Get("copilot"); ok && pc.OAuthToken != nil {
				fmt.Println("You are already logged in to GitHub Copilot.")
				fmt.Println("Use --force to re-authenticate.")
				return nil
			}
		}
	}

	ctx := getLoginContext()

	if diskToken, hasDiskToken := copilot.RefreshTokenFromDisk(); hasDiskToken {
		fmt.Println("Found existing GitHub Copilot token on disk. Using it to authenticate...")
		token, err := copilot.RefreshToken(ctx, diskToken)
		if err != nil {
			return fmt.Errorf("unable to refresh token from disk: %w", err)
		}
		if err := ws.SetProviderAPIKey(config.ScopeGlobal, "copilot", token); err != nil {
			return err
		}
		fmt.Println()
		fmt.Println("You're now authenticated with GitHub Copilot!")
		return nil
	}

	token, err := login.Run(ctx, login.PlatformCopilot)
	if err != nil {
		if errors.Is(err, copilot.ErrNotAvailable) {
			fmt.Println()
			fmt.Println("GitHub Copilot is unavailable for this account. To signup, go to the following page:")
			fmt.Println()
			lipgloss.Println(lipgloss.NewStyle().Hyperlink(copilot.SignupURL, "id=copilot-signup").Render(copilot.SignupURL))
			fmt.Println()
			fmt.Println("You may be able to request free access if eligible. For more information, see:")
			fmt.Println()
			lipgloss.Println(lipgloss.NewStyle().Hyperlink(copilot.FreeURL, "id=copilot-free").Render(copilot.FreeURL))
		}
		return err
	}

	if err := ws.SetProviderAPIKey(config.ScopeGlobal, "copilot", token); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("You're now authenticated with GitHub Copilot!")
	return nil
}

func loginOpenAI(ws workspace.Workspace, force bool) error {
	if !force {
		cfg := ws.Config()
		if cfg != nil {
			if pc, ok := cfg.Providers.Get("openai"); ok && pc.OAuthToken != nil {
				fmt.Println("You are already logged in to OpenAI with a ChatGPT account.")
				fmt.Println("Use --force to re-authenticate.")
				return nil
			}
		}
	}

	ctx := getLoginContext()
	token, err := login.Run(ctx, login.PlatformOpenAI)
	if err != nil {
		return err
	}

	if err := ws.SetProviderAPIKey(config.ScopeGlobal, "openai", token); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("You're now authenticated with your ChatGPT account!")
	return nil
}

func loginGrok(ws workspace.Workspace, force bool) error {
	if !force {
		cfg := ws.Config()
		if cfg != nil {
			if pc, ok := cfg.Providers.Get("xai"); ok && pc.OAuthToken != nil {
				fmt.Println("You are already logged in to xAI with a Grok account.")
				fmt.Println("Use --force to re-authenticate.")
				return nil
			}
		}
	}

	ctx := getLoginContext()
	token, err := login.Run(ctx, login.PlatformGrok)
	if err != nil {
		return err
	}

	if err := ws.SetProviderAPIKey(config.ScopeGlobal, "xai", token); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("You're now authenticated with your Grok account!")
	return nil
}

// loginDiscovered authenticates against any configured provider whose
// host publishes OAuth authorization server metadata. Everything is
// derived from the provider's base URL: the authorization server is
// discovered (RFC 8414), the client registers itself (RFC 7591), and the
// code flow runs with PKCE over a loopback redirect, degrading to a
// printed URL plus pasted code (or device flow) when no browser exists.
func loginDiscovered(ws workspace.Workspace, providerID string, force, noBrowser bool) error {
	ctx := getLoginContext()

	cfg := ws.Config()
	pc, ok := cfg.Providers.Get(providerID)
	if !ok {
		return fmt.Errorf("unknown platform or provider: %s", providerID)
	}
	if !force && pc.OAuthToken != nil {
		fmt.Printf("You are already logged in to %s.\nUse --force to re-authenticate.\n", providerID)
		return nil
	}
	if pc.BaseURL == "" {
		return fmt.Errorf("provider %s has no base URL to discover an OAuth server from", providerID)
	}

	opts := oidc.Options{
		APIBaseURL: pc.BaseURL,
		NoBrowser:  noBrowser,
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
	}
	// Reuse the client registered by a previous login to avoid churn.
	if pc.OAuthToken != nil && pc.OAuthToken.Client != nil {
		opts.ClientID = pc.OAuthToken.Client.ClientID
		opts.ClientSecret = pc.OAuthToken.Client.ClientSecret
	}

	fmt.Printf("Discovering OAuth server for %s...\n", providerID)
	token, err := oidc.Login(ctx, opts)
	if err != nil {
		return err
	}

	if err := ws.SetProviderAPIKey(config.ScopeGlobal, providerID, token); err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("You're now authenticated with %s!\n", cmp.Or(pc.Name, providerID))
	return nil
}

func getLoginContext() context.Context {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	go func() {
		<-ctx.Done()
		cancel()
	}()
	return ctx
}
