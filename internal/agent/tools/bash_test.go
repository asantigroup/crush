package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"charm.land/fantasy"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/permission"
	"github.com/charmbracelet/crush/internal/pubsub"
	"github.com/charmbracelet/crush/internal/shell"
	"github.com/stretchr/testify/require"
)

type mockBashPermissionService struct {
	*pubsub.Broker[permission.PermissionRequest]
}

func (m *mockBashPermissionService) Request(ctx context.Context, req permission.CreatePermissionRequest) (bool, error) {
	return true, nil
}

func (m *mockBashPermissionService) Grant(req permission.PermissionRequest) bool { return true }

func (m *mockBashPermissionService) Deny(req permission.PermissionRequest) bool { return true }

func (m *mockBashPermissionService) GrantPersistent(req permission.PermissionRequest) bool {
	return true
}

func (m *mockBashPermissionService) AutoApproveSession(sessionID string) {}

func (m *mockBashPermissionService) SetSkipRequests(skip bool) {}

func (m *mockBashPermissionService) SkipRequests() bool {
	return false
}

func (m *mockBashPermissionService) SubscribeNotifications(ctx context.Context) <-chan pubsub.Event[permission.PermissionNotification] {
	return make(<-chan pubsub.Event[permission.PermissionNotification])
}

func TestBashTool_DefaultAutoBackgroundThreshold(t *testing.T) {
	workingDir := t.TempDir()
	tool := newBashToolForTest(workingDir)
	ctx := context.WithValue(context.Background(), SessionIDContextKey, "test-session")

	resp := runBashTool(t, tool, ctx, BashParams{
		Description: "default threshold",
		Command:     "echo done",
	})

	require.False(t, resp.IsError)
	var meta BashResponseMetadata
	require.NoError(t, json.Unmarshal([]byte(resp.Metadata), &meta))
	require.False(t, meta.Background)
	require.Empty(t, meta.ShellID)
	require.Contains(t, meta.Output, "done")
}

func TestBashTool_CustomAutoBackgroundThreshold(t *testing.T) {
	workingDir := t.TempDir()
	tool := newBashToolForTest(workingDir)
	ctx := context.WithValue(context.Background(), SessionIDContextKey, "test-session")

	resp := runBashTool(t, tool, ctx, BashParams{
		Description:         "custom threshold",
		Command:             "sleep 1.5 && echo done",
		AutoBackgroundAfter: 1,
	})

	require.False(t, resp.IsError)
	var meta BashResponseMetadata
	require.NoError(t, json.Unmarshal([]byte(resp.Metadata), &meta))
	require.True(t, meta.Background)
	require.NotEmpty(t, meta.ShellID)
	require.Contains(t, resp.Content, "moved to background")

	bgManager := shell.GetBackgroundShellManager()
	require.NoError(t, bgManager.Kill(meta.ShellID))
}

type recordingPermissionService struct {
	*pubsub.Broker[permission.PermissionRequest]
	requestCount int
	allow        bool
}

func (m *recordingPermissionService) Request(ctx context.Context, req permission.CreatePermissionRequest) (bool, error) {
	m.requestCount++
	return m.allow, nil
}

func (m *recordingPermissionService) Grant(req permission.PermissionRequest) bool { return true }

func (m *recordingPermissionService) Deny(req permission.PermissionRequest) bool { return true }

func (m *recordingPermissionService) GrantPersistent(req permission.PermissionRequest) bool {
	return true
}

func (m *recordingPermissionService) AutoApproveSession(sessionID string) {}

func (m *recordingPermissionService) SetSkipRequests(skip bool) {}

func (m *recordingPermissionService) SkipRequests() bool {
	return false
}

func (m *recordingPermissionService) SubscribeNotifications(ctx context.Context) <-chan pubsub.Event[permission.PermissionNotification] {
	return make(<-chan pubsub.Event[permission.PermissionNotification])
}

func newBashToolForTest(workingDir string) fantasy.AgentTool {
	permissions := &mockBashPermissionService{Broker: pubsub.NewBroker[permission.PermissionRequest]()}
	attribution := &config.Attribution{TrailerStyle: config.TrailerStyleNone}
	return NewBashTool(permissions, workingDir, attribution, "test-model", nil)
}

func newBashToolWithRecordingPerms(workingDir string, allow bool) (fantasy.AgentTool, *recordingPermissionService) {
	perms := &recordingPermissionService{
		Broker: pubsub.NewBroker[permission.PermissionRequest](),
		allow:  allow,
	}
	attribution := &config.Attribution{TrailerStyle: config.TrailerStyleNone}
	return NewBashTool(perms, workingDir, attribution, "test-model", nil), perms
}

func TestBashTool_ChainedCommandsRequirePermission(t *testing.T) {
	workingDir := t.TempDir()
	tool, perms := newBashToolWithRecordingPerms(workingDir, true)
	ctx := context.WithValue(context.Background(), SessionIDContextKey, "test-session")

	// ls && echo should trigger permission check.
	resp := runBashTool(t, tool, ctx, BashParams{
		Description: "chained ls",
		Command:     "ls && echo done",
	})

	require.False(t, resp.IsError)
	require.Equal(t, 1, perms.requestCount, "chained command should trigger permission request")

	// Plain ls should NOT trigger permission check.
	perms.requestCount = 0
	resp = runBashTool(t, tool, ctx, BashParams{
		Description: "plain ls",
		Command:     "ls -la",
	})

	require.False(t, resp.IsError)
	require.Equal(t, 0, perms.requestCount, "plain ls should not trigger permission request")
}

func TestBashTool_ChainedCommandsDenied(t *testing.T) {
	workingDir := t.TempDir()
	tool, perms := newBashToolWithRecordingPerms(workingDir, false)
	ctx := context.WithValue(context.Background(), SessionIDContextKey, "test-session")

	resp := runBashTool(t, tool, ctx, BashParams{
		Description: "chained ls denied",
		Command:     "ls && rm -rf /",
	})

	require.Equal(t, 1, perms.requestCount)
	require.Contains(t, resp.Content, "User denied permission")
}

func runBashTool(t *testing.T, tool fantasy.AgentTool, ctx context.Context, params BashParams) fantasy.ToolResponse {
	t.Helper()

	input, err := json.Marshal(params)
	require.NoError(t, err)

	call := fantasy.ToolCall{
		ID:    "test-call",
		Name:  BashToolName,
		Input: string(input),
	}

	resp, err := tool.Run(ctx, call)
	require.NoError(t, err)
	return resp
}

func TestTruncateOutputValidUTF8(t *testing.T) {
	t.Parallel()
	// CJK characters are 2 cells wide; this string is far wider than
	// MaxOutputLength so TruncateOutput must truncate it.
	content := strings.Repeat("你好世界", MaxOutputLength)

	out := TruncateOutput(content)
	require.True(t, utf8.ValidString(out), "truncated output must stay valid UTF-8")
	require.Contains(t, out, "lines truncated")
}

func TestTruncateOutputShortContent(t *testing.T) {
	t.Parallel()
	content := "short output"
	require.Equal(t, content, TruncateOutput(content))
}

func TestTruncateOutputEmoji(t *testing.T) {
	t.Parallel()
	// Emoji with ZWJ sequences should not be split.
	content := strings.Repeat("👨‍👩‍👧‍👦", MaxOutputLength)

	out := TruncateOutput(content)
	require.True(t, utf8.ValidString(out), "truncated output must stay valid UTF-8")
	require.Contains(t, out, "lines truncated")
}

func TestParseAllowedCommands(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		entries []string
		want    []parsedAllowedEntry
	}{
		{
			name:    "empty input",
			entries: nil,
			want:    []parsedAllowedEntry{},
		},
		{
			name:    "bare command",
			entries: []string{"sudo"},
			want:    []parsedAllowedEntry{{cmd: "sudo"}},
		},
		{
			name:    "command with args",
			entries: []string{"apt-get install"},
			want:    []parsedAllowedEntry{{cmd: "apt-get", args: []string{"install"}}},
		},
		{
			name:    "command with flags",
			entries: []string{"npm install -g"},
			want:    []parsedAllowedEntry{{cmd: "npm", args: []string{"install"}, flags: []string{"-g"}}},
		},
		{
			name:    "flag with value stripped to name",
			entries: []string{"npm install --prefix=/foo"},
			want:    []parsedAllowedEntry{{cmd: "npm", args: []string{"install"}, flags: []string{"--prefix"}}},
		},
		{
			name:    "empty string skipped",
			entries: []string{"", "sudo"},
			want:    []parsedAllowedEntry{{cmd: "sudo"}},
		},
		{
			name:    "whitespace-only skipped",
			entries: []string{"   ", "sudo"},
			want:    []parsedAllowedEntry{{cmd: "sudo"}},
		},
		{
			name:    "multiple entries",
			entries: []string{"sudo", "curl", "apt-get install"},
			want: []parsedAllowedEntry{
				{cmd: "sudo"},
				{cmd: "curl"},
				{cmd: "apt-get", args: []string{"install"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseAllowedCommands(tt.entries)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestIsArgBlockAllowed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		rule    argBlockRule
		allowed []parsedAllowedEntry
		want    bool
	}{
		{
			name:    "empty allowed list",
			rule:    argBlockRule{cmd: "npm", args: []string{"install"}, flags: []string{"-g"}},
			allowed: nil,
			want:    false,
		},
		{
			name:    "bare command exempts all rules for that command",
			rule:    argBlockRule{cmd: "go", args: []string{"test"}, flags: []string{"-exec"}},
			allowed: []parsedAllowedEntry{{cmd: "go"}},
			want:    true,
		},
		{
			name:    "cmd+args no flags exempts all flag combos",
			rule:    argBlockRule{cmd: "npm", args: []string{"install"}, flags: []string{"--global"}},
			allowed: []parsedAllowedEntry{{cmd: "npm", args: []string{"install"}}},
			want:    true,
		},
		{
			name:    "cmd+args+flags exempts matching rule only",
			rule:    argBlockRule{cmd: "npm", args: []string{"install"}, flags: []string{"-g"}},
			allowed: []parsedAllowedEntry{{cmd: "npm", args: []string{"install"}, flags: []string{"-g"}}},
			want:    true,
		},
		{
			name:    "cmd+args+flags does not exempt non-matching flag rule",
			rule:    argBlockRule{cmd: "npm", args: []string{"install"}, flags: []string{"--global"}},
			allowed: []parsedAllowedEntry{{cmd: "npm", args: []string{"install"}, flags: []string{"-g"}}},
			want:    false,
		},
		{
			name:    "non-matching command not exempted",
			rule:    argBlockRule{cmd: "npm", args: []string{"install"}, flags: []string{"-g"}},
			allowed: []parsedAllowedEntry{{cmd: "sudo"}},
			want:    false,
		},
		{
			name:    "non-matching args not exempted",
			rule:    argBlockRule{cmd: "go", args: []string{"test"}, flags: []string{"-exec"}},
			allowed: []parsedAllowedEntry{{cmd: "go", args: []string{"install"}}},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isArgBlockAllowed(tt.rule, tt.allowed)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestBlockFuncs_Default(t *testing.T) {
	t.Parallel()
	funcs := blockFuncs(nil)
	require.True(t, anyBlocked(funcs, []string{"curl", "https://example.com"}))
	require.True(t, anyBlocked(funcs, []string{"sudo", "ls"}))
	require.True(t, anyBlocked(funcs, []string{"apt-get", "install", "foo"}))
	require.True(t, anyBlocked(funcs, []string{"npm", "install", "-g", "foo"}))
	require.False(t, anyBlocked(funcs, []string{"echo", "hello"}))
	require.False(t, anyBlocked(funcs, []string{"npm", "install", "foo"}))
}

func TestBlockFuncs_AllowedBareCommand(t *testing.T) {
	t.Parallel()
	funcs := blockFuncs([]string{"sudo"})
	require.False(t, anyBlocked(funcs, []string{"sudo", "ls"}))
	require.True(t, anyBlocked(funcs, []string{"curl", "https://example.com"}))
}

func TestBlockFuncs_AllowedMultipleBareCommands(t *testing.T) {
	t.Parallel()
	funcs := blockFuncs([]string{"sudo", "curl", "wget"})
	require.False(t, anyBlocked(funcs, []string{"sudo", "ls"}))
	require.False(t, anyBlocked(funcs, []string{"curl", "https://example.com"}))
	require.False(t, anyBlocked(funcs, []string{"wget", "https://example.com"}))
	require.True(t, anyBlocked(funcs, []string{"ssh", "user@host"}))
}

func TestBlockFuncs_AllowedArgCommand(t *testing.T) {
	t.Parallel()
	funcs := blockFuncs([]string{"apt-get install"})
	require.False(t, anyBlocked(funcs, []string{"apt-get", "install", "foo"}))
	require.True(t, anyBlocked(funcs, []string{"apt", "install", "foo"}))
}

func TestBlockFuncs_AllowedArgAllFlags(t *testing.T) {
	t.Parallel()
	funcs := blockFuncs([]string{"npm install"})
	require.False(t, anyBlocked(funcs, []string{"npm", "install", "-g", "foo"}))
	require.False(t, anyBlocked(funcs, []string{"npm", "install", "--global", "foo"}))
	require.False(t, anyBlocked(funcs, []string{"npm", "install", "foo"}))
}

func TestBlockFuncs_AllowedArgSpecificFlag(t *testing.T) {
	t.Parallel()
	funcs := blockFuncs([]string{"npm install -g"})
	require.False(t, anyBlocked(funcs, []string{"npm", "install", "-g", "foo"}))
	require.True(t, anyBlocked(funcs, []string{"npm", "install", "--global", "foo"}))
}

func TestBlockFuncs_AllowedBareCommandExemptsArgRules(t *testing.T) {
	t.Parallel()
	funcs := blockFuncs([]string{"go"})
	require.False(t, anyBlocked(funcs, []string{"go", "install", "foo"}))
	require.False(t, anyBlocked(funcs, []string{"go", "test", "-exec", "foo"}))
}

func TestBlockFuncs_AllowedBashCommandDoesNotAffectOthers(t *testing.T) {
	t.Parallel()
	funcs := blockFuncs([]string{"sudo"})
	require.True(t, anyBlocked(funcs, []string{"apt-get", "install", "foo"}))
	require.True(t, anyBlocked(funcs, []string{"npm", "install", "-g", "foo"}))
}

func anyBlocked(funcs []shell.BlockFunc, args []string) bool {
	for _, f := range funcs {
		if f(args) {
			return true
		}
	}
	return false
}
