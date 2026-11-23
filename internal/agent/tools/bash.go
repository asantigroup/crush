package tools

import (
	"bytes"
	"cmp"
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"log/slog"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/exp/slice"

	"charm.land/fantasy"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/fsext"
	"github.com/charmbracelet/crush/internal/permission"
	"github.com/charmbracelet/crush/internal/pubsub"
	"github.com/charmbracelet/crush/internal/shell"
)

type BashParams struct {
	Description         string `json:"description" description:"A brief description of what the command does, try to keep it under 30 characters or so"`
	Command             string `json:"command" description:"The command to execute"`
	WorkingDir          string `json:"working_dir,omitempty" description:"The working directory to execute the command in (defaults to current directory)"`
	RunInBackground     bool   `json:"run_in_background,omitempty" description:"Set to true (boolean) to run this command in the background. Use job_output to read the output later."`
	AutoBackgroundAfter int    `json:"auto_background_after,omitempty" description:"Seconds to wait before automatically moving the command to a background job (default: 60)"`
}

type BashPermissionsParams struct {
	Description         string `json:"description"`
	Command             string `json:"command"`
	WorkingDir          string `json:"working_dir"`
	RunInBackground     bool   `json:"run_in_background"`
	AutoBackgroundAfter int    `json:"auto_background_after"`
}

type BashResponseMetadata struct {
	StartTime        int64  `json:"start_time"`
	EndTime          int64  `json:"end_time"`
	Output           string `json:"output"`
	Description      string `json:"description"`
	WorkingDirectory string `json:"working_directory"`
	Background       bool   `json:"background,omitempty"`
	ShellID          string `json:"shell_id,omitempty"`
}

const (
	BashToolName = "bash"

	DefaultAutoBackgroundAfter = 60 // Commands taking longer automatically become background jobs
	MaxOutputLength            = 30000
	BashNoOutput               = "no output"
)

//go:embed bash.md.tpl
var bashDescriptionTmpl []byte

var bashDescriptionTpl = template.Must(
	template.New("bashDescription").
		Parse(string(bashDescriptionTmpl)),
)

type bashDescriptionData struct {
	BannedCommands  string
	MaxOutputLength int
	Attribution     config.Attribution
	ModelID         string
	RgAvailable     bool
	GhAvailable     bool
}

// defaultBlockedCommands is the built-in dangerous-command list. It is a
// default, not a hardcoded policy: the `permissions` config block can add
// to it and take away from it (see resolveBlockedCommands), and the
// allowed_bash_commands option removes whole commands from it.
var defaultBlockedCommands = []string{
	// Shell builtins
	"alias",

	// Browsers
	"chrome",
	"firefox",
	"links",
	"lynx",
	"safari",
	"w3m",

	// Indirect execution: these run a command name the static check can't
	// see, so whatever they wrap would never be flagged on its own.
	"env",
	"eval",
	"nohup",
	"xargs",

	// Package managers
	"apk",
	"apt",
	"apt-cache",
	"apt-get",
	"dnf",
	"dpkg",
	"emerge",
	"home-manager",
	"makepkg",
	"opkg",
	"pacman",
	"paru",
	"pkg",
	"pkg_add",
	"pkg_delete",
	"portage",
	"rpm",
	"yay",
	"yum",
	"zypper",

	// Network configuration
	"firewall-cmd",
	"ifconfig",
	"ip",
	"iptables",
	"netstat",
	"pfctl",
	"route",
	"ufw",
}

// argBlockRule defines an argument-based block rule.
type argBlockRule struct {
	cmd   string
	args  []string
	flags []string
}

// argBlockRules is the list of subcommand/flag combinations that are
// blocked even when the base command is not fully banned.
var argBlockRules = []argBlockRule{
	// System package managers.
	{cmd: "apk", args: []string{"add"}},
	{cmd: "apt", args: []string{"install"}},
	{cmd: "apt-get", args: []string{"install"}},
	{cmd: "dnf", args: []string{"install"}},
	{cmd: "pacman", flags: []string{"-S"}},
	{cmd: "pkg", args: []string{"install"}},
	{cmd: "yum", args: []string{"install"}},
	{cmd: "zypper", args: []string{"install"}},

	// Language-specific package managers.
	{cmd: "brew", args: []string{"install"}},
	{cmd: "cargo", args: []string{"install"}},
	{cmd: "gem", args: []string{"install"}},
	{cmd: "go", args: []string{"install"}},
	{cmd: "npm", args: []string{"install"}, flags: []string{"--global"}},
	{cmd: "npm", args: []string{"install"}, flags: []string{"-g"}},
	{cmd: "pip", args: []string{"install"}, flags: []string{"--user"}},
	{cmd: "pip3", args: []string{"install"}, flags: []string{"--user"}},
	{cmd: "pnpm", args: []string{"add"}, flags: []string{"--global"}},
	{cmd: "pnpm", args: []string{"add"}, flags: []string{"-g"}},
	{cmd: "yarn", args: []string{"global", "add"}},

	// `go test -exec` can run arbitrary commands.
	{cmd: "go", args: []string{"test"}, flags: []string{"-exec"}},
}

// parsedAllowedEntry is a parsed entry from the allowed_bash_commands
// config option.
type parsedAllowedEntry struct {
	cmd   string
	args  []string
	flags []string
}

// parseAllowedCommands parses allowed_bash_commands entries into
// (cmd, args, flags) triples. Each entry is split on whitespace; the
// first token is the command, tokens starting with "-" are flags, and
// the rest are positional args.
func parseAllowedCommands(entries []string) []parsedAllowedEntry {
	parsed := make([]parsedAllowedEntry, 0, len(entries))
	for _, entry := range entries {
		parts := strings.Fields(entry)
		if len(parts) == 0 {
			continue
		}
		cmd := parts[0]
		var args, flags []string
		for _, p := range parts[1:] {
			if strings.HasPrefix(p, "-") {
				flag := p
				if before, _, ok := strings.Cut(p, "="); ok {
					flag = before
				}
				flags = append(flags, flag)
			} else {
				args = append(args, p)
			}
		}
		parsed = append(parsed, parsedAllowedEntry{cmd: cmd, args: args, flags: flags})
	}
	return parsed
}

// allowedCommandSet returns the set of commands that appear in any
// allowed entry (bare or with arguments). These commands are removed
// from the fully-banned list, since allowing a subcommand implies the
// base command itself should not be blanket-blocked.
func allowedCommandSet(allowed []parsedAllowedEntry) map[string]struct{} {
	set := make(map[string]struct{})
	for _, a := range allowed {
		set[a.cmd] = struct{}{}
	}
	return set
}

// isArgBlockAllowed reports whether an argument block rule is exempted
// by the allowed entries. A rule is exempted if a bare command entry
// matches (e.g. "go" exempts all "go" rules), if a matching cmd+args
// entry with no flags exempts all flag combos, or if a matching
// cmd+args entry whose flags are a superset of the rule's flags exempts
// that specific combination.
func isArgBlockAllowed(rule argBlockRule, allowed []parsedAllowedEntry) bool {
	for _, a := range allowed {
		if a.cmd != rule.cmd {
			continue
		}
		if len(a.args) == 0 && len(a.flags) == 0 {
			return true
		}
		if !slices.Equal(a.args, rule.args) {
			continue
		}
		if len(a.flags) == 0 {
			return true
		}
		if slice.IsSubset(rule.flags, a.flags) {
			return true
		}
	}
	return false
}

// resolveBlockedCommands returns the effective dangerous-command list:
// the built-in defaults plus perms.BlockedCommands, minus
// perms.AllowedCommands and any command covered by the
// allowed_bash_commands option.
//
// The built-in order is preserved and user additions are appended. The list is
// embedded verbatim in the tool description, so it has to be deterministic, but
// sorting it would scramble the category grouping the defaults are written in
// and churn the prompt for every existing user.
func resolveBlockedCommands(perms *config.Permissions, allowedBashCommands []string) []string {
	if perms == nil {
		if len(allowedBashCommands) == 0 {
			return slices.Clone(defaultBlockedCommands)
		}
		perms = &config.Permissions{}
	}
	// Both sides are normalized the way the block list itself matches, so a
	// config entry spelled "/usr/bin/CURL" or " curl " lines up with the
	// "curl" already on the list. Without this, allowing a command by a
	// slightly different spelling did nothing at all, which is the worst way
	// for a permission setting to be wrong: it looks applied.
	allowed := make(map[string]struct{}, len(perms.AllowedCommands))
	for _, cmd := range perms.AllowedCommands {
		allowed[shell.NormalizeCommandName(cmd)] = struct{}{}
	}

	blocked := make([]string, 0, len(defaultBlockedCommands)+len(perms.BlockedCommands))
	blocked = append(blocked, defaultBlockedCommands...)
	for _, cmd := range perms.BlockedCommands {
		if name := shell.NormalizeCommandName(cmd); name != "" {
			blocked = append(blocked, name)
		}
	}
	blocked = slices.DeleteFunc(blocked, func(c string) bool {
		_, ok := allowed[shell.NormalizeCommandName(c)]
		return ok
	})
	// allowed_bash_commands entries exempt commands by name: allowing a
	// subcommand implies the base command itself should not be
	// blanket-blocked.
	allowedCmds := allowedCommandSet(parseAllowedCommands(allowedBashCommands))
	blocked = slices.DeleteFunc(blocked, func(c string) bool {
		_, ok := allowedCmds[shell.NormalizeCommandName(c)]
		return ok
	})

	seen := make(map[string]struct{}, len(blocked))
	deduped := blocked[:0]
	for _, cmd := range blocked {
		if _, dup := seen[cmd]; dup {
			continue
		}
		seen[cmd] = struct{}{}
		deduped = append(deduped, cmd)
	}
	return deduped
}

func bashDescription(attribution *config.Attribution, modelID string, blocked []string) string {
	var out bytes.Buffer
	if err := bashDescriptionTpl.Execute(&out, bashDescriptionData{
		BannedCommands:  strings.Join(blocked, ", "),
		MaxOutputLength: MaxOutputLength,
		Attribution:     *attribution,
		ModelID:         modelID,
		RgAvailable:     getRg() != "",
		GhAvailable:     ghAvailable,
	}); err != nil {
		// this should never happen.
		panic("failed to execute bash description template: " + err.Error())
	}
	return out.String()
}

// blockFuncs builds the block list from the resolved dangerous commands,
// dropping argument rules that allowed_bash_commands entries exempt. The
// flat command list is configurable; the argument blockers below are
// structural rules about specific flags rather than a list of binaries, so
// they stay built in.
func blockFuncs(blocked []string, allowed []parsedAllowedEntry) []shell.BlockFunc {
	funcs := []shell.BlockFunc{
		shell.CommandsBlocker(blocked),
	}

	for _, rule := range argBlockRules {
		if isArgBlockAllowed(rule, allowed) {
			continue
		}
		funcs = append(funcs, shell.ArgumentsBlocker(rule.cmd, rule.args, rule.flags))
	}

	return funcs
}

// NewBashTool returns the bash tool. Every shell it starts is tagged with
// shellOwner, so the owner can stop them with
// [shell.BackgroundShellManager.KillOwned].
func NewBashTool(permissions permission.Service, workingDir, spillDir string, attribution *config.Attribution, modelID string, maxBackgroundJobs int, allowedBashCommands []string, perms *config.Permissions, shellOwner any, progress pubsub.Publisher[ToolProgress]) fantasy.AgentTool {
	blocked := resolveBlockedCommands(perms, allowedBashCommands)
	allowedEntries := parseAllowedCommands(allowedBashCommands)
	userSafe := userSafeCommands(perms)
	return fantasy.NewAgentTool(
		BashToolName,
		string(bashDescription(attribution, modelID, blocked)),
		func(ctx context.Context, params BashParams, call fantasy.ToolCall) (fantasy.ToolResponse, error) {
			if params.Command == "" {
				return fantasy.NewTextErrorResponse("missing command"), nil
			}

			// Determine working directory
			execWorkingDir := cmp.Or(params.WorkingDir, workingDir)

			safeReadOnly := isSafeReadOnly(params.Command, userSafe)

			sessionID := GetSessionFromContext(ctx)
			if sessionID == "" {
				return fantasy.ToolResponse{}, fmt.Errorf("session ID is required for executing shell command")
			}
			// Check whether the command is dangerous so we can surface a
			// warning in the permission dialog.
			var check shell.CommandCheck
			mode := permissions.PermissionMode()
			if !safeReadOnly {
				check = shell.CheckCommand(params.Command, blockFuncs(blocked, allowedEntries))

				if check.Matched && mode.RefusesDangerous() {
					return fantasy.NewTextErrorResponse(yoloBlockedMessage(check.Reason)), nil
				}

				p, err := permissions.Request(
					ctx,
					permission.CreatePermissionRequest{
						SessionID:   sessionID,
						Path:        execWorkingDir,
						ToolCallID:  call.ID,
						ToolName:    BashToolName,
						Action:      "execute",
						Description: fmt.Sprintf("Execute command: %s", params.Command),
						Params:      BashPermissionsParams(params),
						Danger:      check.Reason,
						// Path is only the working directory here, so a
						// session grant keyed on it alone would turn one
						// approval of `ls` into standing approval for every
						// later command run in that directory. Key it to the
						// command the user was actually shown.
						GrantKey: params.Command,
					},
				)
				if err != nil {
					return fantasy.ToolResponse{}, err
				}
				if !p {
					return NewPermissionDeniedResponse(), nil
				}
			}

			// A named match reaching here was approved at a prompt; keep the block list for everything else.
			var blocksToUse []shell.BlockFunc
			if !check.Matched && mode != permission.PermissionModeSysadmin {
				blocksToUse = blockFuncs(blocked, allowedEntries)
			}
			reporter := newProgressReporter(progress, sessionID, call.ID)
			return executeBashCommand(ctx, params, execWorkingDir, spillDir, blocksToUse, maxBackgroundJobs, shellOwner, reporter)
		},
	)
}

// yoloBlockedMessage names the way out so the model doesn't retry variations.
func yoloBlockedMessage(command string) string {
	return fmt.Sprintf("blocked: %s is a dangerous command, and yolo mode blocks dangerous commands without asking. Tell the user: they can switch to normal mode to be asked about it, use sysadmin mode to allow it, or mark it safe with `permissions safe`.", command)
}

func executeBashCommand(ctx context.Context, params BashParams, execWorkingDir, spillDir string, blockFuncsToUse []shell.BlockFunc, maxBackgroundJobs int, shellOwner any, progress *progressReporter) (fantasy.ToolResponse, error) {
	// If explicitly requested as background, start immediately with detached context
	if params.RunInBackground {
		startTime := time.Now()
		bgManager := shell.GetBackgroundShellManager()
		// Use background context so it continues after tool returns
		bgShell, err := bgManager.Start(context.Background(), shellOwner, execWorkingDir, blockFuncsToUse, params.Command, params.Description, maxBackgroundJobs)
		if err != nil {
			return fantasy.NewTextErrorResponse("Failed to start background shell: " + err.Error()), nil
		}

		// Wait a short time to detect fast failures (blocked commands, syntax errors, etc.)
		time.Sleep(1 * time.Second)
		stdout, stderr, done, execErr := bgShell.GetOutput()

		if done {
			// Command failed or completed very quickly
			bgManager.Remove(bgShell.ID)

			interrupted := shell.IsInterrupt(execErr)
			exitCode := shell.ExitCode(execErr)
			if exitCode == 0 && !interrupted && execErr != nil {
				return fantasy.NewTextErrorResponse(fmt.Sprintf("[Job %s] Error executing command: %s", bgShell.ID, execErr)), nil
			}

			stdout = formatOutput(stdout, stderr, execErr, spillDir)

			metadata := BashResponseMetadata{
				StartTime:        startTime.UnixMilli(),
				EndTime:          time.Now().UnixMilli(),
				Output:           stdout,
				Description:      params.Description,
				Background:       params.RunInBackground,
				WorkingDirectory: bgShell.WorkingDir,
			}
			if stdout == "" {
				return fantasy.WithResponseMetadata(fantasy.NewTextResponse(BashNoOutput), metadata), nil
			}
			stdout += fmt.Sprintf("\n\n<cwd>%s</cwd>", normalizeWorkingDir(bgShell.WorkingDir))
			return fantasy.WithResponseMetadata(fantasy.NewTextResponse(stdout), metadata), nil
		}

		// Still running after fast-failure check - return as background job
		metadata := BashResponseMetadata{
			StartTime:        startTime.UnixMilli(),
			EndTime:          time.Now().UnixMilli(),
			Description:      params.Description,
			WorkingDirectory: bgShell.WorkingDir,
			Background:       true,
			ShellID:          bgShell.ID,
		}
		response := fmt.Sprintf("Background shell started with ID: %s\n\nUse job_output tool to view output or job_kill to terminate.", bgShell.ID)
		return fantasy.WithResponseMetadata(fantasy.NewTextResponse(response), metadata), nil
	}

	// Start synchronous execution with auto-background support
	startTime := time.Now()

	// Start with detached context so it can survive if moved to background
	bgManager := shell.GetBackgroundShellManager()
	bgShell, err := bgManager.Start(context.Background(), shellOwner, execWorkingDir, blockFuncsToUse, params.Command, params.Description, maxBackgroundJobs)
	if err != nil {
		return fantasy.NewTextErrorResponse("Failed to start shell: " + err.Error()), nil
	}

	// Wait for either completion, auto-background threshold, or context cancellation
	autoBackgroundAfter := cmp.Or(params.AutoBackgroundAfter, DefaultAutoBackgroundAfter)
	autoBackgroundThreshold := time.Duration(autoBackgroundAfter) * time.Second
	timer := time.NewTimer(autoBackgroundThreshold)
	defer timer.Stop()
	progressTicker := time.NewTicker(progressPollInterval)
	defer progressTicker.Stop()

wait:
	for {
		select {
		case <-bgShell.Done():
			break wait
		case <-timer.C:
			break wait
		case <-progressTicker.C:
			progress.report(bgShell)
		case <-ctx.Done():
			// Incoming context was cancelled before we moved to background
			// Kill the shell and return error
			bgManager.Kill(ctx, bgShell.ID)
			return fantasy.ToolResponse{}, ctx.Err()
		}
	}
	stdout, stderr, done, execErr := bgShell.GetOutput()

	if done {
		// Command completed within threshold - return synchronously
		// Remove from background manager since we're returning directly
		// Don't call Kill() as it cancels the context and corrupts the exit code
		bgManager.Remove(bgShell.ID)

		interrupted := shell.IsInterrupt(execErr)
		exitCode := shell.ExitCode(execErr)
		if exitCode == 0 && !interrupted && execErr != nil {
			return fantasy.NewTextErrorResponse(fmt.Sprintf("[Job %s] Error executing command: %s", bgShell.ID, execErr)), nil
		}

		stdout = formatOutput(stdout, stderr, execErr, spillDir)

		metadata := BashResponseMetadata{
			StartTime:        startTime.UnixMilli(),
			EndTime:          time.Now().UnixMilli(),
			Output:           stdout,
			Description:      params.Description,
			Background:       params.RunInBackground,
			WorkingDirectory: bgShell.WorkingDir,
		}
		if stdout == "" {
			return fantasy.WithResponseMetadata(fantasy.NewTextResponse(BashNoOutput), metadata), nil
		}
		stdout += fmt.Sprintf("\n\n<cwd>%s</cwd>", normalizeWorkingDir(bgShell.WorkingDir))
		return fantasy.WithResponseMetadata(fantasy.NewTextResponse(stdout), metadata), nil
	}

	// Still running - keep as background job
	metadata := BashResponseMetadata{
		StartTime:        startTime.UnixMilli(),
		EndTime:          time.Now().UnixMilli(),
		Description:      params.Description,
		WorkingDirectory: bgShell.WorkingDir,
		Background:       true,
		ShellID:          bgShell.ID,
	}
	response := fmt.Sprintf("Command is taking longer than expected and has been moved to background.\n\nBackground shell ID: %s\n\nUse job_output tool to view output or job_kill to terminate.", bgShell.ID)
	return fantasy.WithResponseMetadata(fantasy.NewTextResponse(response), metadata), nil
}

// formatOutput formats the output of a completed command with error handling
func formatOutput(stdout, stderr string, execErr error, spillDir string) string {
	interrupted := shell.IsInterrupt(execErr)
	exitCode := shell.ExitCode(execErr)

	stdout = truncateOutput(stdout, spillDir)
	stderr = truncateOutput(stderr, spillDir)

	errorMessage := stderr
	if errorMessage == "" && execErr != nil {
		errorMessage = execErr.Error()
	}

	if interrupted {
		if errorMessage != "" {
			errorMessage += "\n"
		}
		errorMessage += "Command was aborted before completion"
	} else if exitCode != 0 {
		if errorMessage != "" {
			errorMessage += "\n"
		}
		errorMessage += fmt.Sprintf("Exit code %d", exitCode)
	}

	hasBothOutputs := stdout != "" && stderr != ""

	if hasBothOutputs {
		stdout += "\n"
	}

	if errorMessage != "" {
		stdout += "\n" + errorMessage
	}

	return stdout
}

// TruncateOutput keeps the head and tail of oversized tool output. The
// dropped middle is written in full to a file under spillDir so the agent
// can read it back rather than losing it for good.
func TruncateOutput(content, spillDir string) string {
	if ansi.StringWidth(content) <= MaxOutputLength {
		return content
	}

	halfLength := MaxOutputLength / 2
	start := ansi.Truncate(content, halfLength, "")
	end := ansi.TruncateLeft(content, ansi.StringWidth(content)-halfLength, "")

	truncatedLinesCount := max(strings.Count(content, "\n")-strings.Count(start, "\n")-strings.Count(end, "\n"), 0)
	marker := fmt.Sprintf("... [%d lines truncated] ...", truncatedLinesCount)
	if path, err := shell.SpillOutput(ansi.Strip(content), spillDir); err == nil {
		marker = fmt.Sprintf("... [%d lines truncated, full output: %s] ...", truncatedLinesCount, path)
	} else {
		slog.Debug("Could not spill tool output", "dir", spillDir, "error", err)
	}
	return fmt.Sprintf("%s\n\n%s\n\n%s", start, marker, end)
}

func truncateOutput(content, spillDir string) string {
	return TruncateOutput(content, spillDir)
}

func normalizeWorkingDir(path string) string {
	if runtime.GOOS == "windows" {
		path = strings.ReplaceAll(path, fsext.WindowsWorkingDirDrive(), "")
	}
	return filepath.ToSlash(path)
}
