package update

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// tokenEnvVars lists the environment variables a GitHub API token is read
// from, in precedence order.
var tokenEnvVars = []string{"CRUSH_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"}

// githubToken returns a GitHub API token for authenticated update checks, or
// "" when none is configured. Authenticated requests lift the 60 requests
// per hour unauthenticated per-IP limit, which shared NAT addresses exhaust
// almost immediately. The token is read from CRUSH_GITHUB_TOKEN, GH_TOKEN, or
// GITHUB_TOKEN, falling back to the gh CLI's login token when available.
func githubToken() string {
	for _, key := range tokenEnvVars {
		if token := strings.TrimSpace(os.Getenv(key)); token != "" {
			return token
		}
	}
	return ghHostsToken()
}

// ghHostsToken reads the oauth_token recorded for github.com in the gh CLI's
// hosts.yml. It is best-effort: any problem reading or parsing the file
// yields "" and update checks proceed unauthenticated.
func ghHostsToken() string {
	dir := ghConfigDir()
	if dir == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		return ""
	}

	host := ""
	for line := range strings.SplitSeq(string(data), "\n") {
		switch {
		case strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#"):
			continue
		case !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t"):
			host = strings.TrimSuffix(strings.TrimSpace(line), ":")
		case host == "github.com" && isHostLevelKey(line):
			if name, value, ok := parseEntry(line); ok && name == "oauth_token" && value != "" {
				return value
			}
		}
	}
	return ""
}

// isHostLevelKey reports whether the line is a key directly under a host
// block, i.e. indented by exactly the four spaces gh writes. Deeper keys,
// such as per-user tokens nested under "users:", are ignored.
func isHostLevelKey(line string) bool {
	return strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     ")
}

// parseEntry splits a "key: value" YAML line into its trimmed parts.
func parseEntry(line string) (key, value string, ok bool) {
	key, value, ok = strings.Cut(line, ":")
	if !ok {
		return "", "", false
	}
	key = strings.TrimSpace(key)
	value = strings.Trim(strings.TrimSpace(value), `"'`)
	return key, value, key != ""
}

// ghConfigDir returns gh's configuration directory, honoring GH_CONFIG_DIR
// the same way gh itself does.
func ghConfigDir() string {
	if dir := os.Getenv("GH_CONFIG_DIR"); dir != "" {
		return dir
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(dir, "GitHub CLI")
	}
	return filepath.Join(dir, "gh")
}
