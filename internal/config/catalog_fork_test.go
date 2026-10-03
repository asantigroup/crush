package config

import (
	"slices"
	"testing"

	"charm.land/catwalk/pkg/catwalk"
)

// requireKnownProvider skips the test when the embedded provider catalog
// does not include the provider under test. The asantigroup catwalk fork
// ships a trimmed catalog, so upstream tests that assume providers like
// openai or xai are present cannot run against it.
func requireKnownProvider(t *testing.T, id string) {
	t.Helper()
	if slices.Contains(catwalk.KnownProviders(), catwalk.InferenceProvider(id)) {
		return
	}
	t.Skipf("provider %q is not in the embedded catalog", id)
}
