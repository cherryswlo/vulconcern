package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cherryswlo/vulconcern/internal/collect"
)

func TestSaveRestrictsExistingBaselineMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	err := Save(path, []collect.Artifact{{
		Path: "/tmp/project/.mcp.json",
		Kind: "config",
		Hash: "abc123",
	}})
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("baseline mode = %#o, want 0600", got)
	}
}
