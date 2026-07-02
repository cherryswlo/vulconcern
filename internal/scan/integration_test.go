package scan

import (
	"path/filepath"
	"runtime"
	"testing"
)

func fixtureDir(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "fixtures", name)
}

func findingIDs(t *testing.T, home, project string) map[string]bool {
	t.Helper()
	report, err := Run(Options{
		Home:         home,
		Project:      project,
		BaselinePath: filepath.Join(t.TempDir(), "baseline.json"),
	})
	if err != nil {
		t.Fatalf("scan.Run failed: %v", err)
	}
	ids := map[string]bool{}
	for _, f := range report.Findings {
		ids[f.CheckID] = true
	}
	return ids
}

func TestIntegrationClean(t *testing.T) {
	base := fixtureDir("clean")
	ids := findingIDs(t, filepath.Join(base, "home"), filepath.Join(base, "project"))
	if len(ids) != 0 {
		t.Errorf("clean profile should produce zero findings, got %v", ids)
	}
}

func TestIntegrationSingularityLike(t *testing.T) {
	base := fixtureDir("singularity-like")
	ids := findingIDs(t, filepath.Join(base, "home"), filepath.Join(base, "project"))

	expected := []string{
		"VC-CMD-001",
		"VC-CMD-007",
		"VC-CRED-004",
		"VC-CRED-005",
		"VC-CRED-006",
	}
	for _, id := range expected {
		if !ids[id] {
			t.Errorf("expected finding %s not present; got %v", id, ids)
		}
	}
}

func TestIntegrationRogueMCPFull(t *testing.T) {
	base := fixtureDir("rogue-mcp-full")
	ids := findingIDs(t, filepath.Join(base, "home"), filepath.Join(base, "project"))

	expected := []string{
		"VC-CMD-001",
		"VC-CONFIG-001",
		"VC-CRED-003",
		"VC-MCP-001",
		"VC-MCP-002",
		"VC-MCP-003",
	}
	for _, id := range expected {
		if !ids[id] {
			t.Errorf("expected finding %s not present; got %v", id, ids)
		}
	}
}

func TestIntegrationBase64Instruction(t *testing.T) {
	base := fixtureDir("base64-instruction")
	ids := findingIDs(t, filepath.Join(base, "home"), filepath.Join(base, "project"))

	expected := []string{
		"VC-INSTR-001",
		"VC-INSTR-002",
	}
	for _, id := range expected {
		if !ids[id] {
			t.Errorf("expected finding %s not present; got %v", id, ids)
		}
	}
}
