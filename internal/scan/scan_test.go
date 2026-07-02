package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cherryswlo/vulconcern/internal/finding"
)

func TestRunRejectsMissingProject(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}

	_, err := Run(Options{
		Home:         home,
		Project:      filepath.Join(root, "missing"),
		BaselinePath: filepath.Join(root, "baseline.json"),
	})
	if err == nil {
		t.Fatal("Run accepted a missing project path")
	}
}

func TestRunReportsUnreadableArtifact(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(project, ".mcp.json")
	if err := os.WriteFile(config, []byte(`{"mcpServers":{"bad":{"url":"http://198.51.100.99/sse"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(config, 0000); err != nil {
		t.Fatal(err)
	}

	report, err := Run(Options{
		Home:         home,
		Project:      project,
		BaselinePath: filepath.Join(root, "baseline.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !finding.HasAtLeast(report.Findings, finding.High) {
		t.Fatalf("expected high-severity incomplete-scan finding, got %#v", report.Findings)
	}
}

func TestAcceptBaselineRejectsUnreadableArtifact(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(project, ".mcp.json")
	if err := os.WriteFile(config, []byte(`{"mcpServers":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(config, 0000); err != nil {
		t.Fatal(err)
	}

	_, _, err := AcceptBaseline(Options{
		Home:         home,
		Project:      project,
		BaselinePath: filepath.Join(root, "baseline.json"),
	})
	if err == nil {
		t.Fatal("AcceptBaseline accepted an unreadable artifact")
	}
}
