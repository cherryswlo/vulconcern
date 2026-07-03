package scan

import (
	"bytes"
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

func TestRunReportsOversizedLightweightCodeArtifact(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0700); err != nil {
		t.Fatal(err)
	}
	extension := filepath.Join(home, ".vscode", "extensions", "codex-helper", "dist", "extension.js")
	if err := os.MkdirAll(filepath.Dir(extension), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".vscode", "extensions", "codex-helper", "package.json"), []byte(`{"name":"codex-helper"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(extension, bytes.Repeat([]byte("a"), (1<<20)+1), 0600); err != nil {
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
	hasIncompleteScan := false
	for _, item := range report.Findings {
		if item.CheckID == "VC-SCAN-001" {
			hasIncompleteScan = true
		}
	}
	if !hasIncompleteScan {
		t.Fatalf("expected oversized code to produce VC-SCAN-001, got %#v", report.Findings)
	}
}
