package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectProjectAndHomeFindsKnownPaths(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(root, "project")
	mustMkdir(t, filepath.Join(home, ".codex"))
	mustMkdir(t, filepath.Join(project, ".cursor"))
	mustMkdir(t, project)
	mustWrite(t, filepath.Join(home, ".codex", "config.toml"), []byte("model = \"gpt-5.4\"\n"))
	mustWrite(t, filepath.Join(project, ".cursor", "mcp.json"), []byte("{}\n"))
	mustWrite(t, filepath.Join(project, "AGENTS.md"), []byte("instructions\n"))

	artifacts, skipped := CollectProjectAndHome(home, project)
	if len(skipped) != 0 {
		t.Fatalf("expected no skipped paths, got %#v", skipped)
	}
	assertArtifact(t, artifacts, filepath.Join(home, ".codex", "config.toml"))
	assertArtifact(t, artifacts, filepath.Join(project, ".cursor", "mcp.json"))
	assertArtifact(t, artifacts, filepath.Join(project, "AGENTS.md"))
}

func TestCollectProjectAndHomeFindsXDGConfigHome(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(root, "project")
	xdg := filepath.Join(root, "xdg")
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	mustWrite(t, filepath.Join(xdg, "codex", "config.toml"), []byte("model = \"gpt-5\"\n"))
	mustMkdir(t, project)
	mustMkdir(t, home)

	artifacts, skipped := CollectProjectAndHome(home, project)
	if len(skipped) != 0 {
		t.Fatalf("expected no skipped paths, got %#v", skipped)
	}
	assertArtifact(t, artifacts, filepath.Join(xdg, "codex", "config.toml"))
}

func TestCollectProjectAndHomeIgnoresXDGConfigHomeForHomeOverride(t *testing.T) {
	root := t.TempDir()
	realHome := filepath.Join(root, "real-home")
	homeOverride := filepath.Join(root, "fixture-home")
	project := filepath.Join(root, "project")
	xdg := filepath.Join(root, "xdg")
	t.Setenv("HOME", realHome)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	mustWrite(t, filepath.Join(xdg, "codex", "config.toml"), []byte("model = \"gpt-5\"\n"))
	mustMkdir(t, project)
	mustMkdir(t, realHome)
	mustMkdir(t, homeOverride)

	artifacts, skipped := CollectProjectAndHome(homeOverride, project)
	if len(skipped) != 0 {
		t.Fatalf("expected no skipped paths, got %#v", skipped)
	}
	assertNoArtifact(t, artifacts, filepath.Join(xdg, "codex", "config.toml"))
}

func TestCollectProjectAndHomeFindsAICLIWrappersAndAutostart(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(root, "project")
	wrapper := filepath.Join(home, ".local", "bin", "codex")
	launchAgent := filepath.Join(home, "Library", "LaunchAgents", "com.test.codexd.plist")
	mustWrite(t, wrapper, []byte("#!/bin/sh\nexec /usr/local/bin/codex \"$@\"\n"))
	mustWrite(t, launchAgent, []byte("<plist></plist>\n"))
	mustMkdir(t, project)

	artifacts, skipped := CollectProjectAndHome(home, project)
	if len(skipped) != 0 {
		t.Fatalf("expected no skipped paths, got %#v", skipped)
	}
	assertArtifact(t, artifacts, wrapper)
	assertArtifact(t, artifacts, launchAgent)
}

func TestCollectProjectAndHomeFindsEditorExtensionFiles(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(root, "project")
	manifest := filepath.Join(home, ".vscode", "extensions", "codex-helper", "package.json")
	bundle := filepath.Join(home, ".vscode", "extensions", "codex-helper", "dist", "extension.js")
	mustWrite(t, manifest, []byte(`{"name":"codex-helper"}`))
	mustWrite(t, bundle, []byte("module.exports = {}\n"))
	mustMkdir(t, project)

	artifacts, skipped := CollectProjectAndHome(home, project)
	if len(skipped) != 0 {
		t.Fatalf("expected no skipped paths, got %#v", skipped)
	}
	assertArtifact(t, artifacts, manifest)
	assertArtifact(t, artifacts, bundle)
}

func TestCollectProjectAndHomeFindsEditorExtensionManifestEntrypoint(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(root, "project")
	manifest := filepath.Join(home, ".vscode", "extensions", "codex-helper", "package.json")
	entrypoint := filepath.Join(home, ".vscode", "extensions", "codex-helper", "dist", "main.js")
	mustWrite(t, manifest, []byte(`{"name":"codex-helper","main":"./dist/main.js"}`))
	mustWrite(t, entrypoint, []byte("module.exports = {}\n"))
	mustMkdir(t, project)

	artifacts, skipped := CollectProjectAndHome(home, project)
	if len(skipped) != 0 {
		t.Fatalf("expected no skipped paths, got %#v", skipped)
	}
	assertArtifact(t, artifacts, entrypoint)
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	mustMkdir(t, filepath.Dir(path))
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func assertArtifact(t *testing.T, artifacts []Artifact, path string) {
	t.Helper()
	for _, artifact := range artifacts {
		if artifact.Path == path && artifact.Hash != "" {
			return
		}
	}
	t.Fatalf("missing artifact %s in %#v", path, artifacts)
}

func assertNoArtifact(t *testing.T, artifacts []Artifact, path string) {
	t.Helper()
	for _, artifact := range artifacts {
		if artifact.Path == path {
			t.Fatalf("unexpected artifact %s in %#v", path, artifacts)
		}
	}
}
