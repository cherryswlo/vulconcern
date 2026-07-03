package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type CandidatePath struct {
	Path  string
	Tool  string
	Scope string
	Kind  string
}

func CandidateConfigPaths(home, project string) []CandidatePath {
	xdg := xdgConfigHome(home)
	paths := []CandidatePath{
		{Path: filepath.Join(home, ".claude.json"), Tool: "claude", Scope: "user", Kind: "config"},
		{Path: filepath.Join(home, ".claude", "settings.json"), Tool: "claude", Scope: "user", Kind: "config"},
		{Path: filepath.Join(project, ".mcp.json"), Tool: "claude", Scope: "project", Kind: "config"},
		{Path: filepath.Join(project, ".claude", "settings.json"), Tool: "claude", Scope: "project", Kind: "config"},
		{Path: filepath.Join(project, ".claude", "settings.local.json"), Tool: "claude", Scope: "project", Kind: "config"},
		{Path: filepath.Join(home, ".cursor", "mcp.json"), Tool: "cursor", Scope: "user", Kind: "config"},
		{Path: filepath.Join(project, ".cursor", "mcp.json"), Tool: "cursor", Scope: "project", Kind: "config"},
		{Path: filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), Tool: "windsurf", Scope: "user", Kind: "config"},
		{Path: filepath.Join(project, ".vscode", "mcp.json"), Tool: "vscode", Scope: "project", Kind: "config"},
		{Path: filepath.Join(home, ".codex", "config.toml"), Tool: "codex", Scope: "user", Kind: "config"},
		{Path: filepath.Join(xdg, "codex", "config.toml"), Tool: "codex", Scope: "user", Kind: "config"},
		{Path: filepath.Join(home, ".gemini", "settings.json"), Tool: "gemini", Scope: "user", Kind: "config"},
	}
	if runtime.GOOS == "darwin" {
		paths = append(paths, CandidatePath{
			Path:  filepath.Join(string(os.PathSeparator), "Library", "Application Support", "ClaudeCode", "managed-settings.json"),
			Tool:  "claude",
			Scope: "enterprise",
			Kind:  "config",
		})
	}
	return paths
}

func CandidateInstructionPaths(home, project string) []CandidatePath {
	var paths []CandidatePath
	add := func(path, scope string) {
		paths = append(paths, CandidatePath{Path: path, Tool: "instructions", Scope: scope, Kind: "instruction"})
	}
	add(filepath.Join(project, "AGENTS.md"), "project")
	add(filepath.Join(project, "CLAUDE.md"), "project")
	add(filepath.Join(project, ".cursorrules"), "project")
	add(filepath.Join(project, ".github", "copilot-instructions.md"), "project")
	add(filepath.Join(home, "CLAUDE.md"), "user")
	for _, pattern := range []string{
		filepath.Join(project, ".cursor", "rules", "*"),
		filepath.Join(project, ".claude", "commands", "*"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			add(match, "project")
		}
	}
	return paths
}

func CandidateCredentialPaths(home string) []CandidatePath {
	xdg := xdgConfigHome(home)
	return []CandidatePath{
		{Path: filepath.Join(home, ".claude", ".credentials.json"), Tool: "claude", Scope: "user", Kind: "credential"},
		{Path: filepath.Join(home, ".codex", "auth.json"), Tool: "codex", Scope: "user", Kind: "credential"},
		{Path: filepath.Join(home, ".gemini", "oauth_creds.json"), Tool: "gemini", Scope: "user", Kind: "credential"},
		{Path: filepath.Join(home, ".config", "gh", "hosts.yml"), Tool: "github", Scope: "user", Kind: "credential"},
		{Path: filepath.Join(xdg, "gh", "hosts.yml"), Tool: "github", Scope: "user", Kind: "credential"},
		{Path: filepath.Join(home, ".npmrc"), Tool: "npm", Scope: "user", Kind: "credential"},
	}
}

func CandidateShellRCPaths(home string) []CandidatePath {
	return []CandidatePath{
		{Path: filepath.Join(home, ".zshrc"), Tool: "shell", Scope: "user", Kind: "shellrc"},
		{Path: filepath.Join(home, ".bashrc"), Tool: "shell", Scope: "user", Kind: "shellrc"},
		{Path: filepath.Join(home, ".bash_profile"), Tool: "shell", Scope: "user", Kind: "shellrc"},
		{Path: filepath.Join(home, ".profile"), Tool: "shell", Scope: "user", Kind: "shellrc"},
		{Path: filepath.Join(home, ".config", "fish", "config.fish"), Tool: "shell", Scope: "user", Kind: "shellrc"},
	}
}

func CandidateShellHistoryPaths(home string) []CandidatePath {
	xdgData := xdgDataHome(home)
	return []CandidatePath{
		{Path: filepath.Join(home, ".zsh_history"), Tool: "shell", Scope: "user", Kind: "shell-history"},
		{Path: filepath.Join(home, ".bash_history"), Tool: "shell", Scope: "user", Kind: "shell-history"},
		{Path: filepath.Join(xdgData, "fish", "fish_history"), Tool: "shell", Scope: "user", Kind: "shell-history"},
	}
}

func CandidateIncidentPaths(home string) []CandidatePath {
	var paths []CandidatePath
	add := func(path string) {
		paths = append(paths, CandidatePath{Path: path, Tool: "incident", Scope: "host", Kind: "incident-artifact"})
	}

	if isRealHome(home) {
		for _, root := range incidentTempRoots() {
			add(filepath.Join(root, "inventory.txt"))
			add(filepath.Join(root, "inventory.txt.bak"))
		}
	}
	return paths
}

func CandidateAICLIWrapperPaths(home, project string) []CandidatePath {
	names := []string{"claude", "codex", "gemini", "q"}
	dirs := []string{
		filepath.Join(home, "bin"),
		filepath.Join(home, ".bin"),
		filepath.Join(home, ".local", "bin"),
		filepath.Join(home, ".npm-global", "bin"),
		filepath.Join(home, ".bun", "bin"),
		filepath.Join(home, ".cargo", "bin"),
		filepath.Join(home, ".deno", "bin"),
		filepath.Join(home, ".yarn", "bin"),
		filepath.Join(project, "node_modules", ".bin"),
	}
	for _, pattern := range []string{
		filepath.Join(home, ".nvm", "versions", "node", "*", "bin"),
		filepath.Join(home, ".volta", "bin"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		dirs = append(dirs, matches...)
	}

	var paths []CandidatePath
	for _, dir := range dedupeStrings(dirs) {
		for _, name := range names {
			paths = append(paths, CandidatePath{
				Path:  filepath.Join(dir, name),
				Tool:  name,
				Scope: "user",
				Kind:  "ai-cli-wrapper",
			})
		}
	}
	return paths
}

func CandidateAutostartPaths(home string) []CandidatePath {
	patterns := []string{
		filepath.Join(home, "Library", "LaunchAgents", "*.plist"),
		filepath.Join(home, ".config", "systemd", "user", "*.service"),
		filepath.Join(home, ".config", "autostart", "*.desktop"),
	}

	var paths []CandidatePath
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			paths = append(paths, CandidatePath{
				Path:  match,
				Tool:  "autostart",
				Scope: "user",
				Kind:  "autostart",
			})
		}
	}
	return paths
}

func CandidateEditorExtensionPaths(home string) []CandidatePath {
	extensionRoots := []string{
		filepath.Join(home, ".vscode", "extensions"),
		filepath.Join(home, ".vscode-oss", "extensions"),
		filepath.Join(home, ".vscodium", "extensions"),
		filepath.Join(home, ".cursor", "extensions"),
		filepath.Join(home, ".windsurf", "extensions"),
		filepath.Join(home, ".codeium", "windsurf", "extensions"),
	}
	relFiles := []struct {
		path string
		kind string
	}{
		{path: "package.json", kind: "extension-manifest"},
		{path: "extension.js", kind: "extension-code"},
		{path: filepath.Join("out", "extension.js"), kind: "extension-code"},
		{path: filepath.Join("dist", "extension.js"), kind: "extension-code"},
		{path: filepath.Join("build", "extension.js"), kind: "extension-code"},
	}

	var paths []CandidatePath
	for _, root := range extensionRoots {
		matches, err := filepath.Glob(filepath.Join(root, "*"))
		if err != nil {
			continue
		}
		for _, extensionDir := range matches {
			info, err := os.Stat(extensionDir)
			if err != nil || !info.IsDir() {
				continue
			}
			for _, rel := range append(relFiles, extensionManifestEntryPoints(extensionDir)...) {
				paths = append(paths, CandidatePath{
					Path:  filepath.Join(extensionDir, rel.path),
					Tool:  "editor-extension",
					Scope: "user",
					Kind:  rel.kind,
				})
			}
		}
	}
	return paths
}

func extensionManifestEntryPoints(extensionDir string) []struct {
	path string
	kind string
} {
	raw, err := os.ReadFile(filepath.Join(extensionDir, "package.json"))
	if err != nil {
		return nil
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil
	}

	var rels []string
	for _, key := range []string{"main", "browser"} {
		switch value := manifest[key].(type) {
		case string:
			rels = append(rels, value)
		case map[string]any:
			for _, mapped := range value {
				if rel, ok := mapped.(string); ok {
					rels = append(rels, rel)
				}
			}
		}
	}

	var out []struct {
		path string
		kind string
	}
	for _, rel := range dedupeStrings(rels) {
		clean := cleanExtensionRelPath(rel)
		if clean == "" {
			continue
		}
		out = append(out, struct {
			path string
			kind string
		}{path: clean, kind: "extension-code"})
	}
	return out
}

func cleanExtensionRelPath(rel string) string {
	rel = strings.TrimSpace(strings.Trim(rel, `"'`))
	if rel == "" || filepath.IsAbs(rel) {
		return ""
	}
	clean := filepath.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return ""
	}
	return clean
}

func incidentTempRoots() []string {
	roots := []string{string(os.PathSeparator) + "tmp"}
	if tmp := os.TempDir(); tmp != "" {
		roots = append(roots, tmp)
	}
	if runtime.GOOS == "darwin" {
		roots = append(roots, filepath.Join(string(os.PathSeparator), "private", "tmp"))
	}

	seen := map[string]bool{}
	var out []string
	for _, root := range roots {
		clean := filepath.Clean(root)
		if clean == "" || seen[clean] {
			continue
		}
		seen[clean] = true
		out = append(out, clean)
	}
	return out
}

func samePath(left, right string) bool {
	leftAbs, err := filepath.Abs(left)
	if err != nil {
		leftAbs = left
	}
	rightAbs, err := filepath.Abs(right)
	if err != nil {
		rightAbs = right
	}
	return filepath.Clean(leftAbs) == filepath.Clean(rightAbs)
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value == "" {
			continue
		}
		clean := filepath.Clean(value)
		if seen[clean] {
			continue
		}
		seen[clean] = true
		out = append(out, clean)
	}
	return out
}

func xdgConfigHome(home string) string {
	if value := os.Getenv("XDG_CONFIG_HOME"); value != "" && isRealHome(home) {
		return value
	}
	return filepath.Join(home, ".config")
}

func xdgDataHome(home string) string {
	if value := os.Getenv("XDG_DATA_HOME"); value != "" && isRealHome(home) {
		return value
	}
	return filepath.Join(home, ".local", "share")
}

func isRealHome(home string) bool {
	realHome, err := os.UserHomeDir()
	return err == nil && samePath(home, realHome)
}
