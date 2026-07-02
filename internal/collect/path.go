package collect

import (
	"os"
	"path/filepath"
	"runtime"
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

func xdgConfigHome(home string) string {
	if value := os.Getenv("XDG_CONFIG_HOME"); value != "" {
		return value
	}
	return filepath.Join(home, ".config")
}
