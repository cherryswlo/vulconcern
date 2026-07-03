package checks

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/cherryswlo/vulconcern/internal/collect"
	"github.com/cherryswlo/vulconcern/internal/finding"
)

func EvaluateUsageSiphon(artifacts []collect.Artifact) []finding.Finding {
	var findings []finding.Finding
	for _, artifact := range artifacts {
		switch artifact.Kind {
		case "ai-cli-wrapper":
			findings = append(findings, evaluateAICLIWrapper(artifact)...)
		case "autostart":
			findings = append(findings, evaluateAutostartSiphon(artifact)...)
		case "shellrc":
			findings = append(findings, evaluateShellWrapperSiphon(artifact)...)
		case "extension-code":
			findings = append(findings, evaluateExtensionCodeSiphon(artifact)...)
		case "extension-manifest":
			findings = append(findings, evaluateExtensionManifestSiphon(artifact)...)
		}
	}
	return dedupe(findings)
}

func evaluateAICLIWrapper(artifact collect.Artifact) []finding.Finding {
	if len(artifact.Raw) == 0 {
		return nil
	}
	text := string(artifact.Raw)
	lower := strings.ToLower(text)
	if !hasAICredentialReference(lower) {
		return nil
	}

	evidence := []finding.KV{
		{Key: "path", Value: artifact.Path},
		{Key: "kind", Value: artifact.Kind},
		{Key: "tool", Value: filepath.Base(artifact.Path)},
		{Key: "pattern", Value: "ai-cli-wrapper-credential-touch"},
	}
	findings := []finding.Finding{{
		CheckID:     "VC-SIPHON-001",
		Severity:    finding.High,
		Title:       "AI CLI wrapper touches local auth or token material",
		Evidence:    evidence,
		Citation:    "Credential-touching AI CLI wrapper heuristic",
		Remediation: "Verify this wrapper is expected. If not, remove it, reinstall the official CLI, and rotate the affected AI-provider credentials.",
	}}
	if hasNetworkRelay(lower) {
		findings = append(findings, finding.Finding{
			CheckID:  "VC-SIPHON-002",
			Severity: finding.Critical,
			Title:    "AI CLI wrapper combines token access with network relay behavior",
			Evidence: []finding.KV{
				{Key: "path", Value: artifact.Path},
				{Key: "kind", Value: artifact.Kind},
				{Key: "tool", Value: filepath.Base(artifact.Path)},
				{Key: "pattern", Value: "ai-cli-token-network-relay"},
			},
			Citation:    "Covert AI account usage or token exfiltration heuristic",
			Remediation: "Treat the account as potentially hijacked: remove the wrapper, rotate tokens, revoke active sessions, and review provider usage logs.",
		})
	}
	return findings
}

func evaluateAutostartSiphon(artifact collect.Artifact) []finding.Finding {
	text := string(artifact.Raw)
	lower := strings.ToLower(text)
	if strings.TrimSpace(lower) == "" {
		return nil
	}

	var findings []finding.Finding
	if hasAICredentialReference(lower) && (hasNetworkRelay(lower) || hasAutostartBehavior(lower)) {
		findings = append(findings, finding.Finding{
			CheckID:  "VC-SIPHON-003",
			Severity: finding.Critical,
			Title:    "Autostart job references AI auth material",
			Evidence: []finding.KV{
				{Key: "path", Value: artifact.Path},
				{Key: "kind", Value: artifact.Kind},
				{Key: "pattern", Value: "autostart-ai-credential-touch"},
			},
			Citation:    "Background AI credential access heuristic",
			Remediation: "Disable the autostart job, inspect the target program, rotate AI-provider credentials, and review usage logs for activity during normal work windows.",
		})
	}
	if hasAIToolReference(lower) && hasSuspiciousAutostartPath(lower) {
		findings = append(findings, finding.Finding{
			CheckID:  "VC-SIPHON-004",
			Severity: finding.High,
			Title:    "Autostart job runs suspicious AI-tool-adjacent command",
			Evidence: []finding.KV{
				{Key: "path", Value: artifact.Path},
				{Key: "kind", Value: artifact.Kind},
				{Key: "pattern", Value: "autostart-ai-suspicious-path"},
			},
			Citation:    "Background AI tool wrapper or usage siphon heuristic",
			Remediation: "Confirm the autostart job is expected and remove it if it is not part of an intentional local workflow.",
		})
	}
	return findings
}

func evaluateShellWrapperSiphon(artifact collect.Artifact) []finding.Finding {
	text := string(artifact.Raw)
	lower := strings.ToLower(text)
	if !hasShellAIWrapperDefinition(lower) || !hasAICredentialReference(lower) {
		return nil
	}

	severity := finding.High
	pattern := "shell-ai-wrapper-credential-touch"
	if hasNetworkRelay(lower) {
		severity = finding.Critical
		pattern = "shell-ai-wrapper-token-network-relay"
	}
	return []finding.Finding{{
		CheckID:  "VC-SIPHON-005",
		Severity: severity,
		Title:    "Shell profile defines an AI CLI wrapper that touches auth material",
		Evidence: []finding.KV{
			{Key: "path", Value: artifact.Path},
			{Key: "kind", Value: artifact.Kind},
			{Key: "pattern", Value: pattern},
		},
		Citation:    "Interactive AI CLI usage siphon heuristic",
		Remediation: "Remove unexpected shell functions or aliases, reinstall the official CLI, and rotate affected AI-provider credentials.",
	}}
}

func evaluateExtensionCodeSiphon(artifact collect.Artifact) []finding.Finding {
	if len(artifact.Raw) == 0 {
		return nil
	}
	lower := strings.ToLower(string(artifact.Raw))
	if !hasAICredentialReference(lower) || !hasNetworkRelay(lower) {
		return nil
	}
	return []finding.Finding{{
		CheckID:  "VC-SIPHON-006",
		Severity: finding.Critical,
		Title:    "Editor extension code combines AI auth access with network relay behavior",
		Evidence: []finding.KV{
			{Key: "path", Value: artifact.Path},
			{Key: "kind", Value: artifact.Kind},
			{Key: "pattern", Value: "extension-ai-token-network-relay"},
		},
		Citation:    "Covert AI account usage or token exfiltration heuristic inside an editor extension",
		Remediation: "Disable the extension, inspect or reinstall it from a trusted source, revoke active AI-provider sessions, and rotate affected credentials.",
	}}
}

func evaluateExtensionManifestSiphon(artifact collect.Artifact) []finding.Finding {
	var manifest map[string]any
	if err := json.Unmarshal(artifact.Raw, &manifest); err != nil {
		return nil
	}
	if !isAIAdjacentExtensionManifest(manifest) || !hasInstallLifecycleScript(manifest) {
		return nil
	}
	return []finding.Finding{{
		CheckID:  "VC-SIPHON-007",
		Severity: finding.Medium,
		Title:    "AI-adjacent editor extension has install lifecycle scripts",
		Evidence: []finding.KV{
			{Key: "path", Value: artifact.Path},
			{Key: "kind", Value: artifact.Kind},
			{Key: "pattern", Value: "ai-extension-install-script"},
		},
		Citation:    "AI-adjacent extension install-time execution heuristic",
		Remediation: "Verify the extension publisher and installed source; remove it if the lifecycle script is unexpected.",
	}}
}

func hasAICredentialReference(lower string) bool {
	for _, needle := range []string{
		".codex/auth.json",
		".claude/.credentials",
		".gemini/oauth_creds",
		"anthropic_auth_token",
		"anthropic_api_key",
		"openai_api_key",
		"refresh_token",
		"access_token",
		"authorization: bearer",
		"bearer ",
		"oauth",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func hasNetworkRelay(lower string) bool {
	for _, needle := range []string{
		"curl ",
		"wget ",
		"fetch(",
		"http.get(",
		"https.get(",
		"xmlhttprequest",
		"websocket",
		"wss://",
		"http://",
		"https://",
		"nc ",
		"ncat ",
		"socat ",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func hasAIToolReference(lower string) bool {
	normalized := " " + normalizeCommandText(lower) + " "
	for _, needle := range []string{
		" claude ",
		" codex ",
		" gemini ",
		" q ",
		" amazon q ",
		" anthropic_",
		" openai_",
		".codex/",
		".claude/",
		".gemini/",
	} {
		if strings.Contains(normalized, needle) || strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func hasAutostartBehavior(lower string) bool {
	for _, needle := range []string{
		"runatload",
		"startinterval",
		"keepalive",
		"watchpaths",
		"wantedby=",
		"timer",
		"oncalendar",
		"autostart",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func hasSuspiciousAutostartPath(lower string) bool {
	for _, needle := range []string{
		"/tmp/",
		"/private/tmp/",
		"/var/folders/",
		"/.cache/",
		"/.tmp",
		"/downloads/",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func hasShellAIWrapperDefinition(lower string) bool {
	for _, needle := range []string{
		"alias claude=",
		"alias codex=",
		"alias gemini=",
		"alias q=",
		"function claude",
		"function codex",
		"function gemini",
		"function q",
		"claude()",
		"codex()",
		"gemini()",
		"q()",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func isAIAdjacentExtensionManifest(manifest map[string]any) bool {
	var parts []string
	for _, key := range []string{"name", "displayName", "description", "publisher"} {
		if value, ok := manifest[key].(string); ok {
			parts = append(parts, value)
		}
	}
	text := strings.ToLower(strings.Join(parts, " "))
	for _, needle := range []string{
		"codex",
		"claude",
		"anthropic",
		"openai",
		"gemini",
		"ai agent",
		"coding agent",
	} {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func hasInstallLifecycleScript(manifest map[string]any) bool {
	scripts, ok := manifest["scripts"].(map[string]any)
	if !ok {
		return false
	}
	for _, key := range []string{"preinstall", "install", "postinstall", "prepare"} {
		if value, ok := scripts[key].(string); ok && strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}
