package checks

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cherryswlo/vulconcern/internal/collect"
	"github.com/cherryswlo/vulconcern/internal/finding"
)

func EvaluateIncidentTriage(artifacts []collect.Artifact) []finding.Finding {
	var findings []finding.Finding
	for _, artifact := range artifacts {
		switch artifact.Kind {
		case "incident-artifact":
			findings = append(findings, evaluateIncidentArtifact(artifact)...)
		case "shell-history":
			findings = append(findings, evaluateShellHistory(artifact)...)
		}
	}
	return dedupe(findings)
}

func evaluateIncidentArtifact(artifact collect.Artifact) []finding.Finding {
	name := strings.ToLower(filepath.Base(artifact.Path))
	if name != "inventory.txt" && name != "inventory.txt.bak" {
		return nil
	}
	return []finding.Finding{{
		CheckID:  "VC-IR-001",
		Severity: finding.Critical,
		Title:    "Known local credential inventory artifact found",
		Evidence: append(baseEvidence(artifact, "pattern", "local-credential-inventory"),
			finding.KV{Key: "file_name", Value: name},
		),
		Citation:    "Known supply-chain compromise indicator",
		Remediation: "Treat this machine as potentially compromised: inspect the inventory, rotate developer credentials, and check for unexpected GitHub repositories or forks.",
	}}
}

func evaluateShellHistory(artifact collect.Artifact) []finding.Finding {
	lines := strings.Split(string(artifact.Raw), "\n")
	var findings []finding.Finding
	seen := map[string]bool{}

	for i, raw := range lines {
		line := normalizeShellHistoryLine(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}
		lower := strings.ToLower(line)
		lineNumber := strconv.Itoa(i + 1)

		if hasAgentCredentialRecon(lower) {
			findings = appendOnce(findings, seen, finding.Finding{
				CheckID:  "VC-IR-002",
				Severity: finding.Critical,
				Title:    "Shell history shows AI CLI credential-reconnaissance pattern",
				Evidence: append(baseEvidence(artifact, "pattern", "ai-cli-credential-recon"),
					finding.KV{Key: "line", Value: lineNumber},
				),
				Citation:    "AI CLI abuse for local credential reconnaissance",
				Remediation: "Review the surrounding history and rotate credentials referenced by the reconnaissance target set.",
			})
			continue
		}

		if hasAIPermissionBypass(lower) {
			findings = appendOnce(findings, seen, finding.Finding{
				CheckID:  "VC-IR-003",
				Severity: finding.High,
				Title:    "Shell history shows AI CLI permission-bypass usage",
				Evidence: append(baseEvidence(artifact, "pattern", "ai-cli-permission-bypass"),
					finding.KV{Key: "line", Value: lineNumber},
				),
				Citation:    "AI CLI permission-bypass or trust-all-tools usage",
				Remediation: "Confirm this was an intentional local command; if not, inspect recent package installs and rotate affected credentials.",
			})
		}

		if hasKnownIncidentReference(lower) {
			findings = appendOnce(findings, seen, finding.Finding{
				CheckID:  "VC-IR-004",
				Severity: finding.High,
				Title:    "Shell history references known supply-chain compromise indicators",
				Evidence: append(baseEvidence(artifact, "pattern", "known-incident-reference"),
					finding.KV{Key: "line", Value: lineNumber},
				),
				Citation:    "Known local or GitHub artifact from developer-tool compromise",
				Remediation: "Check whether the referenced artifact exists and follow incident response steps for token rotation and repository exposure.",
			})
		}
	}

	return findings
}

func appendOnce(findings []finding.Finding, seen map[string]bool, item finding.Finding) []finding.Finding {
	if seen[item.CheckID] {
		return findings
	}
	seen[item.CheckID] = true
	return append(findings, item)
}

func normalizeShellHistoryLine(line string) string {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, ": ") {
		if _, command, ok := strings.Cut(trimmed, ";"); ok {
			return strings.TrimSpace(command)
		}
	}
	if strings.HasPrefix(trimmed, "- cmd: ") {
		return strings.TrimSpace(strings.TrimPrefix(trimmed, "- cmd: "))
	}
	return trimmed
}

func hasAgentCredentialRecon(lower string) bool {
	if !hasAIPermissionBypass(lower) {
		return false
	}
	for _, needle := range []string{
		"recursively search",
		"inventory.txt",
		"id_rsa",
		".npmrc",
		".env",
		"secrets.json",
		"wallet",
		"keystore",
		"local storage",
		"indexeddb",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func hasAIPermissionBypass(lower string) bool {
	normalized := " " + normalizeCommandText(lower) + " "
	hasAI := strings.Contains(normalized, " claude ") ||
		strings.Contains(normalized, " gemini ") ||
		strings.Contains(normalized, " q ") ||
		strings.Contains(normalized, " amazon q ") ||
		strings.Contains(normalized, " codex ")
	if !hasAI {
		return false
	}
	for _, flag := range []string{
		"--dangerously-skip-permissions",
		"--yolo",
		"--trust-all-tools",
		"--no-interactive",
		"--auto-approve",
		"--autoapprove",
		"--always-allow",
		"--alwaysallow",
	} {
		if strings.Contains(normalized, flag) {
			return true
		}
	}
	return false
}

func hasKnownIncidentReference(lower string) bool {
	for _, needle := range []string{
		"s1ngularity-repository",
		"results.b64",
		"/tmp/inventory.txt",
		"/private/tmp/inventory.txt",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}
