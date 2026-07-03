package checks

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cherryswlo/vulconcern/internal/collect"
	"github.com/cherryswlo/vulconcern/internal/finding"
)

var exportedSecretPattern = regexp.MustCompile(`(?m)(^|\s)(export\s+)?(ANTHROPIC_API_KEY|OPENAI_API_KEY|ANTHROPIC_AUTH_TOKEN|OPENAI_BASE_URL|ANTHROPIC_BASE_URL)\s*=`)

func EvaluateCredentialSurface(artifacts []collect.Artifact) []finding.Finding {
	var findings []finding.Finding
	credentialHashesByName := map[string]string{}
	credentialPathsByHash := map[string]string{}
	for _, artifact := range artifacts {
		if artifact.Kind == "credential" && artifact.Hash != "" {
			credentialHashesByName[filepath.Base(artifact.Path)] = artifact.Hash
			credentialPathsByHash[artifact.Hash] = artifact.Path
		}
	}

	for _, artifact := range artifacts {
		switch artifact.Kind {
		case "credential":
			if artifact.Mode.Perm()&0077 != 0 || artifact.Mode.Perm()&0111 != 0 {
				findings = append(findings, finding.Finding{
					CheckID:  "VC-CRED-001",
					Severity: finding.Medium,
					Title:    "Credential file mode is broader than 0600",
					Evidence: []finding.KV{
						{Key: "path", Value: artifact.Path},
						{Key: "mode", Value: fmt.Sprintf("%#o", artifact.Mode.Perm())},
						{Key: "sha256", Value: shortHash(artifact.Hash)},
					},
					Citation:    "Broadly readable local credential file",
					Remediation: "Restrict the file mode to 0600.",
				})
			}
		case "credential-copy":
			expectedPath := credentialPathsByHash[artifact.Hash]
			hash := credentialHashesByName[filepath.Base(artifact.Path)]
			if artifact.Hash != "" && (expectedPath != "" || hash == artifact.Hash) {
				findings = append(findings, finding.Finding{
					CheckID:  "VC-CRED-002",
					Severity: finding.High,
					Title:    "Credential file copy found outside its expected location",
					Evidence: []finding.KV{
						{Key: "path", Value: artifact.Path},
						{Key: "expected_path", Value: expectedPath},
						{Key: "sha256", Value: shortHash(artifact.Hash)},
					},
					Citation:    "Credential copy outside its expected location",
					Remediation: "Delete the stray copy after confirming it is not needed, then rotate the affected credential.",
				})
			}
		case "shellrc":
			findings = append(findings, evaluateShellRC(artifact)...)
		}
	}
	return dedupe(findings)
}

func evaluateShellRC(artifact collect.Artifact) []finding.Finding {
	text := string(artifact.Raw)
	lower := strings.ToLower(text)
	var findings []finding.Finding
	findings = append(findings, textCommandRisks(artifact, text)...)
	findings = append(findings, baseURLOverrideRisks(artifact, text)...)

	if exportedSecretPattern.MatchString(text) {
		findings = append(findings, finding.Finding{
			CheckID:     "VC-CRED-003",
			Severity:    finding.Info,
			Title:       "Shell profile exports AI provider credential or endpoint variables",
			Evidence:    baseEvidence(artifact, "pattern", "provider-env-export"),
			Citation:    "Shell profile export of AI credential or endpoint variables",
			Remediation: "Prefer a credential manager when possible and review endpoint overrides carefully.",
		})
	}

	if strings.Contains(lower, "sudo shutdown") || strings.Contains(lower, "shutdown -h") {
		findings = append(findings, finding.Finding{
			CheckID:     "VC-CRED-004",
			Severity:    finding.High,
			Title:       "Shell profile contains a destructive shutdown command",
			Evidence:    baseEvidence(artifact, "pattern", "shutdown-command"),
			Citation:    "Destructive shell profile tampering pattern",
			Remediation: "Remove the command and review recent package installs and shell profile history.",
		})
	}

	if hasSuspiciousAICLIAlias(text) {
		findings = append(findings, finding.Finding{
			CheckID:     "VC-CRED-005",
			Severity:    finding.Medium,
			Title:       "Shell profile aliases an AI CLI command to a suspicious target",
			Evidence:    baseEvidence(artifact, "pattern", "ai-cli-alias"),
			Citation:    "AI CLI wrapper or session interception pattern",
			Remediation: "Confirm the alias target is expected and not a wrapper in a temporary, hidden, or shell-eval path.",
		})
	}

	if hasSuspiciousShellSource(text) {
		findings = append(findings, finding.Finding{
			CheckID:     "VC-CRED-006",
			Severity:    finding.High,
			Title:       "Shell profile sources a script from a suspicious path",
			Evidence:    baseEvidence(artifact, "pattern", "suspicious-shell-source"),
			Citation:    "Shell profile sourced from a temporary or hidden path",
			Remediation: "Remove the sourced path unless it is expected and stored in a trusted location.",
		})
	}

	return findings
}

func hasSuspiciousAICLIAlias(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lower := strings.ToLower(trimmed)
		if !strings.HasPrefix(lower, "alias claude=") &&
			!strings.HasPrefix(lower, "alias codex=") &&
			!strings.HasPrefix(lower, "alias gemini=") &&
			!strings.HasPrefix(lower, "alias q=") {
			continue
		}
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if suspiciousAliasTarget(parts[1]) {
			return true
		}
	}
	return false
}

func suspiciousAliasTarget(target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	target = strings.Trim(target, `"'`)
	for _, needle := range []string{
		"/tmp/",
		"/private/tmp/",
		"/var/folders/",
		"/.tmp",
		"curl ",
		"wget ",
		"sh -c",
		"bash -c",
		"zsh -c",
		"python -c",
		"osascript",
		"eval ",
		"|",
		">",
		"<",
	} {
		if strings.Contains(target, needle) {
			return true
		}
	}
	return false
}

func hasSuspiciousShellSource(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		var target string
		switch {
		case strings.HasPrefix(trimmed, "source "):
			target = strings.TrimSpace(strings.TrimPrefix(trimmed, "source "))
		case strings.HasPrefix(trimmed, ". "):
			target = strings.TrimSpace(strings.TrimPrefix(trimmed, ". "))
		default:
			continue
		}
		if suspiciousSourceTarget(target) {
			return true
		}
	}
	return false
}

func suspiciousSourceTarget(target string) bool {
	target = strings.ToLower(strings.TrimSpace(strings.Trim(target, `"'`)))
	for _, needle := range []string{
		"/tmp/",
		"/private/tmp/",
		"/var/folders/",
		"/downloads/",
		"/.tmp",
		"/.cache/",
	} {
		if strings.Contains(target, needle) {
			return true
		}
	}
	return false
}

func shortHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}
