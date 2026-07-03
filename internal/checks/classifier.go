package checks

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/cherryswlo/vulconcern/internal/collect"
	"github.com/cherryswlo/vulconcern/internal/finding"
)

var urlPattern = regexp.MustCompile(`(?i)(https?|wss?)://[^\s"'<>),]+`)
var longBase64Pattern = regexp.MustCompile(`[A-Za-z0-9+/]{120,}={0,2}`)
var broadBashPattern = regexp.MustCompile(`(?i)bash\s*\(\s*\*\s*\)`)
var pipePattern = regexp.MustCompile(`\s*\|\s*`)
var spacePattern = regexp.MustCompile(`\s+`)

func textCommandRisks(artifact collect.Artifact, text string) []finding.Finding {
	lower := strings.ToLower(text)
	var findings []finding.Finding

	if hasDownloadExec(lower) {
		findings = append(findings, finding.Finding{
			CheckID:     "VC-CMD-001",
			Severity:    finding.Critical,
			Title:       "Command content contains a download-and-execute pattern",
			Evidence:    baseEvidence(artifact, "pattern", "download-and-execute"),
			Citation:    "Download-and-execute shell pattern",
			Remediation: "Remove the command or replace it with a reviewed local script from a trusted path.",
		})
	}

	if hasCredentialTouch(lower) {
		findings = append(findings, finding.Finding{
			CheckID:     "VC-CMD-002",
			Severity:    finding.High,
			Title:       "Command content references credential file locations",
			Evidence:    baseEvidence(artifact, "pattern", "credential-path-reference"),
			Citation:    "Credential file access or staging pattern",
			Remediation: "Review why this configuration or script needs credential paths; remove it unless it is intentional and trusted.",
		})
	}

	if hasAIHeadless(lower) {
		findings = append(findings, finding.Finding{
			CheckID:     "VC-CMD-003",
			Severity:    finding.High,
			Title:       "Command content appears to invoke an AI CLI headlessly",
			Evidence:    baseEvidence(artifact, "pattern", "ai-cli-headless"),
			Citation:    "Headless AI CLI execution pattern",
			Remediation: "Review the invocation and remove unattended AI CLI execution unless it is a known automation.",
		})
	}

	if strings.Contains(lower, "--dangerously-skip-permissions") || broadBashPattern.MatchString(text) {
		findings = append(findings, finding.Finding{
			CheckID:     "VC-CMD-004",
			Severity:    finding.High,
			Title:       "Configuration grants broad command execution permissions",
			Evidence:    baseEvidence(artifact, "pattern", "broad-command-permission"),
			Citation:    "Command allowlist or permission-bypass pattern",
			Remediation: "Narrow the allowlist to specific commands or remove permission-skip flags.",
		})
	}

	if strings.Contains(lower, "alwaysallow") || strings.Contains(lower, "autoapprove") {
		findings = append(findings, finding.Finding{
			CheckID:     "VC-CMD-005",
			Severity:    finding.Medium,
			Title:       "Configuration contains auto-approval style permissions",
			Evidence:    baseEvidence(artifact, "pattern", "auto-approval"),
			Citation:    "Auto-approval or trust-chain abuse pattern",
			Remediation: "Confirm the auto-approved tools are narrow and expected.",
		})
	}

	if longBase64Pattern.MatchString(text) {
		findings = append(findings, finding.Finding{
			CheckID:     "VC-CMD-006",
			Severity:    finding.Medium,
			Title:       "Content contains a long base64-like blob",
			Evidence:    baseEvidence(artifact, "pattern", "long-base64-like-run"),
			Citation:    "Obfuscated payload or encoded-blob pattern",
			Remediation: "Decode and review the blob in an isolated environment, or remove it if it is not expected.",
		})
	}

	return findings
}

func remoteURLRisks(artifact collect.Artifact, text string) []finding.Finding {
	return urlRiskFindings(artifact, text, nil)
}

func urlRiskFindings(artifact collect.Artifact, text string, extraEvidence []finding.KV) []finding.Finding {
	var findings []finding.Finding
	for _, raw := range urlPattern.FindAllString(text, -1) {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		evidence := append(baseEvidence(artifact, "url_host", host), extraEvidence...)
		scheme := strings.ToLower(parsed.Scheme)
		if scheme == "http" || scheme == "ws" {
			findings = append(findings, finding.Finding{
				CheckID:     "VC-MCP-001",
				Severity:    finding.High,
				Title:       "Remote MCP or config URL uses plaintext HTTP",
				Evidence:    append(evidence, finding.KV{Key: "scheme", Value: scheme}),
				Citation:    "Plaintext remote MCP or config transport",
				Remediation: "Use HTTPS and verify the MCP server identity before trusting it.",
			})
			continue
		}
		if net.ParseIP(host) != nil {
			findings = append(findings, finding.Finding{
				CheckID:     "VC-MCP-002",
				Severity:    finding.High,
				Title:       "Remote MCP or config URL uses an IP literal host",
				Evidence:    evidence,
				Citation:    "IP-literal remote endpoint trust risk",
				Remediation: "Prefer a reviewed domain name or explicitly allowlist the host after review.",
			})
			continue
		}
		if strings.Contains(host, "xn--") {
			findings = append(findings, finding.Finding{
				CheckID:     "VC-MCP-003",
				Severity:    finding.Medium,
				Title:       "Remote URL host uses punycode",
				Evidence:    evidence,
				Citation:    "Lookalike or punycode remote endpoint risk",
				Remediation: "Decode and verify the host before trusting this endpoint.",
			})
			continue
		}
		if !isFirstPartyAIHost(host) && (scheme == "https" || scheme == "wss") {
			findings = append(findings, finding.Finding{
				CheckID:     "VC-MCP-004",
				Severity:    finding.Info,
				Title:       "Remote MCP or config URL uses an unrecognized host",
				Evidence:    evidence,
				Citation:    "Remote MCP endpoint trust boundary",
				Remediation: "Verify the host is expected before trusting this endpoint.",
			})
		}
	}
	return dedupe(findings)
}

func baseURLOverrideRisks(artifact collect.Artifact, text string) []finding.Finding {
	var findings []finding.Finding
	for _, line := range strings.Split(text, "\n") {
		if !hasBaseURLMarker(line) {
			continue
		}
		for _, raw := range urlPattern.FindAllString(line, -1) {
			parsed, err := url.Parse(raw)
			if err != nil || parsed.Hostname() == "" {
				continue
			}
			host := strings.ToLower(parsed.Hostname())
			if isFirstPartyAIHost(host) {
				continue
			}
			findings = append(findings, finding.Finding{
				CheckID:     "VC-CONFIG-001",
				Severity:    finding.High,
				Title:       "AI provider base URL points to a non-first-party host",
				Evidence:    baseEvidence(artifact, "url_host", host),
				Citation:    "Non-first-party AI API relay or gateway override",
				Remediation: "Remove the override unless this is a known corporate gateway; record an allowlist entry once allowlists land.",
			})
		}
	}
	return dedupe(findings)
}

func hasBaseURLMarker(text string) bool {
	lower := strings.ToLower(text)
	return strings.Contains(lower, "anthropic_base_url") ||
		strings.Contains(lower, "openai_base_url") ||
		strings.Contains(lower, "base_url") ||
		strings.Contains(lower, "baseurl")
}

func hiddenUnicodeClasses(text string) []string {
	if utf8.ValidString(text) {
		classes := map[string]bool{}
		for _, r := range text {
			switch {
			case r == '\u200b' || r == '\u200c' || r == '\u200d' || r == '\ufeff':
				classes["zero-width"] = true
			case r >= '\u202a' && r <= '\u202e':
				classes["bidi-override"] = true
			case r >= '\u2066' && r <= '\u2069':
				classes["bidi-isolate"] = true
			case r >= '\U000e0000' && r <= '\U000e007f':
				classes["unicode-tags"] = true
			}
		}
		out := make([]string, 0, len(classes))
		for class := range classes {
			out = append(out, class)
		}
		sort.Strings(out)
		return out
	}
	return []string{"invalid-utf8"}
}

func hasDownloadExec(lower string) bool {
	normalized := normalizeCommandText(lower)
	hasDownloader := strings.Contains(normalized, "curl ") ||
		strings.Contains(normalized, "wget ")
	pipesToShell := strings.Contains(normalized, "|sh") ||
		strings.Contains(normalized, "|bash") ||
		strings.Contains(normalized, "|zsh") ||
		strings.Contains(normalized, "|/bin/sh") ||
		strings.Contains(normalized, "|/bin/bash") ||
		strings.Contains(normalized, "|/bin/zsh")
	if hasDownloader && pipesToShell {
		return true
	}
	if strings.Contains(normalized, "base64 -d|") && pipesToShell {
		return true
	}
	if strings.Contains(normalized, "base64 --decode|") && pipesToShell {
		return true
	}
	return hasInlineInterpreterNetworkExec(normalized)
}

func hasCredentialTouch(lower string) bool {
	needles := []string{
		".claude/.credentials",
		".codex/auth.json",
		".gemini/oauth_creds",
		".config/gh/hosts.yml",
		".aws/credentials",
		".npmrc",
		"anthropic_auth_token",
	}
	for _, needle := range needles {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func hasAIHeadless(lower string) bool {
	normalized := " " + normalizeCommandText(lower) + " "
	return strings.Contains(normalized, " claude -p ") ||
		strings.Contains(normalized, " claude --print ") ||
		strings.Contains(normalized, " gemini -p ") ||
		strings.Contains(normalized, " codex exec ") ||
		strings.Contains(normalized, " q chat ") ||
		strings.Contains(normalized, " amazon q ")
}

func normalizeCommandText(text string) string {
	text = strings.ToLower(text)
	text = strings.ReplaceAll(text, "\n", " ")
	text = strings.ReplaceAll(text, "\r", " ")
	text = pipePattern.ReplaceAllString(text, "|")
	text = spacePattern.ReplaceAllString(text, " ")
	return strings.TrimSpace(text)
}

func hasInlineInterpreterNetworkExec(normalized string) bool {
	hasInline := strings.Contains(normalized, "python -c ") ||
		strings.Contains(normalized, "python3 -c ") ||
		strings.Contains(normalized, "node -e ") ||
		strings.Contains(normalized, "nodejs -e ")
	if !hasInline {
		return false
	}
	hasNetwork := strings.Contains(normalized, "urlopen(") ||
		strings.Contains(normalized, "requests.get(") ||
		strings.Contains(normalized, "fetch(") ||
		strings.Contains(normalized, "http.get(") ||
		strings.Contains(normalized, "https.get(")
	hasExec := strings.Contains(normalized, "exec(") ||
		strings.Contains(normalized, "eval(") ||
		strings.Contains(normalized, "function(") ||
		strings.Contains(normalized, "child_process")
	return hasNetwork && hasExec
}

func isFirstPartyAIHost(host string) bool {
	return host == "api.anthropic.com" ||
		host == "anthropic.com" ||
		strings.HasSuffix(host, ".anthropic.com") ||
		host == "api.openai.com" ||
		host == "openai.com" ||
		strings.HasSuffix(host, ".openai.com")
}

func baseEvidence(artifact collect.Artifact, key, value string) []finding.KV {
	return []finding.KV{
		{Key: "path", Value: artifact.Path},
		{Key: "kind", Value: artifact.Kind},
		{Key: key, Value: value},
	}
}

func dedupe(findings []finding.Finding) []finding.Finding {
	seen := map[string]bool{}
	var out []finding.Finding
	for _, f := range findings {
		key := f.CheckID + "\x00" + f.Title
		for _, ev := range f.Evidence {
			key += "\x00" + ev.Key + "=" + ev.Value
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}
