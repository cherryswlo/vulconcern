package checks

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/cherryswlo/vulconcern/internal/collect"
	"github.com/cherryswlo/vulconcern/internal/finding"
)

var rawConfigStringValuePattern = regexp.MustCompile(`(?i)"(command|apiKeyHelper)"\s*:\s*"([^"]+)"`)

func EvaluateConfig(artifacts []collect.Artifact) []finding.Finding {
	var findings []finding.Finding
	for _, artifact := range artifacts {
		if artifact.Kind != "config" {
			continue
		}
		text := string(artifact.Raw)
		findings = append(findings, textCommandRisks(artifact, text)...)
		semanticFindings, parsed := semanticConfigRisks(artifact)
		if parsed {
			findings = append(findings, semanticFindings...)
		} else if strings.EqualFold(filepath.Ext(artifact.Path), ".toml") {
			findings = append(findings, semanticTOMLRisks(artifact)...)
		}
		findings = append(findings, rawConfigKeyRisks(artifact)...)
		findings = append(findings, remoteURLRisks(artifact, text)...)
		findings = append(findings, baseURLOverrideRisks(artifact, text)...)
	}
	return dedupe(findings)
}

func semanticConfigRisks(artifact collect.Artifact) ([]finding.Finding, bool) {
	var root any
	if err := json.Unmarshal(artifact.Raw, &root); err != nil {
		return nil, false
	}
	return dedupe(walkConfigValue(artifact, filepath.Dir(artifact.Path), "", root)), true
}

func walkConfigValue(artifact collect.Artifact, baseDir, key string, value any) []finding.Finding {
	switch typed := value.(type) {
	case map[string]any:
		findings := semanticObjectRisks(artifact, baseDir, typed)
		for childKey, child := range typed {
			findings = append(findings, walkConfigValue(artifact, baseDir, childKey, child)...)
		}
		return findings
	case []any:
		var findings []finding.Finding
		for _, child := range typed {
			findings = append(findings, walkConfigValue(artifact, baseDir, key, child)...)
		}
		return findings
	case string:
		findings := urlRiskFindings(artifact, typed, nil)
		if isBaseURLKey(key) || strings.Contains(strings.ToLower(typed), "base_url") {
			findings = append(findings, baseURLOverrideRisks(artifact, key+"="+typed)...)
		}
		return findings
	default:
		return nil
	}
}

func semanticObjectRisks(artifact collect.Artifact, baseDir string, object map[string]any) []finding.Finding {
	var findings []finding.Finding

	command := stringValue(object["command"])
	args := stringArrayValue(object["args"])
	if command != "" {
		findings = append(findings, textCommandRisks(artifact, command+" "+strings.Join(args, " "))...)
		findings = append(findings, commandTargetRisks(artifact, baseDir, command, args)...)
		findings = append(findings, wrappedRemoteURLRisks(artifact, command, args)...)
	}
	if helper := stringValue(object["apiKeyHelper"]); helper != "" {
		findings = append(findings, commandTargetRisks(artifact, baseDir, helper, nil)...)
	}
	if env, ok := object["env"].(map[string]any); ok {
		for key, raw := range env {
			if !isBaseURLKey(key) {
				continue
			}
			if value := stringValue(raw); value != "" {
				findings = append(findings, baseURLOverrideRisks(artifact, key+"="+value)...)
			}
		}
	}

	return findings
}

func semanticTOMLRisks(artifact collect.Artifact) []finding.Finding {
	baseDir := filepath.Dir(artifact.Path)
	current := map[string]any{}
	var findings []finding.Finding
	flush := func() {
		if len(current) == 0 {
			return
		}
		findings = append(findings, semanticObjectRisks(artifact, baseDir, current)...)
		for key, raw := range current {
			findings = append(findings, walkConfigValue(artifact, baseDir, key, raw)...)
		}
		current = map[string]any{}
	}

	for _, line := range strings.Split(string(artifact.Raw), "\n") {
		trimmed := strings.TrimSpace(stripLineComment(line))
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			flush()
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if parsed, ok := parseQuotedValue(value); ok {
			current[key] = parsed
			continue
		}
		if parsed, ok := parseStringArrayValue(value); ok {
			current[key] = parsed
		}
	}
	flush()
	return dedupe(findings)
}

func rawConfigKeyRisks(artifact collect.Artifact) []finding.Finding {
	var findings []finding.Finding
	baseDir := filepath.Dir(artifact.Path)
	for _, match := range rawConfigStringValuePattern.FindAllStringSubmatch(string(artifact.Raw), -1) {
		if len(match) != 3 {
			continue
		}
		findings = append(findings, commandTargetRisks(artifact, baseDir, match[2], nil)...)
	}
	return dedupe(findings)
}

func wrappedRemoteURLRisks(artifact collect.Artifact, command string, args []string) []finding.Finding {
	wrapper := remoteWrapperName(command, args)
	if wrapper == "" {
		return nil
	}
	var findings []finding.Finding
	for _, arg := range args {
		findings = append(findings, urlRiskFindings(artifact, arg, []finding.KV{{Key: "wrapper", Value: wrapper}})...)
	}
	return findings
}

func remoteWrapperName(command string, args []string) string {
	candidates := append([]string{command}, args...)
	for _, candidate := range candidates {
		base := strings.ToLower(filepath.Base(strings.TrimSpace(strings.Trim(candidate, `"'`))))
		switch base {
		case "mcp-remote", "supergateway":
			return base
		}
	}
	return ""
}

func commandTargetRisks(artifact collect.Artifact, baseDir, command string, args []string) []finding.Finding {
	target, relativeToConfig := resolveCommandTarget(baseDir, command, args)
	if target == "" {
		return nil
	}

	var findings []finding.Finding
	if pathClass := suspiciousPathClass(target, relativeToConfig); pathClass != "" {
		evidence := []finding.KV{
			{Key: "path", Value: artifact.Path},
			{Key: "kind", Value: artifact.Kind},
			{Key: "command_target", Value: target},
			{Key: "path_class", Value: pathClass},
		}
		if info, err := os.Stat(target); err == nil {
			if owner := fileOwner(info); owner != "" {
				evidence = append(evidence, finding.KV{Key: "owner_uid", Value: owner})
			}
		}
		findings = append(findings, finding.Finding{
			CheckID:     "VC-CMD-007",
			Severity:    finding.High,
			Title:       "Configuration command resolves to a suspicious path",
			Evidence:    evidence,
			Citation:    "Command target path outside normal trusted locations",
			Remediation: "Replace the command with a reviewed binary or script from a trusted path.",
		})
	}

	info, err := os.Stat(target)
	if err == nil && info.Mode().Perm()&0002 != 0 {
		evidence := []finding.KV{
			{Key: "path", Value: artifact.Path},
			{Key: "kind", Value: artifact.Kind},
			{Key: "command_target", Value: target},
			{Key: "mode", Value: info.Mode().Perm().String()},
		}
		if owner := fileOwner(info); owner != "" {
			evidence = append(evidence, finding.KV{Key: "owner_uid", Value: owner})
		}
		findings = append(findings, finding.Finding{
			CheckID:     "VC-CMD-008",
			Severity:    finding.High,
			Title:       "Configuration command target is world-writable",
			Evidence:    evidence,
			Citation:    "World-writable command target in the AI tool trust chain",
			Remediation: "Move the command target to a trusted location and restrict its file mode.",
		})
	}

	return findings
}

func resolveCommandTarget(baseDir, command string, args []string) (string, bool) {
	if explicit, relative := resolveExplicitPath(baseDir, command); explicit != "" {
		return explicit, relative
	}
	if isScriptLauncher(command) && len(args) > 0 {
		for _, arg := range args {
			if script, relative := resolveExplicitPath(baseDir, arg); script != "" {
				return script, relative
			}
		}
		if len(args) > 1 && (args[0] == "-c" || args[0] == "-e") {
			fields := strings.Fields(args[1])
			if len(fields) > 0 {
				if script, relative := resolveExplicitPath(baseDir, fields[0]); script != "" {
					return script, relative
				}
			}
		}
	}
	resolved, err := exec.LookPath(command)
	if err != nil {
		return "", false
	}
	return resolved, false
}

func resolveExplicitPath(baseDir, raw string) (string, bool) {
	raw = strings.TrimSpace(strings.Trim(raw, `"'`))
	if raw == "" {
		return "", false
	}
	if strings.HasPrefix(raw, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", false
		}
		return filepath.Join(home, strings.TrimPrefix(raw, "~/")), false
	}
	if filepath.IsAbs(raw) {
		return raw, false
	}
	if strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../") {
		return filepath.Clean(filepath.Join(baseDir, raw)), true
	}
	if strings.Contains(raw, "/") {
		return filepath.Clean(filepath.Join(baseDir, raw)), true
	}
	return "", false
}

func isScriptLauncher(command string) bool {
	command = strings.ToLower(filepath.Base(strings.TrimSpace(strings.Trim(command, `"'`))))
	switch command {
	case "node", "nodejs", "python", "python3", "bash", "sh", "zsh":
		return true
	default:
		return false
	}
}

func suspiciousPathClass(path string, relativeToConfig bool) string {
	lower := strings.ToLower(filepath.Clean(path))
	switch {
	case !relativeToConfig && (strings.HasPrefix(lower, "/tmp/") || strings.HasPrefix(lower, "/private/tmp/") || strings.Contains(lower, "/var/folders/")):
		return "temporary"
	case !relativeToConfig && strings.Contains(lower, "/downloads/"):
		return "downloads"
	case !relativeToConfig && strings.Contains(lower, "/node_modules/"):
		return "node-modules"
	case !relativeToConfig && (strings.Contains(lower, "/.cache/") || strings.Contains(lower, "/.tmp/")):
		return "hidden"
	default:
		return ""
	}
}

func isBaseURLKey(key string) bool {
	lower := strings.ToLower(key)
	return lower == "openai_base_url" || lower == "anthropic_base_url"
}

func stripLineComment(line string) string {
	inSingle := false
	inDouble := false
	escaped := false
	for i, r := range line {
		switch r {
		case '\\':
			if inDouble && !escaped {
				escaped = true
				continue
			}
		case '"':
			if !inSingle && !escaped {
				inDouble = !inDouble
			}
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '#':
			if !inSingle && !inDouble {
				return line[:i]
			}
		}
		escaped = false
	}
	return line
}

func parseQuotedValue(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if len(value) < 2 {
		return "", false
	}
	quote := value[0]
	if (quote != '"' && quote != '\'') || value[len(value)-1] != quote {
		return "", false
	}
	return strings.Trim(value[1:len(value)-1], " \t"), true
}

func parseStringArrayValue(value string) ([]any, bool) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
		return nil, false
	}
	body := strings.TrimSpace(value[1 : len(value)-1])
	if body == "" {
		return []any{}, true
	}
	parts := strings.Split(body, ",")
	out := make([]any, 0, len(parts))
	for _, part := range parts {
		parsed, ok := parseQuotedValue(strings.TrimSpace(part))
		if !ok {
			return nil, false
		}
		out = append(out, parsed)
	}
	return out, true
}

func fileOwner(info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return strconv.FormatUint(uint64(stat.Uid), 10)
}

func stringValue(raw any) string {
	value, _ := raw.(string)
	return value
}

func stringArrayValue(raw any) []string {
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		value, ok := item.(string)
		if ok {
			out = append(out, value)
		}
	}
	return out
}
