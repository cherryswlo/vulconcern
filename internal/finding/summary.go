package finding

import "strings"

type categoryDef struct {
	id     string
	title  string
	action string
	match  func(Finding) bool
}

var summaryCategories = []categoryDef{
	{
		id:     "possible_usage_siphon",
		title:  "Possible AI account usage siphon",
		action: "Remove unexpected AI CLI wrappers, editor extensions, or autostart jobs; reinstall official CLIs, revoke active sessions, and rotate AI-provider credentials.",
		match: func(f Finding) bool {
			return strings.HasPrefix(f.CheckID, "VC-SIPHON-") || f.CheckID == "VC-CONFIG-001"
		},
	},
	{
		id:     "credential_exposure",
		title:  "Credential exposure or unsafe credential surface",
		action: "Rotate affected credentials after removing suspicious local files, wrappers, or exports.",
		match: func(f Finding) bool {
			return strings.HasPrefix(f.CheckID, "VC-CRED-") || f.CheckID == "VC-CMD-002"
		},
	},
	{
		id:     "config_relay",
		title:  "Provider or MCP traffic may be relayed through an unexpected endpoint",
		action: "Remove unexpected base URL overrides or remote MCP endpoints before trusting future AI sessions.",
		match: func(f Finding) bool {
			return f.CheckID == "VC-CONFIG-001" || strings.HasPrefix(f.CheckID, "VC-MCP-")
		},
	},
	{
		id:     "incident_residue",
		title:  "Known incident residue or AI CLI abuse trace",
		action: "Review surrounding local history and provider/account logs; rotate credentials if the activity was not intentional.",
		match: func(f Finding) bool {
			return strings.HasPrefix(f.CheckID, "VC-IR-") || f.CheckID == "VC-CRED-004"
		},
	},
	{
		id:     "command_execution",
		title:  "Suspicious command execution path",
		action: "Remove download-execute commands, suspicious command targets, and broad AI tool permissions.",
		match: func(f Finding) bool {
			return strings.HasPrefix(f.CheckID, "VC-CMD-")
		},
	},
	{
		id:     "trust_chain_drift",
		title:  "Audited trust-chain artifact changed since baseline",
		action: "Review changed or new artifacts before accepting a new baseline.",
		match: func(f Finding) bool {
			return strings.HasPrefix(f.CheckID, "VC-BASE-")
		},
	},
	{
		id:     "instruction_tampering",
		title:  "Instruction file tampering signal",
		action: "Review AI instruction files in an editor that reveals hidden characters and remove unexpected encoded blobs.",
		match: func(f Finding) bool {
			return strings.HasPrefix(f.CheckID, "VC-INSTR-")
		},
	},
	{
		id:     "incomplete_scan",
		title:  "Scan could not read an in-scope artifact",
		action: "Fix file permissions and rerun before relying on the result.",
		match: func(f Finding) bool {
			return f.CheckID == "VC-SCAN-001"
		},
	},
}

func BuildSummary(findings []Finding) Summary {
	if len(findings) == 0 {
		return Summary{
			Verdict: "no_findings",
			Actions: []string{
				"No suspicious local behavior detected by the current checks.",
			},
		}
	}

	var categories []SummaryCategory
	var actions []string
	for _, def := range summaryCategories {
		category := SummaryCategory{
			ID:     def.id,
			Title:  def.title,
			Action: def.action,
		}
		for _, item := range findings {
			if item.Suppressed || !def.match(item) {
				continue
			}
			category.FindingCount++
			if Rank(item.Severity) > Rank(category.Severity) {
				category.Severity = item.Severity
			}
		}
		if category.FindingCount == 0 {
			continue
		}
		categories = append(categories, category)
		actions = appendUnique(actions, def.action)
	}

	return Summary{
		Verdict:    verdictFor(categories, findings),
		Categories: categories,
		Actions:    actions,
	}
}

func verdictFor(categories []SummaryCategory, findings []Finding) string {
	for _, category := range categories {
		if category.ID == "possible_usage_siphon" && Rank(category.Severity) >= Rank(High) {
			return "suspicious_behavior"
		}
	}
	if HasAtLeast(findings, Critical) {
		return "critical_findings"
	}
	if HasAtLeast(findings, High) {
		return "review_required"
	}
	return "findings_present"
}

func appendUnique(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
