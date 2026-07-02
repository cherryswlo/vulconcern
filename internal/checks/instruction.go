package checks

import (
	"strings"

	"github.com/cherryswlo/vulconcern/internal/collect"
	"github.com/cherryswlo/vulconcern/internal/finding"
)

func EvaluateInstructions(artifacts []collect.Artifact) []finding.Finding {
	var findings []finding.Finding
	for _, artifact := range artifacts {
		if artifact.Kind != "instruction" {
			continue
		}
		text := string(artifact.Raw)
		classes := hiddenUnicodeClasses(text)
		if len(classes) > 0 {
			findings = append(findings, finding.Finding{
				CheckID:     "VC-INSTR-001",
				Severity:    finding.High,
				Title:       "Instruction file contains hidden or control Unicode",
				Evidence:    baseEvidence(artifact, "unicode_class", strings.Join(classes, ",")),
				Citation:    "Hidden or control Unicode in instruction content",
				Remediation: "Remove hidden Unicode and review the file in an editor that can reveal control characters.",
			})
		}
		if longBase64Pattern.Match(artifact.Raw) {
			findings = append(findings, finding.Finding{
				CheckID:     "VC-INSTR-002",
				Severity:    finding.Medium,
				Title:       "Instruction file contains a long base64-like blob",
				Evidence:    baseEvidence(artifact, "pattern", "long-base64-like-run"),
				Citation:    "Hidden instruction or encoded-blob pattern",
				Remediation: "Decode and review the blob in an isolated environment, or remove it if it is not expected.",
			})
		}
	}
	return dedupe(findings)
}
