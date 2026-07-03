package finding

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{8,}`),
	regexp.MustCompile(`ghp_[A-Za-z0-9_]{8,}`),
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{8,}`),
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{8,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{12,}`),
}

func WriteJSON(w io.Writer, report Report) error {
	report = RedactReport(report)
	if report.Findings == nil {
		report.Findings = []Finding{}
	}
	SortFindings(report.Findings)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func WriteText(w io.Writer, report Report) error {
	report = RedactReport(report)
	SortFindings(report.Findings)

	fmt.Fprintf(w, "vulconcern scan\n")
	fmt.Fprintf(w, "Project: %s\n", report.Project)
	fmt.Fprintf(w, "Baseline: %s\n", report.BaselinePath)
	if report.Note != "" {
		fmt.Fprintf(w, "\n%s\n", report.Note)
	}

	writeSummary(w, report)

	if len(report.Findings) == 0 {
		fmt.Fprintf(w, "\nNo findings.\n")
		writeSkipped(w, report)
		return nil
	}

	order := []Severity{Critical, High, Medium, Info}
	for _, sev := range order {
		wroteHeader := false
		for _, f := range report.Findings {
			if f.Severity != sev {
				continue
			}
			if !wroteHeader {
				fmt.Fprintf(w, "\n%s\n", sev)
				wroteHeader = true
			}
			fmt.Fprintf(w, "- [%s] %s\n", f.CheckID, f.Title)
			for _, ev := range f.Evidence {
				fmt.Fprintf(w, "  %s: %s\n", ev.Key, ev.Value)
			}
			if f.Citation != "" {
				fmt.Fprintf(w, "  maps_to: %s\n", f.Citation)
			}
			if f.Remediation != "" {
				fmt.Fprintf(w, "  fix: %s\n", f.Remediation)
			}
		}
	}

	writeSkipped(w, report)
	return nil
}

func writeSummary(w io.Writer, report Report) {
	if report.Summary.Verdict == "" {
		return
	}
	fmt.Fprintf(w, "\nSummary: %s\n", report.Summary.Verdict)
	for _, category := range report.Summary.Categories {
		fmt.Fprintf(w, "- [%s] %s (%d findings)\n", category.Severity, category.Title, category.FindingCount)
		if category.Action != "" {
			fmt.Fprintf(w, "  next: %s\n", category.Action)
		}
	}
	if len(report.Summary.Categories) == 0 {
		for _, action := range report.Summary.Actions {
			fmt.Fprintf(w, "- %s\n", action)
		}
	}
}

func RedactReport(report Report) Report {
	for i := range report.Findings {
		for j := range report.Findings[i].Evidence {
			report.Findings[i].Evidence[j].Value = RedactValue(report.Findings[i].Evidence[j].Value)
		}
	}
	return report
}

func RedactValue(value string) string {
	for _, pattern := range secretPatterns {
		value = pattern.ReplaceAllString(value, "[REDACTED]")
	}
	return value
}

func writeSkipped(w io.Writer, report Report) {
	if len(report.Skipped) == 0 {
		return
	}
	fmt.Fprintf(w, "\nSkipped\n")
	for _, s := range report.Skipped {
		fmt.Fprintf(w, "- %s: %s\n", s.Path, s.Reason)
	}
}
