package finding

import "testing"

func TestBuildSummaryFlagsUsageSiphonAsSuspiciousBehavior(t *testing.T) {
	summary := BuildSummary([]Finding{
		{CheckID: "VC-SIPHON-002", Severity: Critical, Title: "relay"},
		{CheckID: "VC-CRED-001", Severity: Medium, Title: "credential mode"},
	})

	if summary.Verdict != "suspicious_behavior" {
		t.Fatalf("verdict = %q, want suspicious_behavior", summary.Verdict)
	}
	assertSummaryCategory(t, summary, "possible_usage_siphon", Critical, 1)
	assertSummaryCategory(t, summary, "credential_exposure", Medium, 1)
}

func TestBuildSummaryNoFindings(t *testing.T) {
	summary := BuildSummary(nil)
	if summary.Verdict != "no_findings" {
		t.Fatalf("verdict = %q, want no_findings", summary.Verdict)
	}
	if len(summary.Actions) == 0 {
		t.Fatal("expected no-findings action text")
	}
}

func assertSummaryCategory(t *testing.T, summary Summary, id string, severity Severity, count int) {
	t.Helper()
	for _, category := range summary.Categories {
		if category.ID != id {
			continue
		}
		if category.Severity != severity || category.FindingCount != count {
			t.Fatalf("category %s = %#v, want severity %s count %d", id, category, severity, count)
		}
		return
	}
	t.Fatalf("missing category %s in %#v", id, summary.Categories)
}
