package finding

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteJSONEmitsVersionedReport(t *testing.T) {
	report := Report{
		Version: 1,
		Project: "/tmp/project",
		Findings: []Finding{{
			CheckID:  "VC-TEST",
			Severity: High,
			Title:    "test finding",
		}},
	}
	var out bytes.Buffer
	if err := WriteJSON(&out, report); err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Version != 1 || len(decoded.Findings) != 1 {
		t.Fatalf("unexpected report: %#v", decoded)
	}
}

func TestWriteJSONEmitsEmptyFindingsArray(t *testing.T) {
	report := Report{
		Version: 1,
		Project: "/tmp/project",
	}
	var out bytes.Buffer
	if err := WriteJSON(&out, report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), `"findings": null`) {
		t.Fatalf("findings encoded as null:\n%s", out.String())
	}
	if !strings.Contains(out.String(), `"findings": []`) {
		t.Fatalf("findings not encoded as empty array:\n%s", out.String())
	}
}

func TestWriteTextGroupsFindingsBySeverity(t *testing.T) {
	report := Report{
		Version: 1,
		Project: "/tmp/project",
		Findings: []Finding{
			{CheckID: "VC-LOW", Severity: Info, Title: "info"},
			{CheckID: "VC-HIGH", Severity: High, Title: "high"},
		},
	}
	var out bytes.Buffer
	if err := WriteText(&out, report); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "HIGH\n- [VC-HIGH] high") {
		t.Fatalf("missing high group in:\n%s", text)
	}
	if !strings.Contains(text, "INFO\n- [VC-LOW] info") {
		t.Fatalf("missing info group in:\n%s", text)
	}
}

func TestRendererRedactsTokenShapedEvidence(t *testing.T) {
	report := Report{
		Version: 1,
		Project: "/tmp/project",
		Findings: []Finding{{
			CheckID:  "VC-SECRET",
			Severity: High,
			Title:    "secret",
			Evidence: []KV{{Key: "value", Value: "sk-fixture-secret-value"}},
		}},
	}
	var out bytes.Buffer
	if err := WriteText(&out, report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "sk-fixture-secret-value") {
		t.Fatalf("secret was not redacted:\n%s", out.String())
	}
}
