package baseline

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/cherryswlo/vulconcern/internal/collect"
	"github.com/cherryswlo/vulconcern/internal/finding"
)

type Baseline struct {
	Version    int              `json:"v"`
	AcceptedAt time.Time        `json:"accepted_at"`
	Artifacts  []ArtifactRecord `json:"artifacts"`
}

type ArtifactRecord struct {
	Path  string `json:"path"`
	Tool  string `json:"tool"`
	Scope string `json:"scope"`
	Kind  string `json:"kind"`
	Hash  string `json:"sha256"`
}

func DefaultPath(home string) string {
	return filepath.Join(home, ".config", "vulconcern", "baseline.json")
}

func Load(path string) (Baseline, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Baseline{}, false, nil
		}
		return Baseline{}, false, err
	}
	var baseline Baseline
	if err := json.Unmarshal(raw, &baseline); err != nil {
		return Baseline{}, false, err
	}
	return baseline, true, nil
}

func Save(path string, artifacts []collect.Artifact) error {
	baseline := Baseline{
		Version:    1,
		AcceptedAt: time.Now().UTC(),
		Artifacts:  recordsFromArtifacts(artifacts),
	}
	raw, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

func EvaluateDrift(artifacts []collect.Artifact, baseline Baseline) []finding.Finding {
	expected := map[string]ArtifactRecord{}
	for _, record := range baseline.Artifacts {
		expected[record.Path] = record
	}
	current := map[string]collect.Artifact{}
	for _, artifact := range artifacts {
		if baselineEligible(artifact) {
			current[artifact.Path] = artifact
		}
	}

	var findings []finding.Finding
	for path, artifact := range current {
		record, ok := expected[path]
		if !ok {
			findings = append(findings, driftFinding("VC-BASE-001", finding.Info, "New audited artifact detected", artifact, "added"))
			continue
		}
		if record.Hash != artifact.Hash {
			severity := finding.Info
			if artifact.Kind == "config" || artifact.Kind == "instruction" || artifact.Kind == "shellrc" {
				severity = finding.Medium
			}
			findings = append(findings, driftFinding("VC-BASE-002", severity, "Audited artifact changed since baseline", artifact, "changed"))
		}
	}
	for path, record := range expected {
		if _, ok := current[path]; ok {
			continue
		}
		findings = append(findings, finding.Finding{
			CheckID:  "VC-BASE-003",
			Severity: finding.Info,
			Title:    "Baseline artifact is no longer present",
			Evidence: []finding.KV{
				{Key: "path", Value: path},
				{Key: "kind", Value: record.Kind},
				{Key: "drift", Value: "removed"},
			},
			Citation:    "TOFU baseline drift",
			Remediation: "Run `vulconcern baseline accept` after reviewing the removal.",
		})
	}
	return findings
}

func recordsFromArtifacts(artifacts []collect.Artifact) []ArtifactRecord {
	var records []ArtifactRecord
	for _, artifact := range artifacts {
		if !baselineEligible(artifact) {
			continue
		}
		records = append(records, ArtifactRecord{
			Path:  artifact.Path,
			Tool:  artifact.Tool,
			Scope: artifact.Scope,
			Kind:  artifact.Kind,
			Hash:  artifact.Hash,
		})
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Path < records[j].Path
	})
	return records
}

func baselineEligible(artifact collect.Artifact) bool {
	return artifact.Hash != "" && artifact.Kind != "credential-copy"
}

func driftFinding(id string, severity finding.Severity, title string, artifact collect.Artifact, status string) finding.Finding {
	return finding.Finding{
		CheckID:  id,
		Severity: severity,
		Title:    title,
		Evidence: []finding.KV{
			{Key: "path", Value: artifact.Path},
			{Key: "kind", Value: artifact.Kind},
			{Key: "drift", Value: status},
		},
		Citation:    "TOFU baseline drift",
		Remediation: "Review the artifact and run `vulconcern baseline accept` only if the state is expected.",
	}
}
