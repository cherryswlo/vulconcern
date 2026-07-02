package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cherryswlo/vulconcern/internal/baseline"
	"github.com/cherryswlo/vulconcern/internal/checks"
	"github.com/cherryswlo/vulconcern/internal/collect"
	"github.com/cherryswlo/vulconcern/internal/finding"
)

type Options struct {
	Project      string
	Home         string
	BaselinePath string
}

func Run(options Options) (finding.Report, error) {
	resolved, err := resolve(options)
	if err != nil {
		return finding.Report{}, err
	}

	artifacts, skipped := collect.CollectProjectAndHome(resolved.Home, resolved.Project)
	copyArtifacts, copySkipped := collect.ExistingArtifacts(collect.FindCredentialCopyCandidates(resolved.Home), true)
	artifacts = append(artifacts, copyArtifacts...)
	skipped = append(skipped, copySkipped...)
	keychainArtifacts, keychainSkipped := collect.ExistingKeychainArtifacts()
	artifacts = append(artifacts, keychainArtifacts...)
	skipped = append(skipped, keychainSkipped...)

	stored, baselinePresent, err := baseline.Load(resolved.BaselinePath)
	if err != nil {
		return finding.Report{}, err
	}

	var findings []finding.Finding
	if baselinePresent {
		findings = append(findings, baseline.EvaluateDrift(artifacts, stored)...)
	}
	findings = append(findings, skippedFindings(skipped)...)
	findings = append(findings, checks.EvaluateConfig(artifacts)...)
	findings = append(findings, checks.EvaluateInstructions(artifacts)...)
	findings = append(findings, checks.EvaluateCredentialSurface(artifacts)...)
	finding.SortFindings(findings)

	note := ""
	if !baselinePresent {
		note = "No baseline found. Absolute rules were applied, but accepting a baseline before review can enshrine an existing compromise."
	}

	return finding.Report{
		Version:         1,
		Project:         resolved.Project,
		BaselinePath:    resolved.BaselinePath,
		BaselinePresent: baselinePresent,
		Note:            note,
		Findings:        findings,
		Skipped:         skipped,
	}, nil
}

func AcceptBaseline(options Options) (string, int, error) {
	resolved, err := resolve(options)
	if err != nil {
		return "", 0, err
	}
	artifacts, skipped := collect.CollectProjectAndHome(resolved.Home, resolved.Project)
	if len(skipped) > 0 {
		return "", 0, fmt.Errorf("cannot accept baseline with unreadable in-scope artifacts")
	}
	keychainArtifacts, _ := collect.ExistingKeychainArtifacts()
	artifacts = append(artifacts, keychainArtifacts...)
	if err := baseline.Save(resolved.BaselinePath, artifacts); err != nil {
		return "", 0, err
	}
	return resolved.BaselinePath, countBaselineArtifacts(artifacts), nil
}

func resolve(options Options) (Options, error) {
	home := options.Home
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return Options{}, err
		}
	}
	project := options.Project
	if project == "" {
		var err error
		project, err = os.Getwd()
		if err != nil {
			return Options{}, err
		}
	}
	projectAbs, err := filepath.Abs(project)
	if err != nil {
		return Options{}, err
	}
	info, err := os.Stat(projectAbs)
	if err != nil {
		return Options{}, err
	}
	if !info.IsDir() {
		return Options{}, fmt.Errorf("project path is not a directory: %s", projectAbs)
	}
	baselinePath := options.BaselinePath
	if baselinePath == "" {
		baselinePath = baseline.DefaultPath(home)
	}
	return Options{Project: projectAbs, Home: home, BaselinePath: baselinePath}, nil
}

func skippedFindings(skipped []finding.Skipped) []finding.Finding {
	var findings []finding.Finding
	for _, item := range skipped {
		if strings.HasPrefix(item.Path, "keychain:") {
			continue
		}
		findings = append(findings, finding.Finding{
			CheckID:  "VC-SCAN-001",
			Severity: finding.High,
			Title:    "In-scope artifact could not be read",
			Evidence: []finding.KV{
				{Key: "path", Value: item.Path},
				{Key: "reason", Value: item.Reason},
			},
			Citation:    "Incomplete local audit",
			Remediation: "Review the file permissions and rerun the scan before accepting a baseline.",
		})
	}
	return findings
}

func countBaselineArtifacts(artifacts []collect.Artifact) int {
	count := 0
	for _, artifact := range artifacts {
		if artifact.Hash != "" && artifact.Kind != "credential-copy" {
			count++
		}
	}
	return count
}
