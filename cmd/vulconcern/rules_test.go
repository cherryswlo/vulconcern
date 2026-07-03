package main

import "testing"

func TestRuleCatalogIncludesAllCurrentFindingIDs(t *testing.T) {
	expected := []string{
		"VC-BASE-001",
		"VC-BASE-002",
		"VC-BASE-003",
		"VC-CMD-001",
		"VC-CMD-002",
		"VC-CMD-003",
		"VC-CMD-004",
		"VC-CMD-005",
		"VC-CMD-006",
		"VC-CMD-007",
		"VC-CMD-008",
		"VC-CONFIG-001",
		"VC-CRED-001",
		"VC-CRED-002",
		"VC-CRED-003",
		"VC-CRED-004",
		"VC-CRED-005",
		"VC-CRED-006",
		"VC-INSTR-001",
		"VC-INSTR-002",
		"VC-IR-001",
		"VC-IR-002",
		"VC-IR-003",
		"VC-IR-004",
		"VC-MCP-001",
		"VC-MCP-002",
		"VC-MCP-003",
		"VC-MCP-004",
		"VC-SCAN-001",
		"VC-SIPHON-001",
		"VC-SIPHON-002",
		"VC-SIPHON-003",
		"VC-SIPHON-004",
		"VC-SIPHON-005",
		"VC-SIPHON-006",
		"VC-SIPHON-007",
	}

	if len(ruleCatalog) != len(expected) {
		t.Fatalf("rule catalog count = %d, want %d", len(ruleCatalog), len(expected))
	}

	seen := make(map[string]bool, len(ruleCatalog))
	for _, rule := range ruleCatalog {
		if rule.ID == "" {
			t.Fatal("rule catalog contains an empty ID")
		}
		if rule.Summary == "" {
			t.Fatalf("rule catalog entry %s has an empty summary", rule.ID)
		}
		if seen[rule.ID] {
			t.Fatalf("rule catalog contains duplicate ID %s", rule.ID)
		}
		seen[rule.ID] = true
	}

	for _, id := range expected {
		if !seen[id] {
			t.Fatalf("rule catalog is missing %s", id)
		}
	}
}
