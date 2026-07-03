package main

type ruleDef struct {
	ID      string
	Summary string
}

var ruleCatalog = []ruleDef{
	{ID: "VC-BASE-001", Summary: "new audited artifact detected"},
	{ID: "VC-BASE-002", Summary: "audited artifact changed since baseline"},
	{ID: "VC-BASE-003", Summary: "baseline artifact no longer present"},
	{ID: "VC-CMD-001", Summary: "download-and-execute command content"},
	{ID: "VC-CMD-002", Summary: "credential path references"},
	{ID: "VC-CMD-003", Summary: "headless AI CLI invocation"},
	{ID: "VC-CMD-004", Summary: "broad command execution permissions"},
	{ID: "VC-CMD-005", Summary: "auto-approval style permissions"},
	{ID: "VC-CMD-006", Summary: "long base64-like blob in command-bearing content"},
	{ID: "VC-CMD-007", Summary: "configuration command resolves to a suspicious path"},
	{ID: "VC-CMD-008", Summary: "configuration command target is world-writable"},
	{ID: "VC-CONFIG-001", Summary: "non-first-party AI base URL"},
	{ID: "VC-CRED-001", Summary: "weak credential file mode"},
	{ID: "VC-CRED-002", Summary: "credential copy outside expected location"},
	{ID: "VC-CRED-003", Summary: "shell profile exports AI provider credential or endpoint variables"},
	{ID: "VC-CRED-004", Summary: "destructive shutdown command in shell profile"},
	{ID: "VC-CRED-005", Summary: "shell profile aliases an AI CLI command to a suspicious target"},
	{ID: "VC-CRED-006", Summary: "shell profile sources a script from a suspicious path"},
	{ID: "VC-INSTR-001", Summary: "hidden Unicode in instruction files"},
	{ID: "VC-INSTR-002", Summary: "long base64-like blob in instruction files"},
	{ID: "VC-IR-001", Summary: "known local credential inventory artifact"},
	{ID: "VC-IR-002", Summary: "shell history AI CLI credential reconnaissance pattern"},
	{ID: "VC-IR-003", Summary: "shell history AI CLI permission-bypass usage"},
	{ID: "VC-IR-004", Summary: "shell history known supply-chain compromise indicator"},
	{ID: "VC-MCP-001", Summary: "plaintext remote MCP/config URL"},
	{ID: "VC-MCP-002", Summary: "IP-literal remote MCP/config URL"},
	{ID: "VC-MCP-003", Summary: "punycode remote MCP/config URL host"},
	{ID: "VC-MCP-004", Summary: "unrecognized remote MCP/config URL host"},
	{ID: "VC-SCAN-001", Summary: "in-scope artifact could not be read"},
	{ID: "VC-SIPHON-001", Summary: "AI CLI wrapper touches auth or token material"},
	{ID: "VC-SIPHON-002", Summary: "AI CLI wrapper combines token access with network relay behavior"},
	{ID: "VC-SIPHON-003", Summary: "autostart job references AI auth material"},
	{ID: "VC-SIPHON-004", Summary: "autostart job runs suspicious AI-tool-adjacent command"},
	{ID: "VC-SIPHON-005", Summary: "shell profile defines AI CLI wrapper touching auth material"},
	{ID: "VC-SIPHON-006", Summary: "editor extension code combines AI auth access with network relay behavior"},
	{ID: "VC-SIPHON-007", Summary: "AI-adjacent editor extension has install lifecycle scripts"},
}
