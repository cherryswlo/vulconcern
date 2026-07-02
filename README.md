# vulconcern

`vulconcern` is a local, read-only auditor for tampering and abuse in the trust chain
around AI coding tools on a developer machine.

It is not an EDR. v0.1 is a point-in-time auditor with a baseline diff. It does not
block, does not run resident, does not phone home, and cannot catch an attacker who
already has arbitrary code execution and chooses to hide.

## Current status

The current implementation covers:

- AI tool config files and MCP endpoint strings
- semantic JSON config checks for suspicious command targets and provider base URL overrides
- instruction files with hidden/control Unicode
- credential file modes and stray credential copies
- best-effort macOS Claude Code keychain presence tracking
- shell profile patterns that reference AI credentials, source suspicious scripts, or wrap AI CLIs
- TOFU baseline accept and drift reporting
- canonicalized JSON and simple TOML config hashing for baseline drift

## Install

Build locally with Go 1.22+:

```sh
go build ./cmd/vulconcern
```

## Primary-source anchors

The table below includes only anchors backed by primary sources. Claims from
planning notes that are not yet supported by primary sources are intentionally
omitted rather than repeated here.

| Rule families | Primary sources | Anchor |
|---|---|---|
| `VC-CMD-001`, `VC-CMD-002`, `VC-CMD-003`, `VC-CMD-004`, `VC-CMD-005`, `VC-CMD-007`, `VC-CMD-008`, `VC-CRED-001`, `VC-CRED-002`, `VC-CRED-003`, `VC-CRED-004`, `VC-CRED-005`, `VC-CRED-006` | [Nx GitHub advisory GHSA-cxm3-wv7p-598c](https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c), [StepSecurity incident analysis](https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware) | The official Nx advisory says the malicious packages scanned the file system, collected credentials, and posted them to GitHub repositories under victim accounts. StepSecurity’s incident analysis documents the same campaign using local AI CLIs (`claude`, `gemini`, `q`) with dangerous permission flags, writing inventory to `/tmp/inventory.txt`, and appending `sudo shutdown -h 0` to shell rc files. In `vulconcern`, these sources anchor the command-content, suspicious command-target, credential-surface, and shell-profile rule families. |
| `VC-MCP-001`, `VC-MCP-002`, `VC-MCP-003` | [NVD CVE-2025-6514](https://nvd.nist.gov/vuln/detail/CVE-2025-6514) | NVD describes `mcp-remote` as exposed to OS command injection when connecting to untrusted MCP servers via crafted authorization endpoint input. That directly anchors offline scrutiny of remote MCP URLs and trust boundaries. |
| `VC-CMD-003`, `VC-CONFIG-001`, broader config trust-chain warnings | [AWS Security Bulletin AWS-2025-015](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/), [NVD CVE-2025-8217](https://nvd.nist.gov/vuln/detail/CVE-2025-8217) | AWS states version `1.84.0` of the Amazon Q Developer VS Code extension included injected code that was designed to call the Q Developer CLI and shipped through the extension release path. In `vulconcern`, this is used as an anchor for the broader claim that AI tool config and extension trust paths can carry injected command behavior. |
| `VC-INSTR-001` | [Trojan Source paper](https://trojansource.codes/trojan-source.pdf), [CERT VU#999008](https://www.kb.cert.org/vuls/id/999008), [GitHub warning about bidirectional Unicode text](https://github.blog/changelog/2021-10-31-warning-about-bidirectional-unicode-text/) | These sources document hidden Unicode and bidi control-character attacks that can make code or instructions appear different to a reviewer than to the machine consuming them. That directly anchors detection of hidden/control Unicode in instruction files. |

Some shipped heuristics are intentionally not overstated here. In particular,
the long base64-like blob rules (`VC-CMD-006`, `VC-INSTR-002`) remain pattern-based
signals in `v0.1`, not incident-specific claims in this README.

## Usage

```sh
vulconcern scan [--project DIR] [--json] [--baseline PATH]
vulconcern baseline accept [--project DIR] [--baseline PATH]
vulconcern rules list
vulconcern version
```

Default baseline path:

```text
~/.config/vulconcern/baseline.json
```

First scan applies absolute rules only. Review the output before accepting a baseline;
accepting a baseline on an already-compromised machine can preserve the compromised
state as trusted.

## False positives and limits

`v0.1` is intentionally biased toward fewer, sharper `HIGH` and `CRITICAL` findings.
Drift by itself is weaker than drift plus risky command content, suspicious MCP targets,
or suspicious shell/profile changes.

Some rules are deliberately labeled as heuristics. In particular, the long base64-like
blob checks (`VC-CMD-006`, `VC-INSTR-002`) are pattern-based signals rather than
incident-specific proof.

This is still a point-in-time read-only scan with TOFU baselining. If a machine is
already compromised before the first baseline is accepted, the baseline can preserve
that state as trusted. A targeted attacker with arbitrary code execution can also evade
userland inspection. The intended value is catching the opportunistic, mass-campaign
tradecraft that recent incidents used without much concealment.

## Offline posture

`v0.1` performs no network I/O. Collection and evaluation stay local, and findings are
rendered from local artifacts only. The current module graph is stdlib-only.

## Development

The intended toolchain is Go 1.22+.

```sh
go test ./...
go build ./cmd/vulconcern
```

v0.1 should stay offline and minimal-dependency by default. Any dependency or network
touchpoint needs a clear security and maintenance reason.
