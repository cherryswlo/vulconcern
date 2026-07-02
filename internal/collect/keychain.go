package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os/exec"
	"runtime"
	"strings"

	"github.com/cherryswlo/vulconcern/internal/finding"
)

func ExistingKeychainArtifacts() ([]Artifact, []finding.Skipped) {
	if runtime.GOOS != "darwin" {
		return nil, nil
	}

	cmd := exec.Command("security", "find-generic-password", "-s", "Claude Code-credentials")
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if isMissingKeychainItemOutput(out) {
				return nil, nil
			}
		}
		return nil, []finding.Skipped{{
			Path:   "keychain:Claude Code-credentials",
			Reason: strings.TrimSpace(string(out)),
		}}
	}

	sum := sha256.Sum256(out)
	return []Artifact{{
		Path:  "keychain:Claude Code-credentials",
		Tool:  "claude",
		Scope: "user",
		Kind:  "credential-store",
		Hash:  hex.EncodeToString(sum[:]),
		Size:  int64(len(out)),
	}}, nil
}

func isMissingKeychainItemOutput(out []byte) bool {
	lower := strings.ToLower(string(out))
	return strings.Contains(lower, "could not be found") || strings.Contains(lower, "item could not be found")
}
