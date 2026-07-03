package collect

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestExistingArtifactsCanonicalizesJSONConfigHashes(t *testing.T) {
	root := t.TempDir()
	left := filepath.Join(root, "left.json")
	right := filepath.Join(root, "right.json")
	mustWriteArtifactFile(t, left, []byte("{\n  \"b\": 2,\n  \"a\": 1\n}\n"))
	mustWriteArtifactFile(t, right, []byte("{\"a\":1,\"b\":2}\n"))

	leftArtifacts, leftSkipped := ExistingArtifacts([]CandidatePath{{
		Path: left,
		Kind: "config",
	}}, true)
	rightArtifacts, rightSkipped := ExistingArtifacts([]CandidatePath{{
		Path: right,
		Kind: "config",
	}}, true)

	if len(leftSkipped) != 0 || len(rightSkipped) != 0 {
		t.Fatalf("unexpected skipped paths: %#v %#v", leftSkipped, rightSkipped)
	}
	if len(leftArtifacts) != 1 || len(rightArtifacts) != 1 {
		t.Fatalf("unexpected artifact counts: %d %d", len(leftArtifacts), len(rightArtifacts))
	}
	if leftArtifacts[0].Hash != rightArtifacts[0].Hash {
		t.Fatalf("config hashes differ after canonicalization: %s != %s", leftArtifacts[0].Hash, rightArtifacts[0].Hash)
	}
}

func TestExistingArtifactsCanonicalizesSimpleTOMLConfigHashes(t *testing.T) {
	root := t.TempDir()
	left := filepath.Join(root, "left.toml")
	right := filepath.Join(root, "right.toml")
	mustWriteArtifactFile(t, left, []byte("model = \"gpt-5\"\nprofile = \"safe\"\n\n[projects.\"/tmp/demo\"]\napproval_policy = \"never\"\nmodel = \"gpt-5-mini\"\n"))
	mustWriteArtifactFile(t, right, []byte("# comment only\nprofile = \"safe\"\nmodel = \"gpt-5\"\n\n[projects.\"/tmp/demo\"]\nmodel = \"gpt-5-mini\"\napproval_policy = \"never\"\n"))

	leftArtifacts, leftSkipped := ExistingArtifacts([]CandidatePath{{
		Path: left,
		Kind: "config",
	}}, true)
	rightArtifacts, rightSkipped := ExistingArtifacts([]CandidatePath{{
		Path: right,
		Kind: "config",
	}}, true)

	if len(leftSkipped) != 0 || len(rightSkipped) != 0 {
		t.Fatalf("unexpected skipped paths: %#v %#v", leftSkipped, rightSkipped)
	}
	if len(leftArtifacts) != 1 || len(rightArtifacts) != 1 {
		t.Fatalf("unexpected artifact counts: %d %d", len(leftArtifacts), len(rightArtifacts))
	}
	if leftArtifacts[0].Hash != rightArtifacts[0].Hash {
		t.Fatalf("toml hashes differ after canonicalization: %s != %s", leftArtifacts[0].Hash, rightArtifacts[0].Hash)
	}
}

func TestFindCredentialCopyCandidatesIncludesNestedRenamedCredentialLikeFiles(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	copyPath := filepath.Join(home, "Downloads", "nested", "auth-backup.json")
	mustWriteArtifactFile(t, copyPath, []byte("{}\n"))

	candidates := FindCredentialCopyCandidates(home)
	for _, candidate := range candidates {
		if candidate.Path == copyPath && candidate.Kind == "credential-copy" {
			return
		}
	}
	t.Fatalf("missing nested renamed credential candidate %s in %#v", copyPath, candidates)
}

func TestExistingArtifactsFlagsOversizedLightweightCode(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "extension.js")
	mustWriteArtifactFile(t, path, bytes.Repeat([]byte("a"), int(maxLightweightCodeReadBytes)+1))

	artifacts, skipped := ExistingArtifacts([]CandidatePath{{
		Path: path,
		Kind: "extension-code",
	}}, true)

	if len(skipped) != 1 {
		t.Fatalf("skipped count = %d, want 1: %#v", len(skipped), skipped)
	}
	if len(artifacts) != 1 {
		t.Fatalf("artifact count = %d, want 1", len(artifacts))
	}
	if artifacts[0].Hash == "" {
		t.Fatalf("oversized artifact hash is empty")
	}
	if len(artifacts[0].Raw) != 0 {
		t.Fatalf("oversized artifact content was read into memory")
	}
}

func mustWriteArtifactFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	mustMkdir(t, filepath.Dir(path))
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
