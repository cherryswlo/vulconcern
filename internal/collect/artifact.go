package collect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cherryswlo/vulconcern/internal/finding"
)

type Artifact struct {
	Path       string
	Tool       string
	Scope      string
	Kind       string
	Hash       string
	Mode       fs.FileMode
	ModTime    time.Time
	Size       int64
	Raw        []byte
	SkipReason string
}

func ExistingArtifacts(candidates []CandidatePath, readContent bool) ([]Artifact, []finding.Skipped) {
	var artifacts []Artifact
	var skipped []finding.Skipped
	seen := map[string]bool{}
	for _, c := range candidates {
		if c.Path == "" || seen[c.Path] {
			continue
		}
		seen[c.Path] = true
		info, err := os.Stat(c.Path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				skipped = append(skipped, finding.Skipped{Path: c.Path, Reason: err.Error()})
			}
			continue
		}
		if info.IsDir() {
			continue
		}
		artifact := Artifact{
			Path:    c.Path,
			Tool:    c.Tool,
			Scope:   c.Scope,
			Kind:    c.Kind,
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
			Size:    info.Size(),
		}
		if readContent {
			raw, err := os.ReadFile(c.Path)
			if err != nil {
				skipped = append(skipped, finding.Skipped{Path: c.Path, Reason: err.Error()})
				continue
			}
			sum := sha256.Sum256(normalizedArtifactBytes(c, raw))
			artifact.Raw = raw
			artifact.Hash = hex.EncodeToString(sum[:])
		}
		artifacts = append(artifacts, artifact)
	}
	return artifacts, skipped
}

func normalizedArtifactBytes(candidate CandidatePath, raw []byte) []byte {
	if candidate.Kind != "config" {
		return raw
	}
	if json.Valid(raw) {
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return raw
		}
		normalized, err := json.Marshal(decoded)
		if err != nil {
			return raw
		}
		return normalized
	}
	if strings.EqualFold(filepath.Ext(candidate.Path), ".toml") {
		if normalized, ok := normalizeSimpleTOML(raw); ok {
			return normalized
		}
	}
	return raw
}

func normalizeSimpleTOML(raw []byte) ([]byte, bool) {
	type sectionEntry struct {
		key   string
		value string
	}

	sections := map[string][]sectionEntry{}
	current := ""
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(stripTOMLComment(line))
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, `"""`) || strings.Contains(trimmed, `'''`) || strings.HasPrefix(trimmed, "[[") {
			return nil, false
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			current = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			if current == "" || strings.Contains(current, "[") || strings.Contains(current, "]") {
				return nil, false
			}
			if _, ok := sections[current]; !ok {
				sections[current] = nil
			}
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			return nil, false
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			return nil, false
		}
		if strings.HasPrefix(value, "[") && !strings.HasSuffix(value, "]") {
			return nil, false
		}
		sections[current] = append(sections[current], sectionEntry{
			key:   key,
			value: value,
		})
	}

	if len(sections) == 0 {
		return nil, false
	}

	names := make([]string, 0, len(sections))
	for name := range sections {
		names = append(names, name)
	}
	sort.Strings(names)

	var out bytes.Buffer
	if rootEntries, ok := sections[""]; ok {
		sort.Slice(rootEntries, func(i, j int) bool {
			return rootEntries[i].key < rootEntries[j].key
		})
		for _, entry := range rootEntries {
			out.WriteString(entry.key)
			out.WriteString(" = ")
			out.WriteString(entry.value)
			out.WriteByte('\n')
		}
		delete(sections, "")
		filtered := names[:0]
		for _, name := range names {
			if name != "" {
				filtered = append(filtered, name)
			}
		}
		names = filtered
	}

	for _, name := range names {
		entries := sections[name]
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].key < entries[j].key
		})
		if out.Len() > 0 {
			out.WriteByte('\n')
		}
		out.WriteByte('[')
		out.WriteString(name)
		out.WriteString("]\n")
		for _, entry := range entries {
			out.WriteString(entry.key)
			out.WriteString(" = ")
			out.WriteString(entry.value)
			out.WriteByte('\n')
		}
	}
	return out.Bytes(), true
}

func stripTOMLComment(line string) string {
	inSingle := false
	inDouble := false
	escaped := false
	for i, r := range line {
		switch r {
		case '\\':
			if inDouble && !escaped {
				escaped = true
				continue
			}
		case '"':
			if !inSingle && !escaped {
				inDouble = !inDouble
			}
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '#':
			if !inSingle && !inDouble {
				return line[:i]
			}
		}
		escaped = false
	}
	return line
}

func CollectProjectAndHome(home, project string) ([]Artifact, []finding.Skipped) {
	var artifacts []Artifact
	var skipped []finding.Skipped
	for _, candidates := range [][]CandidatePath{
		CandidateConfigPaths(home, project),
		CandidateInstructionPaths(home, project),
		CandidateCredentialPaths(home),
		CandidateShellRCPaths(home),
	} {
		found, skip := ExistingArtifacts(candidates, true)
		artifacts = append(artifacts, found...)
		skipped = append(skipped, skip...)
	}
	return artifacts, skipped
}

func FindCredentialCopyCandidates(home string) []CandidatePath {
	var candidates []CandidatePath
	roots := []string{
		os.TempDir(),
		filepath.Join(home, "Downloads"),
		filepath.Join(home, "Dropbox"),
		filepath.Join(home, "Library", "Mobile Documents", "com~apple~CloudDocs"),
		filepath.Join(home, "OneDrive"),
		filepath.Join(home, "Google Drive"),
	}
	names := map[string]bool{}
	for _, c := range CandidateCredentialPaths(home) {
		names[filepath.Base(c.Path)] = true
	}
	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		for name := range names {
			candidates = append(candidates, CandidatePath{
				Path:  filepath.Join(root, name),
				Tool:  "credential-copy",
				Scope: "user",
				Kind:  "credential-copy",
			})
		}
		candidates = append(candidates, shallowCredentialLikeFiles(root)...)
	}
	return candidates
}

func shallowCredentialLikeFiles(root string) []CandidatePath {
	const maxDepth = 2
	const maxSize = 1 << 20
	var candidates []CandidatePath
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if path == root {
			return nil
		}
		depth := pathDepth(root, path)
		if d.IsDir() {
			if depth >= maxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if depth > maxDepth || !credentialLikeName(filepath.Base(path)) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxSize {
			return nil
		}
		candidates = append(candidates, CandidatePath{
			Path:  path,
			Tool:  "credential-copy",
			Scope: "user",
			Kind:  "credential-copy",
		})
		return nil
	})
	return candidates
}

func pathDepth(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return 0
	}
	return len(strings.Split(rel, string(os.PathSeparator)))
}

func credentialLikeName(name string) bool {
	lower := strings.ToLower(name)
	if lower == ".npmrc" || lower == "hosts.yml" || lower == "auth.json" || lower == ".credentials.json" {
		return true
	}
	if strings.HasSuffix(lower, ".json") || strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".toml") {
		return strings.Contains(lower, "auth") ||
			strings.Contains(lower, "credential") ||
			strings.Contains(lower, "token") ||
			strings.Contains(lower, "secret") ||
			strings.Contains(lower, "host")
	}
	return false
}
