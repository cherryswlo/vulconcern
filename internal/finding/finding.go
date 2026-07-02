package finding

// Severity is ordered from least to most urgent.
type Severity string

const (
	Info     Severity = "INFO"
	Medium   Severity = "MEDIUM"
	High     Severity = "HIGH"
	Critical Severity = "CRITICAL"
)

type KV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Finding struct {
	CheckID     string   `json:"check_id"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Evidence    []KV     `json:"evidence,omitempty"`
	Citation    string   `json:"citation,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Suppressed  bool     `json:"suppressed,omitempty"`
}

type Skipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type Report struct {
	Version         int       `json:"v"`
	Project         string    `json:"project"`
	BaselinePath    string    `json:"baseline_path"`
	BaselinePresent bool      `json:"baseline_present"`
	Note            string    `json:"note,omitempty"`
	Findings        []Finding `json:"findings"`
	Skipped         []Skipped `json:"skipped,omitempty"`
}

func Rank(s Severity) int {
	switch s {
	case Critical:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	case Info:
		return 1
	default:
		return 0
	}
}

func HasAtLeast(findings []Finding, minimum Severity) bool {
	minRank := Rank(minimum)
	for _, f := range findings {
		if !f.Suppressed && Rank(f.Severity) >= minRank {
			return true
		}
	}
	return false
}

func SortFindings(findings []Finding) {
	for i := 1; i < len(findings); i++ {
		current := findings[i]
		j := i - 1
		for j >= 0 && less(current, findings[j]) {
			findings[j+1] = findings[j]
			j--
		}
		findings[j+1] = current
	}
}

func less(a, b Finding) bool {
	if Rank(a.Severity) != Rank(b.Severity) {
		return Rank(a.Severity) > Rank(b.Severity)
	}
	if a.CheckID != b.CheckID {
		return a.CheckID < b.CheckID
	}
	return a.Title < b.Title
}
