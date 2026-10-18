// Package checks implements groma's declarative vulnerability-check
// format: one YAML file per check, matched against an Observation (a
// host's identified service — product/version/CPE, however it was
// discovered: naabu's -sV fingerprint, a future banner-grab source, or
// anything else). This mirrors assay's nuclei-compatible YAML templates
// in spirit and in the info/classification field names, so an operator
// who already writes assay templates recognizes the shape immediately.
//
// It is deliberately NOT a NASL-VM reimplementation: there is no
// scripting language, no knowledge base, no execution-phase scheduler.
// A check is pure data — a service match (product/CPE) plus a version
// range — because that is the shape of a remote version-to-CVE mapping,
// which is what this format exists to express. Credentialed/local
// checks (the other half of what makes Nessus "Nessus": SSH/WinRM into
// the host, audit installed packages) need real session and command
// execution and are a deliberately separate, larger build — not
// shoehorned into this format.
package checks

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/TyrusRC/groma/internal/core"
)

// Check is one declarative vulnerability check, loaded from YAML.
type Check struct {
	ID   string `yaml:"id"`
	Info Info   `yaml:"info"`

	Service ServiceMatch `yaml:"service"`
}

// Info mirrors assay's template Info block (same field names) so the
// two YAML formats read the same way to someone maintaining both.
type Info struct {
	Name           string         `yaml:"name"`
	Author         string         `yaml:"author,omitempty"`
	Severity       core.Severity  `yaml:"severity"`
	Description    string         `yaml:"description,omitempty"`
	Reference      []string       `yaml:"reference,omitempty"`
	Remediation    string         `yaml:"remediation,omitempty"`
	Classification Classification `yaml:"classification,omitempty"`
}

// Classification mirrors assay's Classification block.
type Classification struct {
	CVEID       string  `yaml:"cve-id,omitempty"`
	CWEID       string  `yaml:"cwe-id,omitempty"`
	CVSSScore   float64 `yaml:"cvss-score,omitempty"`
	CVSSMetrics string  `yaml:"cvss-metrics,omitempty"`
}

// ServiceMatch is what must be true about a discovered service for this
// check to apply. Product and CPE are alternatives: either matching is
// enough on its own (an operator may know only one reliably). Version
// constraints, if any are set, are ANDed — every one set must hold.
type ServiceMatch struct {
	Product string            `yaml:"product,omitempty"` // case-insensitive exact match
	CPE     string            `yaml:"cpe,omitempty"`     // prefix match against any of the observation's CPEs
	Version VersionConstraint `yaml:"version,omitempty"`
}

// VersionConstraint bounds the vulnerable version range. Any subset of
// fields may be set ("" = unset, not checked); all set fields must hold
// for a match.
type VersionConstraint struct {
	Eq  string `yaml:"eq,omitempty"`
	Lt  string `yaml:"lt,omitempty"`
	Lte string `yaml:"lte,omitempty"`
	Gt  string `yaml:"gt,omitempty"`
	Gte string `yaml:"gte,omitempty"`
}

func (v VersionConstraint) isSet() bool {
	return v.Eq != "" || v.Lt != "" || v.Lte != "" || v.Gt != "" || v.Gte != ""
}

// Observation is a discovered service — the thing a Check is matched
// against. It is a neutral shape, not naabu.Result directly, so any
// future source of product/version/CPE data can feed the same check
// engine; see naabu_bridge.go for the naabu adapter.
type Observation struct {
	Host     string
	Port     int
	Protocol string
	Product  string
	Version  string
	CPEs     []string
}

// Matches reports whether obs satisfies this check's service match and
// version constraints.
func (c *Check) Matches(obs Observation) bool {
	if !c.Service.matchesService(obs) {
		return false
	}
	return c.Service.Version.matches(obs.Version)
}

func (s ServiceMatch) matchesService(obs Observation) bool {
	if s.Product == "" && s.CPE == "" {
		return false // a check with no service match was never meant to fire
	}
	if s.Product != "" && strings.EqualFold(strings.TrimSpace(s.Product), strings.TrimSpace(obs.Product)) {
		return true
	}
	if s.CPE != "" {
		for _, cpe := range obs.CPEs {
			if strings.HasPrefix(cpe, s.CPE) {
				return true
			}
		}
	}
	return false
}

func (v VersionConstraint) matches(version string) bool {
	if version == "" {
		// No observed version means a version-bounded check cannot be
		// evaluated — that is "no match", never a free pass through an
		// unverifiable constraint.
		return !v.isSet()
	}
	if v.Eq != "" && compareVersions(version, v.Eq) != 0 {
		return false
	}
	if v.Lt != "" && compareVersions(version, v.Lt) >= 0 {
		return false
	}
	if v.Lte != "" && compareVersions(version, v.Lte) > 0 {
		return false
	}
	if v.Gt != "" && compareVersions(version, v.Gt) <= 0 {
		return false
	}
	if v.Gte != "" && compareVersions(version, v.Gte) < 0 {
		return false
	}
	return true
}

// ToFinding renders a matched check as a core.Finding.
func (c *Check) ToFinding(obs Observation) *core.Finding {
	f := core.NewFinding(c.ID, c.Info.Severity)
	f.Tool = "groma"
	f.Title = c.Info.Name
	f.Description = c.Info.Description
	f.Host, f.Port, f.Protocol = obs.Host, obs.Port, obs.Protocol
	f.Product, f.Version = obs.Product, obs.Version
	f.Remediation = c.Info.Remediation
	f.References = c.Info.Reference
	if c.Info.Classification.CWEID != "" {
		f.CWE = []string{c.Info.Classification.CWEID}
	}
	f.CVSS = c.Info.Classification.CVSSScore
	f.CVSSVector = c.Info.Classification.CVSSMetrics
	if obs.Protocol == "local" {
		f.Evidence = fmt.Sprintf("Installed package %s %s (credentialed local check)", obs.Product, obs.Version)
	} else {
		f.Evidence = fmt.Sprintf("Observed %s %s on port %d/%s", obs.Product, obs.Version, obs.Port, obs.Protocol)
	}
	return f
}

// Evaluate matches every check against every observation and returns a
// Finding for each (check, observation) pair that matches.
func Evaluate(checkList []*Check, observations []Observation) []*core.Finding {
	var out []*core.Finding
	for _, c := range checkList {
		for _, obs := range observations {
			if c.Matches(obs) {
				out = append(out, c.ToFinding(obs))
			}
		}
	}
	return out
}

// compareVersions compares two dotted/alnum version strings and returns
// -1, 0, or 1.
//
// NOTE: this is a best-effort comparator for the common "digits
// separated by dots, optional letter suffix" shape seen in CVE
// advisories (e.g. "2.4.49", "8.9p1") — not a full package-manager-grade
// version algorithm (no epoch:upstream-revision, no ~pre/+build
// modifiers). A check whose vulnerable range depends on one of those
// exotic schemes should have its boundary verified by hand against the
// advisory, not trusted blindly to this function.
func compareVersions(a, b string) int {
	ta, tb := tokenizeVersion(a), tokenizeVersion(b)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		var x, y string
		if i < len(ta) {
			x = ta[i]
		}
		if i < len(tb) {
			y = tb[i]
		}
		if c := compareToken(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// tokenizeVersion splits a version string into alternating digit-runs
// and letter-runs, discarding any other separator ('.', '-', '_', ...).
func tokenizeVersion(v string) []string {
	var tokens []string
	var cur strings.Builder
	curIsDigit := false
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			if cur.Len() > 0 && !curIsDigit {
				flush()
			}
			curIsDigit = true
			cur.WriteRune(r)
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			if cur.Len() > 0 && curIsDigit {
				flush()
			}
			curIsDigit = false
			cur.WriteRune(r)
		default:
			flush()
		}
	}
	flush()
	return tokens
}

func compareToken(x, y string) int {
	if x == y {
		return 0
	}
	xNum, xIsNum := parseNumericToken(x)
	yNum, yIsNum := parseNumericToken(y)

	// A missing trailing token is treated as numeric zero against a
	// present numeric token, so "2.4" == "2.4.0" rather than
	// "2.4" < "2.4.0" — a trailing .0 is version-equivalent in virtually
	// every advisory's numbering scheme this format targets.
	if x == "" && yIsNum {
		xNum, xIsNum = 0, true
	}
	if y == "" && xIsNum {
		yNum, yIsNum = 0, true
	}

	switch {
	case xIsNum && yIsNum:
		switch {
		case xNum < yNum:
			return -1
		case xNum > yNum:
			return 1
		default:
			return 0
		}
	case xIsNum && !yIsNum:
		return -1 // a bare numeric token sorts before a letter-suffix token (e.g. "2" < "2a")
	case !xIsNum && yIsNum:
		return 1
	default:
		return strings.Compare(x, y)
	}
}

func parseNumericToken(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
