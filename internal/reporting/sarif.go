package reporting

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/TyrusRC/groma/internal/core"
)

const (
	sarifSchema    = "https://json.schemastore.org/sarif-2.1.0.json"
	informationURI = "https://github.com/TyrusRC/groma"

	sarifLevelError   = "error"
	sarifLevelWarning = "warning"
	sarifLevelNote    = "note"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  *sarifText     `json:"fullDescription,omitempty"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifText struct {
	Text string `json:"text"`
}

// WriteSARIF writes the report as a SARIF 2.1.0 log suitable for GitHub
// code scanning and other SARIF consumers. There is no source file for
// a network finding, so the artifact URI is a synthetic
// "network://host:port" location — SARIF only requires a URI string,
// not a real repository path.
func (r *Report) WriteSARIF(w io.Writer) error {
	ruleIndex := make(map[string]bool)
	rules := make([]sarifRule, 0)
	results := make([]sarifResult, 0, len(r.Findings))

	for _, f := range r.Findings {
		id := ruleID(f.Type)
		if !ruleIndex[id] {
			ruleIndex[id] = true
			rules = append(rules, newSARIFRule(id, f))
		}
		results = append(results, newSARIFResult(id, f))
	}

	doc := sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           toolName,
				Version:        reportVersion,
				InformationURI: informationURI,
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func newSARIFRule(id string, f *core.Finding) sarifRule {
	rule := sarifRule{
		ID:               id,
		Name:             f.Type,
		ShortDescription: sarifText{Text: f.Title},
	}
	if f.Description != "" {
		rule.FullDescription = &sarifText{Text: f.Description}
	}
	if len(f.References) > 0 {
		rule.HelpURI = f.References[0]
	}
	props := map[string]any{}
	if len(f.CWE) > 0 {
		props["cwe"] = f.CWE
	}
	if len(props) > 0 {
		rule.Properties = props
	}
	return rule
}

func newSARIFResult(id string, f *core.Finding) sarifResult {
	msg := f.Title
	if f.Description != "" {
		msg = f.Description
	}
	props := map[string]any{}
	if f.CVSS > 0 {
		props["security-severity"] = strconv.FormatFloat(f.CVSS, 'f', 1, 64)
	}
	if f.Evidence != "" {
		props["evidence"] = f.Evidence
	}
	if f.Service != "" {
		props["service"] = f.Service
	}
	return sarifResult{
		RuleID:  id,
		Level:   sarifLevel(f.Severity),
		Message: sarifText{Text: msg},
		Locations: []sarifLocation{{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: networkURI(f)},
			},
		}},
		Properties: props,
	}
}

func networkURI(f *core.Finding) string {
	if f.Port == 0 {
		return "network://" + f.Host
	}
	return "network://" + f.Host + ":" + strconv.Itoa(f.Port)
}

func sarifLevel(s core.Severity) string {
	switch s {
	case core.SeverityCritical, core.SeverityHigh:
		return sarifLevelError
	case core.SeverityMedium:
		return sarifLevelWarning
	default:
		return sarifLevelNote
	}
}

// ruleID derives a stable, SARIF-safe rule identifier from a finding
// type, e.g. "open_port" -> "open-port".
func ruleID(findingType string) string {
	var b strings.Builder
	prevHyphen := false
	for _, r := range strings.ToLower(findingType) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevHyphen = false
		default:
			if !prevHyphen && b.Len() > 0 {
				b.WriteRune('-')
				prevHyphen = true
			}
		}
	}
	out := strings.TrimRight(b.String(), "-")
	if out == "" {
		return "finding"
	}
	return out
}
