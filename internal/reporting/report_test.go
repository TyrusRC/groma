package reporting

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/groma/internal/core"
)

func sampleFindings() core.Findings {
	low := core.NewFinding("open_port", core.SeverityInfo)
	low.Host, low.Port, low.Protocol = "10.0.0.5", 80, "tcp"
	low.Title = "Port 80/tcp open"

	crit := core.NewFinding("CVE-2021-41773", core.SeverityCritical)
	crit.Host, crit.Port, crit.Protocol = "10.0.0.5", 80, "tcp"
	crit.Title = "Apache path traversal"
	crit.CWE = []string{"CWE-22"}
	crit.CVSS = 9.8
	crit.Evidence = "Observed apache 2.4.49"

	return core.Findings{low, crit}
}

func TestNewReportSummarizesAndSortsWorstFirst(t *testing.T) {
	r := NewReport([]string{"10.0.0.5"}, sampleFindings(), 2*time.Second)
	if r.Summary.TotalFindings != 2 || r.Summary.Critical != 1 || r.Summary.Info != 1 {
		t.Errorf("summary mismatch: %+v", r.Summary)
	}
	if r.Findings[0].Severity != core.SeverityCritical {
		t.Errorf("expected worst-first ordering, got %s first", r.Findings[0].Severity)
	}
	if r.DurationMS != 2000 {
		t.Errorf("expected DurationMS=2000, got %d", r.DurationMS)
	}
}

func TestWriteJSONRoundTrips(t *testing.T) {
	r := NewReport([]string{"10.0.0.5"}, sampleFindings(), time.Second)
	var buf bytes.Buffer
	if err := r.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}
	var decoded Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded.Tool != "groma" || len(decoded.Findings) != 2 {
		t.Errorf("decoded report mismatch: %+v", decoded)
	}
}

func TestWriteTextIncludesKeyFields(t *testing.T) {
	r := NewReport([]string{"10.0.0.5"}, sampleFindings(), time.Second)
	var buf bytes.Buffer
	if err := r.WriteText(&buf); err != nil {
		t.Fatalf("WriteText error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"10.0.0.5", "CRITICAL", "Apache path traversal", "CWE-22", "9.8"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected text report to contain %q, got:\n%s", want, out)
		}
	}
}

func TestWriteTextNoFindings(t *testing.T) {
	r := NewReport([]string{"10.0.0.5"}, nil, time.Second)
	var buf bytes.Buffer
	if err := r.WriteText(&buf); err != nil {
		t.Fatalf("WriteText error: %v", err)
	}
	if !strings.Contains(buf.String(), "No findings.") {
		t.Errorf("expected explicit 'No findings.' line, got:\n%s", buf.String())
	}
}

func TestWriteSARIFIsValidAndGroupsRulesByType(t *testing.T) {
	findings := sampleFindings()
	// Two findings of the same type must collapse to one rule.
	dup := core.NewFinding("open_port", core.SeverityInfo)
	dup.Host, dup.Port = "10.0.0.6", 443
	dup.Title = "Port 443/tcp open"
	findings = append(findings, dup)

	r := NewReport([]string{"10.0.0.5", "10.0.0.6"}, findings, time.Second)
	var buf bytes.Buffer
	if err := r.WriteSARIF(&buf); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}

	var doc sarifLog
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid SARIF/JSON: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %q", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected exactly 1 run, got %d", len(doc.Runs))
	}
	run := doc.Runs[0]
	if len(run.Results) != 3 {
		t.Errorf("expected 3 results (one per finding), got %d", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("expected 2 distinct rules (open_port, CVE-2021-41773), got %d: %+v", len(run.Tool.Driver.Rules), run.Tool.Driver.Rules)
	}

	var criticalResult *sarifResult
	for i := range run.Results {
		if run.Results[i].RuleID == "cve-2021-41773" {
			criticalResult = &run.Results[i]
		}
	}
	if criticalResult == nil {
		t.Fatal("expected a result for rule 'cve-2021-41773'")
	}
	if criticalResult.Level != sarifLevelError {
		t.Errorf("critical severity must map to SARIF level 'error', got %q", criticalResult.Level)
	}
	if criticalResult.Locations[0].PhysicalLocation.ArtifactLocation.URI != "network://10.0.0.5:80" {
		t.Errorf("expected synthetic network URI, got %q", criticalResult.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
}

func TestRuleIDSlugifiesFindingType(t *testing.T) {
	cases := map[string]string{
		"open_port":           "open-port",
		"CVE-2021-41773":      "cve-2021-41773",
		"ftp_anonymous_login": "ftp-anonymous-login",
		"":                    "finding",
	}
	for in, want := range cases {
		if got := ruleID(in); got != want {
			t.Errorf("ruleID(%q) = %q, want %q", in, got, want)
		}
	}
}
