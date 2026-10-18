package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TyrusRC/groma/internal/core"
	"github.com/TyrusRC/groma/internal/tools/naabu"
)

func apacheCheck() *Check {
	return &Check{
		ID: "CVE-2021-41773",
		Info: Info{
			Name:     "Apache 2.4.49-2.4.50 Path Traversal / RCE",
			Severity: core.SeverityCritical,
			Classification: Classification{
				CVEID:     "CVE-2021-41773",
				CVSSScore: 9.8,
			},
		},
		Service: ServiceMatch{
			Product: "apache",
			Version: VersionConstraint{Gte: "2.4.49", Lte: "2.4.50"},
		},
	}
}

func TestMatchesVulnerableVersion(t *testing.T) {
	c := apacheCheck()
	if !c.Matches(Observation{Product: "apache", Version: "2.4.49"}) {
		t.Error("2.4.49 is the lower bound (gte) and must match")
	}
	if !c.Matches(Observation{Product: "apache", Version: "2.4.50"}) {
		t.Error("2.4.50 is the upper bound (lte) and must match")
	}
	if !c.Matches(Observation{Product: "Apache", Version: "2.4.49"}) {
		t.Error("product match must be case-insensitive")
	}
}

func TestDoesNotMatchPatchedOrUnrelatedVersion(t *testing.T) {
	c := apacheCheck()
	if c.Matches(Observation{Product: "apache", Version: "2.4.51"}) {
		t.Error("2.4.51 is patched (above lte) and must not match")
	}
	if c.Matches(Observation{Product: "apache", Version: "2.4.48"}) {
		t.Error("2.4.48 is below gte and must not match")
	}
	if c.Matches(Observation{Product: "nginx", Version: "2.4.49"}) {
		t.Error("a different product must never match regardless of version")
	}
}

func TestDoesNotMatchWithoutAnObservedVersion(t *testing.T) {
	c := apacheCheck()
	if c.Matches(Observation{Product: "apache", Version: ""}) {
		t.Error("a version-bounded check with no observed version must not match — that's unverifiable, not a free pass")
	}
}

func TestCPEPrefixMatch(t *testing.T) {
	c := &Check{
		ID:   "test-cpe",
		Info: Info{Name: "test", Severity: core.SeverityLow},
		Service: ServiceMatch{
			CPE: "cpe:/a:vsftpd_project:vsftpd",
		},
	}
	if !c.Matches(Observation{CPEs: []string{"cpe:/a:vsftpd_project:vsftpd:3.0.3"}}) {
		t.Error("a CPE prefix match must succeed")
	}
	if c.Matches(Observation{CPEs: []string{"cpe:/a:apache:http_server:2.4.49"}}) {
		t.Error("an unrelated CPE must not match")
	}
}

func TestServiceMatchWithNeitherProductNorCPENeverMatches(t *testing.T) {
	s := ServiceMatch{}
	if s.matchesService(Observation{Product: "anything", CPEs: []string{"cpe:/a:anything:anything"}}) {
		t.Error("a ServiceMatch with no product or cpe must never match — it was never meant to fire")
	}
}

func TestCompareVersionsNumericNotLexical(t *testing.T) {
	// The classic trap: lexically "3.0.10" < "3.0.3" (because '1' < '3'),
	// but numerically 10 > 3. The comparator must get this right.
	if compareVersions("3.0.3", "3.0.10") >= 0 {
		t.Error("3.0.3 must compare less than 3.0.10 numerically, not lexically")
	}
	if compareVersions("3.0.10", "3.0.3") <= 0 {
		t.Error("3.0.10 must compare greater than 3.0.3 numerically, not lexically")
	}
}

func TestCompareVersionsTrailingZeroEquivalence(t *testing.T) {
	if compareVersions("2.4", "2.4.0") != 0 {
		t.Error("2.4 and 2.4.0 must compare equal")
	}
}

func TestCompareVersionsLetterSuffix(t *testing.T) {
	if compareVersions("8.9p1", "8.9p2") >= 0 {
		t.Error("8.9p1 must compare less than 8.9p2")
	}
	if compareVersions("8.9p1", "8.9p1") != 0 {
		t.Error("identical versions must compare equal")
	}
	if compareVersions("2.4", "2.4a") >= 0 {
		t.Error("a bare version must compare less than its lettered variant")
	}
}

func TestToFindingMapsFields(t *testing.T) {
	c := apacheCheck()
	c.Info.Classification.CWEID = "CWE-22"
	c.Info.Remediation = "Upgrade to 2.4.51 or later."
	obs := Observation{Host: "10.0.0.5", Port: 80, Protocol: "tcp", Product: "apache", Version: "2.4.49"}

	f := c.ToFinding(obs)
	if f.Host != "10.0.0.5" || f.Port != 80 || f.Protocol != "tcp" {
		t.Errorf("location fields mismapped: %+v", f)
	}
	if f.Severity != core.SeverityCritical {
		t.Errorf("expected severity from the check's info block, got %s", f.Severity)
	}
	if len(f.CWE) != 1 || f.CWE[0] != "CWE-22" {
		t.Errorf("expected CWE to map through, got %+v", f.CWE)
	}
	if f.Remediation != "Upgrade to 2.4.51 or later." {
		t.Errorf("expected remediation to map through, got %q", f.Remediation)
	}
	if f.Tool != "groma" {
		t.Errorf("expected Tool=groma, got %q", f.Tool)
	}
	if f.Product != "apache" || f.Version != "2.4.49" {
		t.Errorf("expected the observed product/version to map through as structured fields, got %+v", f)
	}
}

func TestEvaluateReturnsOneFindingPerMatchingPair(t *testing.T) {
	checks := []*Check{apacheCheck()}
	observations := []Observation{
		{Host: "a", Product: "apache", Version: "2.4.49"},
		{Host: "b", Product: "apache", Version: "2.4.51"}, // patched, no match
		{Host: "c", Product: "nginx", Version: "2.4.49"},  // wrong product, no match
	}
	findings := Evaluate(checks, observations)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Host != "a" {
		t.Errorf("expected the finding to be for host 'a', got %q", findings[0].Host)
	}
}

func TestObservationsFromNaabuSkipsPortsWithNoServiceData(t *testing.T) {
	results := []naabu.Result{
		{Port: 21, Product: "vsftpd", Version: "3.0.3"},
		{Port: 443, Product: "", CPEs: nil}, // no fingerprint data — nothing to match on
		{Port: 22, CPEs: []string{"cpe:/a:openbsd:openssh:9.0"}},
	}
	obs := ObservationsFromNaabu("10.0.0.5", results)
	if len(obs) != 2 {
		t.Fatalf("expected 2 observations (port 443 has no product/cpe to match), got %d: %+v", len(obs), obs)
	}
	if obs[0].Host != "10.0.0.5" || obs[0].Port != 21 || obs[0].Product != "vsftpd" {
		t.Errorf("observation 0 mismapped: %+v", obs[0])
	}
}

func TestLoadChecksRoundTrip(t *testing.T) {
	dir := t.TempDir()
	const yamlDoc = `
id: CVE-TEST-0001
info:
  name: "Test Product Old Version RCE"
  severity: high
  reference:
    - https://example.com/advisory
  classification:
    cve-id: CVE-TEST-0001
    cvss-score: 8.1
service:
  product: testproduct
  version:
    lt: "2.0.0"
`
	if err := os.WriteFile(filepath.Join(dir, "test-check.yaml"), []byte(yamlDoc), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadChecks(dir)
	if err != nil {
		t.Fatalf("LoadChecks returned an error: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 loaded check, got %d", len(loaded))
	}
	c := loaded[0]
	if c.ID != "CVE-TEST-0001" || c.Info.Severity != core.SeverityHigh {
		t.Errorf("loaded check fields wrong: %+v", c)
	}
	if !c.Matches(Observation{Product: "testproduct", Version: "1.9.9"}) {
		t.Error("the loaded check must match a vulnerable observation")
	}
	if c.Matches(Observation{Product: "testproduct", Version: "2.0.0"}) {
		t.Error("the loaded check must not match the patched version")
	}
}

func TestLoadChecksRejectsMissingRequiredFields(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"no-id.yaml":       "info:\n  name: x\n  severity: low\nservice:\n  product: x\n",
		"no-severity.yaml": "id: x\ninfo:\n  name: x\nservice:\n  product: x\n",
		"no-match.yaml":    "id: x\ninfo:\n  name: x\n  severity: low\nservice:\n",
	}
	for name, doc := range cases {
		dir := filepath.Join(dir, name+".d")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadChecks(dir); err == nil {
			t.Errorf("%s: expected LoadChecks to reject an invalid check, got no error", name)
		}
	}
}

func TestLoadChecksIgnoresNonYAMLFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("not a check"), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadChecks(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(loaded) != 0 {
		t.Errorf("expected 0 checks loaded from a directory with only a README, got %d", len(loaded))
	}
}
