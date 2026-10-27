package nvd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/TyrusRC/groma/internal/core"
)

const fakeNVDResponse = `{
  "totalResults": 1,
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2024-6387",
        "descriptions": [
          {"lang": "en", "value": "A signal handler race condition in sshd allows unauthenticated RCE."}
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "cvssData": {
                "baseScore": 8.1,
                "baseSeverity": "HIGH",
                "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
              }
            }
          ]
        },
        "weaknesses": [
          {
            "description": [
              {"lang": "en", "value": "CWE-362"}
            ]
          }
        ],
        "references": [
          {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-6387"}
        ]
      }
    }
  ]
}`

func TestParseResponse(t *testing.T) {
	matches, _, err := parseResponse([]byte(fakeNVDResponse))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	m := matches[0]
	if m.ID != "CVE-2024-6387" {
		t.Errorf("expected CVE-2024-6387, got %s", m.ID)
	}
	if m.CVSSv3Score != 8.1 {
		t.Errorf("expected score 8.1, got %f", m.CVSSv3Score)
	}
	if m.Severity != "HIGH" {
		t.Errorf("expected severity HIGH, got %s", m.Severity)
	}
	if len(m.CWEs) != 1 || m.CWEs[0] != "CWE-362" {
		t.Errorf("expected [CWE-362], got %v", m.CWEs)
	}
	if len(m.References) != 1 {
		t.Errorf("expected 1 reference, got %d", len(m.References))
	}
}

func TestQueryByCPE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cpeName") == "" {
			http.Error(w, "missing cpeName", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fakeNVDResponse))
	}))
	defer srv.Close()

	c := NewClient("", "")
	c.BaseURL = srv.URL

	matches, err := c.QueryByCPE(context.Background(), "cpe:/a:openbsd:openssh:8.9")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 || matches[0].ID != "CVE-2024-6387" {
		t.Errorf("expected CVE-2024-6387, got %v", matches)
	}
}

func TestCacheWriteAndRead(t *testing.T) {
	dir := t.TempDir()
	c := NewClient("", dir)
	cpeName := "cpe:/a:openbsd:openssh:8.9"
	matches := []CVEMatch{{ID: "CVE-2024-6387", Severity: "HIGH"}}
	c.writeCache(cpeName, matches)

	got, ok := c.readCache(cpeName)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(got) != 1 || got[0].ID != "CVE-2024-6387" {
		t.Errorf("cache mismatch: got %v", got)
	}
}

func TestCacheMiss(t *testing.T) {
	dir := t.TempDir()
	c := NewClient("", dir)
	_, ok := c.readCache("cpe:/a:nonexistent:foo:1.0")
	if ok {
		t.Error("expected cache miss for unknown CPE")
	}
}

func TestToFindings(t *testing.T) {
	matches := []CVEMatch{
		{
			ID:          "CVE-2024-6387",
			Description: "RCE in sshd",
			Severity:    "HIGH",
			CVSSv3Score: 8.1,
			CVSSv3:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
			CWEs:        []string{"CWE-362"},
		},
	}
	findings := ToFindings("10.0.0.1", 22, "tcp", "ssh", "OpenSSH", "8.9p1", matches)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Type != "CVE-2024-6387" {
		t.Errorf("expected type CVE-2024-6387, got %s", f.Type)
	}
	if f.Host != "10.0.0.1" || f.Port != 22 {
		t.Errorf("wrong host/port: %s:%d", f.Host, f.Port)
	}
	if f.CVSS != 8.1 {
		t.Errorf("expected CVSS 8.1, got %f", f.CVSS)
	}
}

func TestMapNVDSeverity(t *testing.T) {
	cases := []struct {
		sev   string
		score float64
		want  string
	}{
		{"CRITICAL", 9.8, "critical"},
		{"HIGH", 7.5, "high"},
		{"MEDIUM", 5.0, "medium"},
		{"LOW", 2.0, "low"},
		{"", 9.5, "critical"},
		{"", 7.0, "high"},
		{"", 4.0, "medium"},
		{"", 2.0, "low"},
	}
	for _, c := range cases {
		got := mapNVDSeverity(c.sev, c.score)
		if string(got) != c.want {
			t.Errorf("mapNVDSeverity(%q, %.1f) = %s, want %s", c.sev, c.score, got, c.want)
		}
	}
}

func TestCacheKeyDeterministic(t *testing.T) {
	c := NewClient("", "")
	k1 := c.cacheKey("cpe:/a:openbsd:openssh:8.9")
	k2 := c.cacheKey("cpe:/a:openbsd:openssh:8.9")
	if k1 != k2 {
		t.Errorf("cache key not deterministic: %s vs %s", k1, k2)
	}
	k3 := c.cacheKey("cpe:/a:openbsd:openssh:9.0")
	if k1 == k3 {
		t.Error("different CPEs should produce different cache keys")
	}
}

func TestCPE22to23(t *testing.T) {
	cases := []struct {
		cpe22   string
		version string
		want    string
	}{
		{"cpe:/a:openbsd:openssh", "8.9p1", "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"},
		{"cpe:/a:apache:http_server", "2.4.49", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
		{"cpe:/a:nginx:nginx", "", "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"},
		{"cpe:/a:openbsd:openssh", "", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"},
		// Passthrough for already-2.3 format
		{"cpe:2.3:a:openbsd:openssh:9.0:*:*:*:*:*:*:*", "", "cpe:2.3:a:openbsd:openssh:9.0:*:*:*:*:*:*:*"},
	}
	for _, c := range cases {
		got := CPE22to23(c.cpe22, c.version)
		if got != c.want {
			t.Errorf("CPE22to23(%q, %q) = %q, want %q", c.cpe22, c.version, got, c.want)
		}
	}
}

func TestCacheRespectedInQuery(t *testing.T) {
	dir := t.TempDir()
	cpeName := "cpe:/a:test:product:1.0"
	cacheData := `[{"ID":"CVE-FROM-CACHE","Severity":"LOW"}]`
	c := NewClient("", dir)
	path := filepath.Join(dir, c.cacheKey(cpeName)+".json")
	os.WriteFile(path, []byte(cacheData), 0o600)

	// Server should never be called — cache hit.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server was called despite cache hit")
	}))
	defer srv.Close()
	c.BaseURL = srv.URL

	matches, err := c.QueryByCPE(context.Background(), cpeName)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 || matches[0].ID != "CVE-FROM-CACHE" {
		t.Errorf("expected cached result, got %v", matches)
	}
}

func TestParseResponseCVSSv2FallbackAndTotal(t *testing.T) {
	// A pre-2016-style CVE carrying ONLY a CVSS v2 metric must still get a
	// score and a non-"low" severity, and parseResponse must report the
	// query's total for pagination.
	body := `{
      "totalResults": 137,
      "vulnerabilities": [
        {"cve": {
          "id": "CVE-2014-0001",
          "descriptions": [{"lang":"en","value":"old bug"}],
          "metrics": {"cvssMetricV2": [
            {"baseSeverity":"HIGH","cvssData":{"baseScore":7.5,"vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P"}}
          ]}
        }}
      ]
    }`
	matches, total, err := parseResponse([]byte(body))
	if err != nil {
		t.Fatalf("parseResponse error: %v", err)
	}
	if total != 137 {
		t.Errorf("expected total 137 (for pagination), got %d", total)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].CVSSv3Score != 7.5 {
		t.Errorf("expected v2 baseScore 7.5 carried through, got %v", matches[0].CVSSv3Score)
	}
	if got := mapNVDSeverity(matches[0].Severity, matches[0].CVSSv3Score); got != core.SeverityHigh {
		t.Errorf("a 7.5 v2 CVE should map to High, got %v", got)
	}
}

func TestParseResponsePrefersCVSSv40(t *testing.T) {
	// A CVE with both v4.0 and v3.1 must report the v4.0 score/severity.
	body := `{
      "totalResults": 1,
      "vulnerabilities": [
        {"cve": {
          "id": "CVE-2024-9999",
          "descriptions": [{"lang":"en","value":"new bug"}],
          "metrics": {
            "cvssMetricV40": [{"cvssData":{"baseScore":9.3,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/AV:N"}}],
            "cvssMetricV31": [{"cvssData":{"baseScore":7.5,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N"}}]
          }
        }}
      ]
    }`
	matches, _, err := parseResponse([]byte(body))
	if err != nil {
		t.Fatalf("parseResponse error: %v", err)
	}
	if len(matches) != 1 || matches[0].CVSSv3Score != 9.3 || matches[0].Severity != "CRITICAL" {
		t.Errorf("expected v4.0 score 9.3/CRITICAL to win over v3.1, got %+v", matches[0])
	}
}
