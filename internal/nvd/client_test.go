package nvd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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
	matches, err := parseResponse([]byte(fakeNVDResponse))
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
