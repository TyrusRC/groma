// Package nvd queries the NIST National Vulnerability Database (NVD)
// API 2.0 for CPE-matched CVEs. This replaces hand-maintained YAML
// check files with a live, authoritative CVE source that covers every
// published vulnerability automatically.
//
// Rate limits: 5 requests / 30 seconds without an API key, 50 / 30s
// with one. The client enforces this with a simple token-bucket limiter
// and caches results on disk so repeated scans don't re-hit the API.
package nvd

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/TyrusRC/groma/internal/core"
)

const (
	defaultBaseURL     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	defaultTimeout     = 30 * time.Second
	defaultCacheTTL    = 24 * time.Hour
	rateWindow         = 30 * time.Second
	rateNoKey          = 5
	rateWithKey        = 50
	maxResultsPerQuery = 2000 // NVD API 2.0 maximum page size
	maxCVEsPerCPE      = 10000 // safety cap on pagination for a single CPE
)

// Client queries the NVD API for CPE-matched CVEs.
type Client struct {
	BaseURL  string
	APIKey   string
	CacheDir string
	CacheTTL time.Duration
	http     *http.Client

	mu        sync.Mutex
	tokens    int
	lastReset time.Time
}

// NewClient creates an NVD client. apiKey is optional (empty = lower
// rate limit). cacheDir is where responses are cached (empty = no caching).
func NewClient(apiKey, cacheDir string) *Client {
	rate := rateNoKey
	if apiKey != "" {
		rate = rateWithKey
	}
	return &Client{
		BaseURL:  defaultBaseURL,
		APIKey:   apiKey,
		CacheDir: cacheDir,
		CacheTTL: defaultCacheTTL,
		http:     &http.Client{Timeout: defaultTimeout},
		tokens:   rate,
	}
}

// CVEMatch is a CVE found to affect a given CPE.
type CVEMatch struct {
	ID          string
	Description string
	Severity    string
	CVSSv3Score float64
	CVSSv3      string
	CWEs        []string
	References  []string
}

// QueryByCPE looks up all CVEs that match the given CPE name string,
// paginating until every result is collected (NVD caps a page at 2000;
// an old, widely-vulnerable version easily exceeds that, and stopping at
// one page would silently drop CVEs). Results are cached on disk as a
// complete set when CacheDir is set.
func (c *Client) QueryByCPE(ctx context.Context, cpeName string) ([]CVEMatch, error) {
	if cached, ok := c.readCache(cpeName); ok {
		return cached, nil
	}

	var all []CVEMatch
	for startIndex := 0; ; {
		matches, total, err := c.fetchPage(ctx, cpeName, startIndex)
		if err != nil {
			return nil, err
		}
		all = append(all, matches...)
		startIndex += len(matches)
		if len(matches) == 0 || startIndex >= total || startIndex >= maxCVEsPerCPE {
			break
		}
	}

	c.writeCache(cpeName, all)
	return all, nil
}

// fetchPage retrieves one page of CVE results and the total count NVD
// reports for the query.
func (c *Client) fetchPage(ctx context.Context, cpeName string, startIndex int) ([]CVEMatch, int, error) {
	if err := c.rateLimit(ctx); err != nil {
		return nil, 0, err
	}

	params := url.Values{}
	params.Set("cpeName", cpeName)
	params.Set("resultsPerPage", fmt.Sprintf("%d", maxResultsPerQuery))
	params.Set("startIndex", fmt.Sprintf("%d", startIndex))

	reqURL := c.BaseURL + "?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("nvd: building request: %w", err)
	}
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("nvd: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, 0, fmt.Errorf("nvd: rate limited (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("nvd: API returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("nvd: reading response: %w", err)
	}
	return parseResponse(body)
}

// ToFindings converts NVD CVE matches into groma findings for a
// specific host/port/service observation.
func ToFindings(host string, port int, protocol, service, product, version string, matches []CVEMatch) core.Findings {
	var out core.Findings
	for _, m := range matches {
		sev := mapNVDSeverity(m.Severity, m.CVSSv3Score)
		f := core.NewFinding(m.ID, sev)
		f.Tool = "nvd"
		f.Title = fmt.Sprintf("%s — %s", m.ID, truncate(m.Description, 120))
		f.Description = m.Description
		f.Host, f.Port, f.Protocol, f.Service = host, port, protocol, service
		f.Product, f.Version = product, version
		f.Evidence = fmt.Sprintf("Observed %s %s matching NVD CPE record", product, version)
		f.CWE = m.CWEs
		f.CVSS = m.CVSSv3Score
		f.CVSSVector = m.CVSSv3
		f.References = m.References
		f.Remediation = "Upgrade to a version not affected by " + m.ID + "."
		out = append(out, f)
	}
	return out
}

// --- NVD API response parsing ---

type apiResponse struct {
	TotalResults int              `json:"totalResults"`
	Vulns        []vulnContainer  `json:"vulnerabilities"`
}

type vulnContainer struct {
	CVE cveItem `json:"cve"`
}

type cveItem struct {
	ID           string        `json:"id"`
	Descriptions []langString  `json:"descriptions"`
	Metrics      cveMetrics    `json:"metrics"`
	Weaknesses   []cveWeakness `json:"weaknesses"`
	References   []cveRef      `json:"references"`
}

type langString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type cveMetrics struct {
	V40 []metricEntry   `json:"cvssMetricV40"`
	V31 []metricEntry   `json:"cvssMetricV31"`
	V30 []metricEntry   `json:"cvssMetricV30"`
	V2  []metricEntryV2 `json:"cvssMetricV2"`
}

type metricEntry struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

// metricEntryV2 is the CVSS v2 metric. Many pre-2016 CVEs (exactly the
// ones that affect the old software versions groma flags) carry only a v2
// score; without this they'd fall through to a 0.0 score and be
// mislabeled "low". In v2 the severity sits on the metric, not in
// cvssData, and there is no "critical" rating.
type metricEntryV2 struct {
	BaseSeverity string `json:"baseSeverity"`
	CVSSData     struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

type cveWeakness struct {
	Description []langString `json:"description"`
}

type cveRef struct {
	URL string `json:"url"`
}

func parseResponse(body []byte) ([]CVEMatch, int, error) {
	var resp apiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, 0, fmt.Errorf("nvd: parsing response: %w", err)
	}
	var out []CVEMatch
	for _, v := range resp.Vulns {
		m := CVEMatch{ID: v.CVE.ID}
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				m.Description = d.Value
				break
			}
		}
		// Prefer the newest CVSS version present: v4.0 (the current
		// default) → v3.1 → v3.0 → v2.
		switch {
		case len(v.CVE.Metrics.V40) > 0:
			m.CVSSv3Score = v.CVE.Metrics.V40[0].CVSSData.BaseScore
			m.Severity = v.CVE.Metrics.V40[0].CVSSData.BaseSeverity
			m.CVSSv3 = v.CVE.Metrics.V40[0].CVSSData.VectorString
		case len(v.CVE.Metrics.V31) > 0:
			m.CVSSv3Score = v.CVE.Metrics.V31[0].CVSSData.BaseScore
			m.Severity = v.CVE.Metrics.V31[0].CVSSData.BaseSeverity
			m.CVSSv3 = v.CVE.Metrics.V31[0].CVSSData.VectorString
		case len(v.CVE.Metrics.V30) > 0:
			m.CVSSv3Score = v.CVE.Metrics.V30[0].CVSSData.BaseScore
			m.Severity = v.CVE.Metrics.V30[0].CVSSData.BaseSeverity
			m.CVSSv3 = v.CVE.Metrics.V30[0].CVSSData.VectorString
		case len(v.CVE.Metrics.V2) > 0:
			// Severity comes from the v2 baseScore via mapNVDSeverity
			// (baseSeverity left as the API gives it, if any).
			m.CVSSv3Score = v.CVE.Metrics.V2[0].CVSSData.BaseScore
			m.Severity = v.CVE.Metrics.V2[0].BaseSeverity
			m.CVSSv3 = v.CVE.Metrics.V2[0].CVSSData.VectorString
		}
		for _, w := range v.CVE.Weaknesses {
			for _, d := range w.Description {
				if d.Lang == "en" && strings.HasPrefix(d.Value, "CWE-") {
					m.CWEs = append(m.CWEs, d.Value)
				}
			}
		}
		for _, r := range v.CVE.References {
			m.References = append(m.References, r.URL)
		}
		out = append(out, m)
	}
	return out, resp.TotalResults, nil
}

func mapNVDSeverity(nvdSev string, score float64) core.Severity {
	switch strings.ToUpper(nvdSev) {
	case "CRITICAL":
		return core.SeverityCritical
	case "HIGH":
		return core.SeverityHigh
	case "MEDIUM":
		return core.SeverityMedium
	case "LOW":
		return core.SeverityLow
	default:
		if score >= 9.0 {
			return core.SeverityCritical
		} else if score >= 7.0 {
			return core.SeverityHigh
		} else if score >= 4.0 {
			return core.SeverityMedium
		}
		return core.SeverityLow
	}
}

// --- Rate limiting ---

func (c *Client) rateLimit(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if now.Sub(c.lastReset) >= rateWindow {
		limit := rateNoKey
		if c.APIKey != "" {
			limit = rateWithKey
		}
		c.tokens = limit
		c.lastReset = now
	}
	if c.tokens <= 0 {
		wait := rateWindow - now.Sub(c.lastReset)
		c.mu.Unlock()
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			c.mu.Lock()
			return ctx.Err()
		}
		c.mu.Lock()
		limit := rateNoKey
		if c.APIKey != "" {
			limit = rateWithKey
		}
		c.tokens = limit
		c.lastReset = time.Now()
	}
	c.tokens--
	return nil
}

// --- Disk cache ---

func (c *Client) cacheKey(cpeName string) string {
	h := sha256.Sum256([]byte(cpeName))
	return fmt.Sprintf("%x", h[:16])
}

func (c *Client) readCache(cpeName string) ([]CVEMatch, bool) {
	if c.CacheDir == "" {
		return nil, false
	}
	path := filepath.Join(c.CacheDir, c.cacheKey(cpeName)+".json")
	info, err := os.Stat(path)
	if err != nil {
		return nil, false
	}
	if time.Since(info.ModTime()) > c.CacheTTL {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var matches []CVEMatch
	if err := json.Unmarshal(data, &matches); err != nil {
		return nil, false
	}
	return matches, true
}

func (c *Client) writeCache(cpeName string, matches []CVEMatch) {
	if c.CacheDir == "" {
		return
	}
	_ = os.MkdirAll(c.CacheDir, 0o700)
	data, err := json.Marshal(matches)
	if err != nil {
		return
	}
	path := filepath.Join(c.CacheDir, c.cacheKey(cpeName)+".json")
	_ = os.WriteFile(path, data, 0o600)
}

// CPE22to23 converts a CPE 2.2 URI (as nmap/naabu and groma's banner
// fingerprinter produce) to the CPE 2.3 formatted string that the NVD
// API 2.0 requires. version is spliced into the version field; empty
// means wildcard.
//
//	"cpe:/a:openbsd:openssh", "8.9p1" → "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"
//	"cpe:/a:apache:http_server", ""   → "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
func CPE22to23(cpe22, version string) string {
	// Strip "cpe:/" prefix, split on ":"
	s := cpe22
	if strings.HasPrefix(s, "cpe:/") {
		s = s[5:]
	} else if strings.HasPrefix(s, "cpe:") {
		// Already looks like 2.3 — passthrough.
		if strings.HasPrefix(s, "cpe:2.3:") {
			return s
		}
		s = s[4:]
	}
	parts := strings.Split(s, ":")
	// CPE has: part, vendor, product, [version, update, edition, language]
	// Pad to 11 fields (part through other) with *
	for len(parts) < 11 {
		parts = append(parts, "*")
	}
	// If caller supplies a version and the CPE didn't have one, splice it in.
	if version != "" && (len(parts) < 4 || parts[3] == "*" || parts[3] == "") {
		parts[3] = version
	}
	return "cpe:2.3:" + strings.Join(parts[:11], ":")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
