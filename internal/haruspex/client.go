// Package haruspex is a thin, fail-open client for the Haruspex decision
// server (github.com/TyrusRC/haruspex), used to triage groma's own
// vulnerability-check hits before they're reported.
//
// Per Haruspex's own design (see its README "Integrating Haruspex into a
// scanner"): it is wired ONLY at the report/triage stage, never at probe or
// target selection, and it NEVER removes a candidate. A "no"/abstain means
// "not proven yet, keep it" — groma treats it exactly that way: triage only
// annotates a Finding with a Confidence/Triage label, it never drops one.
// If the server is unreachable, every call fails open — findings are
// reported exactly as they would be without Haruspex, just untriaged.
package haruspex

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/TyrusRC/groma/internal/core"
)

const (
	defaultBaseURL = "http://127.0.0.1:3000"
	defaultDomain  = "network" // falls back to the server's default adapter if unregistered (fail-open by design)
	defaultTimeout = 5 * time.Second
)

// Client calls a running Haruspex server's /v1/evaluate endpoint.
type Client struct {
	BaseURL string
	Domain  string
	Timeout time.Duration
	http    *http.Client
}

// NewClient returns a Client pointed at baseURL (empty = the default local
// server address). Safe to construct even when no server is running —
// every call degrades to a no-op error the caller can fail open on.
func NewClient(baseURL string) *Client {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Client{
		BaseURL: baseURL,
		Domain:  defaultDomain,
		Timeout: defaultTimeout,
		http:    &http.Client{Timeout: defaultTimeout},
	}
}

// Verdict is the triage answer for one finding. Accept/Abstain only carry
// meaning when a calibrator is loaded server-side; an uncalibrated server
// still returns Label/Probability, and Accept defaults to true (nothing to
// gate on) so a bare, uncalibrated Haruspex deployment doesn't look like it
// abstained on everything.
type Verdict struct {
	Label       string  // "yes" | "no"
	Probability float64 // P(yes) — "this is a real, reportable finding"
	Accept      bool    // calibrator-gated accept/abstain; true when uncalibrated
	Abstain     bool
	Source      string // e.g. "cve_lookup" when Haruspex deferred to a deterministic resolver
}

type evaluateRequest struct {
	Model     string                      `json:"model"`
	State     map[string]any              `json:"state"`
	Domain    string                      `json:"domain"`
	Questions map[string]evaluateQuestion `json:"questions"`
}

type evaluateQuestion struct {
	Type         string            `json:"type"`
	Instructions string            `json:"instructions"`
	Criteria     map[string]string `json:"criteria"`
}

type evaluateResponse struct {
	Domain  string                     `json:"domain"`
	Answers map[string]json.RawMessage `json:"answers"`
}

const questionName = "reportable"

// Ping does a cheap GET /health with a short, fixed timeout. Callers use it
// once before a batch of Triage calls so an absent server costs a single
// short probe, not c.Timeout per finding.
func (c *Client) Ping(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Triage asks Haruspex whether f looks like a real, reportable finding
// rather than noise (a stale version-match, a backport-patched banner, a
// mere service indicator). It never mutates f; callers decide what to do
// with the Verdict (groma's checks.Evaluate path records it on the
// Finding, never drops it).
func (c *Client) Triage(ctx context.Context, f *core.Finding) (*Verdict, error) {
	state := map[string]any{
		"title":       f.Title,
		"description": f.Description,
		"evidence":    f.Evidence,
		"service":     f.Service,
		"product":     f.Product,
		"version":     f.Version,
		"severity":    string(f.Severity),
		"cve":         f.Type,
	}
	req := evaluateRequest{
		Model:  "haruspex",
		State:  state,
		Domain: c.Domain,
		Questions: map[string]evaluateQuestion{
			questionName: {
				Type: "boolean",
				Instructions: "Is this a real, reportable network vulnerability finding — " +
					"not a stale or already-patched version match, and not mere service/" +
					"version banner noise?",
				Criteria: map[string]string{
					"true":  "the version/evidence genuinely matches a known vulnerable state",
					"false": "the evidence is a banner/recon artifact or a likely false match",
				},
			},
		},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("haruspex: encoding request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/evaluate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("haruspex: building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("haruspex: server unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("haruspex: server returned HTTP %d", resp.StatusCode)
	}

	var out evaluateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("haruspex: decoding response: %w", err)
	}
	raw, ok := out.Answers[questionName]
	if !ok {
		return nil, fmt.Errorf("haruspex: response missing %q answer", questionName)
	}
	var ans struct {
		Label       string  `json:"label"`
		Probability float64 `json:"probability"`
		Accept      *bool   `json:"accept"`
		Abstain     bool    `json:"abstain"`
		Source      string  `json:"source"`
		Error       string  `json:"error"`
	}
	if err := json.Unmarshal(raw, &ans); err != nil {
		return nil, fmt.Errorf("haruspex: decoding answer: %w", err)
	}
	if ans.Error != "" {
		return nil, fmt.Errorf("haruspex: %s", ans.Error)
	}
	accept := true // uncalibrated server: nothing to gate on, so default to accept
	if ans.Accept != nil {
		accept = *ans.Accept
	}
	return &Verdict{
		Label:       ans.Label,
		Probability: ans.Probability,
		Accept:      accept,
		Abstain:     ans.Abstain,
		Source:      ans.Source,
	}, nil
}

// TriageFindings annotates every finding in place with Confidence/Triage
// fields from Haruspex, skipping pure recon findings (open ports with no
// vuln classification — Haruspex is a report/triage layer, not a port
// filter). A finding the server can't reach, errors on, or abstains on is
// left exactly as it was: Triage stays empty, Confidence stays zero. This
// is the fail-open contract — a dead or absent Haruspex server must never
// cause a real finding to disappear from the report.
func TriageFindings(ctx context.Context, c *Client, findings core.Findings) {
	if !c.Ping(ctx) {
		return // fail open: server absent/unreachable, findings stay untriaged
	}
	for _, f := range findings {
		if f.Type == "open_port" || f.Severity == core.SeverityInfo {
			continue
		}
		v, err := c.Triage(ctx, f)
		if err != nil || v == nil {
			continue
		}
		if v.Abstain || !v.Accept {
			f.Triage = "unproven"
		} else if v.Label == "yes" {
			f.Triage = "confirmed"
		} else {
			f.Triage = "likely_noise"
		}
		f.Confidence = v.Probability
	}
}
