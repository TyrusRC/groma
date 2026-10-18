package haruspex

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TyrusRC/groma/internal/core"
)

func newFakeServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestTriageFindingsAnnotatesConfirmed(t *testing.T) {
	srv := newFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/v1/evaluate":
			json.NewEncoder(w).Encode(map[string]any{
				"domain": "network",
				"answers": map[string]any{
					"reportable": map[string]any{"label": "yes", "probability": 0.93},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	f := core.NewFinding("CVE-2021-41773-apache-path-traversal", core.SeverityHigh)
	findings := core.Findings{f}
	TriageFindings(context.Background(), NewClient(srv.URL), findings)

	if f.Triage != "confirmed" {
		t.Errorf("expected Triage=confirmed, got %q", f.Triage)
	}
	if f.Confidence != 0.93 {
		t.Errorf("expected Confidence=0.93, got %v", f.Confidence)
	}
}

func TestTriageFindingsSkipsOpenPortRecon(t *testing.T) {
	called := false
	srv := newFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		called = true
		w.WriteHeader(http.StatusOK)
	})

	f := core.NewFinding("open_port", core.SeverityInfo)
	TriageFindings(context.Background(), NewClient(srv.URL), core.Findings{f})

	if called {
		t.Errorf("expected open_port/info findings to never be sent to Haruspex (it's a report/triage layer, not a port filter)")
	}
	if f.Triage != "" {
		t.Errorf("expected untriaged recon finding to stay untriaged, got %q", f.Triage)
	}
}

func TestTriageFindingsFailsOpenWhenServerUnreachable(t *testing.T) {
	f := core.NewFinding("CVE-2021-41773-apache-path-traversal", core.SeverityHigh)
	f.Title = "Apache path traversal"
	findings := core.Findings{f}

	// No server at all — NewClient points at a dead port.
	TriageFindings(context.Background(), NewClient("http://127.0.0.1:1"), findings)

	if f.Triage != "" || f.Confidence != 0 {
		t.Errorf("expected finding to be left exactly as-is when Haruspex is unreachable (fail-open), got Triage=%q Confidence=%v", f.Triage, f.Confidence)
	}
	if f.Title != "Apache path traversal" {
		t.Errorf("fail-open must never mutate the finding beyond Triage/Confidence")
	}
}

func TestTriageFindingsMarksAbstainAsUnproven(t *testing.T) {
	srv := newFakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/v1/evaluate":
			accept := false
			json.NewEncoder(w).Encode(map[string]any{
				"domain": "network",
				"answers": map[string]any{
					"reportable": map[string]any{
						"label": "no", "probability": 0.4, "abstain": true, "accept": accept,
					},
				},
			})
		}
	})

	f := core.NewFinding("CVE-2021-41773-apache-path-traversal", core.SeverityHigh)
	TriageFindings(context.Background(), NewClient(srv.URL), core.Findings{f})

	if f.Triage != "unproven" {
		t.Errorf("an abstained/rejected verdict must never read as ruled-out noise — expected unproven, got %q", f.Triage)
	}
}
