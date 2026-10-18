// Package creds implements groma's default/weak-credential check — the
// same "does this service still have its vendor default password"
// control test Nessus/OpenVAS ship as a plugin family.
//
// This is a BOUNDED, opt-in control test, not a brute-force or
// credential-stuffing attack: each service gets a short, curated list of
// well-known default pairs (vendor defaults, not a dictionary), the
// first accepted pair stops the probe immediately, and every attempt is
// rate-limited. The goal is "prove the control is absent," the same
// distinction Praetor's hunting rules draw between auth-control testing
// (in scope) and account takeover brute force (not).
package creds

import (
	"context"
	"time"
)

// Pair is one username/password combination to try.
type Pair struct {
	User     string
	Password string
}

// DefaultPairs is the curated, intentionally short list of vendor/common
// default credentials per service. Each list is small on purpose — this
// checks for well-known defaults left unchanged, not a password spray.
var DefaultPairs = map[string][]Pair{
	"ssh": {
		{"root", "root"},
		{"root", "toor"},
		{"root", "password"},
		{"admin", "admin"},
		{"admin", "password"},
		{"ubuntu", "ubuntu"},
		{"pi", "raspberry"},
	},
	"ftp": {
		{"anonymous", "anonymous"},
		{"anonymous", ""},
		{"ftp", "ftp"},
		{"admin", "admin"},
		{"admin", "password"},
	},
	"postgres": {
		{"postgres", "postgres"},
		{"postgres", "password"},
		{"postgres", "admin"},
		{"postgres", ""},
		{"admin", "admin"},
	},
}

func init() {
	// sftp is a subsystem of SSH, not a separate auth protocol — a weak
	// SSH credential grants file access the same way, so it reuses the
	// same checker and pair list rather than a parallel implementation.
	DefaultPairs["sftp"] = DefaultPairs["ssh"]
	// naabu/nmap-services fingerprints PostgreSQL's port as "postgresql".
	DefaultPairs["postgresql"] = DefaultPairs["postgres"]
}

// Hit is a confirmed default-credential finding.
type Hit struct {
	Service  string
	User     string
	Password string
}

// attemptDelay is the pause between individual login attempts — gentle
// by default, never a flood (CLAUDE.md: "no abusive code").
const attemptDelay = 300 * time.Millisecond

// Checker probes one service with a bounded set of default credentials
// and stops at the first success. host/port name the target; attempts is
// the pair list to try (normally DefaultPairs[service]).
type Checker func(ctx context.Context, host string, port int, attempts []Pair) (*Hit, error)

// Checkers maps a fingerprinted service name (as naabu/the native
// scanner reports it) to its default-credential prober. A service not in
// this map is simply skipped — not every protocol groma can fingerprint
// has a check implemented yet (e.g. MySQL's native auth handshake);
// adding one is a new entry here plus a new prober file, not an
// architecture change.
var Checkers = map[string]Checker{
	"ssh":        CheckSSH,
	"sftp":       CheckSSH,
	"ftp":        CheckFTP,
	"postgres":   CheckPostgres,
	"postgresql": CheckPostgres,
}

// Check runs the registered checker for service, if any. A nil, nil
// result means "no checker for this service" — not "no default creds
// found" — callers must not conflate the two.
func Check(ctx context.Context, service, host string, port int) (*Hit, error) {
	checker, ok := Checkers[service]
	if !ok {
		return nil, nil
	}
	pairs, ok := DefaultPairs[service]
	if !ok || len(pairs) == 0 {
		return nil, nil
	}
	return checker(ctx, host, port, pairs)
}

func sleepBetweenAttempts(ctx context.Context) error {
	select {
	case <-time.After(attemptDelay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
