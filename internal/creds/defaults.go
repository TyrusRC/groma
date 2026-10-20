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
// Pairs are sourced from SecLists' Default-Credentials and common vendor
// documentation (https://github.com/danielmiessler/SecLists), filtered
// to the most frequently seen vendor defaults.
var DefaultPairs = map[string][]Pair{
	"ssh": {
		{"root", "root"},
		{"root", "toor"},
		{"root", "password"},
		{"root", "calvin"},
		{"root", "alpine"},
		{"root", "default"},
		{"admin", "admin"},
		{"admin", "password"},
		{"ubuntu", "ubuntu"},
		{"pi", "raspberry"},
		{"vagrant", "vagrant"},
		{"ubnt", "ubnt"},
	},
	"ftp": {
		{"anonymous", "anonymous"},
		{"anonymous", ""},
		{"ftp", "ftp"},
		{"ftp", ""},
		{"ftpuser", "password"},
		{"admin", "admin"},
		{"admin", "password"},
	},
	"postgres": {
		{"postgres", "postgres"},
		{"postgres", "password"},
		{"postgres", "admin"},
		{"postgres", ""},
		{"postgres", "amber"},
		{"postgres", "123"},
		{"admin", "admin"},
	},
	"mysql": {
		{"root", ""},
		{"root", "root"},
		{"root", "mysql"},
		{"root", "password"},
		{"root", "123"},
		{"root", "toor"},
		{"root", "changeme"},
		{"admin", "admin"},
		{"dbuser", "123"},
	},
	"redis": {
		// Redis < 6 is password-only (no username). User="" means the
		// checker sends AUTH <password>; User="default" tries Redis 6+
		// ACL mode (AUTH default <password>) as a fallback.
		{"", "redis"},
		{"", "password"},
		{"", "foobared"},
		{"", "admin"},
		{"", "123456"},
		{"", "changeme"},
		{"default", "redis"},
		{"default", "password"},
		{"default", "foobared"},
	},
	"mongodb": {
		{"", ""},
	},
	"mssql": {
		{"sa", ""},
		{"sa", "sa"},
		{"sa", "password"},
		{"sa", "Password1"},
		{"sa", "Password123"},
		{"sa", "changeme"},
	},
	"vnc": {
		{"", "password"},
		{"", "1234"},
		{"", "admin"},
		{"", "vnc"},
		{"", "winterm"},
	},
	"ldap": {
		{"cn=admin,dc=example,dc=com", "admin"},
		{"cn=admin,dc=example,dc=com", "password"},
		{"cn=Manager,dc=example,dc=com", "secret"},
		{"admin", "admin"},
		{"admin", "password"},
	},
	"snmp": {
		{"", "public"},
		{"", "private"},
		{"", "community"},
		{"", "snmp"},
		{"", "default"},
	},
	"telnet": {
		{"root", "root"},
		{"root", ""},
		{"root", "password"},
		{"root", "admin"},
		{"admin", "admin"},
		{"admin", "password"},
		{"admin", "1234"},
		{"user", "user"},
	},
	"smtp": {
		{"admin", "admin"},
		{"admin", "password"},
		{"postmaster", "password"},
	},
	"memcached": {
		{"", ""},
	},
	// --- HTTP-based infrastructure services ---
	"elasticsearch": {
		{"", ""},
		{"elastic", "changeme"},
		{"elastic", "elastic"},
		{"admin", "admin"},
	},
	"couchdb": {
		{"admin", "admin"},
		{"admin", "password"},
		{"admin", ""},
	},
	"tomcat": {
		{"tomcat", "tomcat"},
		{"admin", "admin"},
		{"manager", "manager"},
		{"admin", "password"},
		{"tomcat", "s3cret"},
	},
	"jenkins": {
		{"", ""},
		{"admin", "admin"},
		{"admin", "password"},
		{"admin", "jenkins"},
	},
	"grafana": {
		{"admin", "admin"},
		{"admin", "password"},
		{"admin", "grafana"},
	},
	"rabbitmq": {
		{"guest", "guest"},
		{"admin", "admin"},
		{"rabbitmq", "rabbitmq"},
	},
	"docker": {
		{"", ""},
	},
	"kubernetes": {
		{"", ""},
	},
	"consul": {
		{"", ""},
	},
	"minio": {
		{"minioadmin", "minioadmin"},
		{"minio", "minio123"},
		{"admin", "password"},
	},
	"portainer": {
		{"", ""},
		{"admin", "admin"},
		{"admin", "password"},
	},
	"traefik": {
		{"", ""},
	},
	"prometheus": {
		{"", ""},
	},
	"harbor": {
		{"admin", "Harbor12345"},
		{"admin", "admin"},
		{"admin", "password"},
	},
	"argocd": {
		{"admin", "admin"},
		{"admin", "argocd"},
		{"admin", "password"},
	},
	"gitea": {
		{"", ""},
		{"gitea", "gitea"},
		{"admin", "admin"},
	},
	// --- AI/ML & modern "vibe coder" services ---
	"jupyter": {
		{"", ""},
		{"", "jupyter"},
		{"", "password"},
	},
	"ollama": {
		{"", ""},
	},
	"chromadb": {
		{"", ""},
	},
	"qdrant": {
		{"", ""},
		{"", "qdrant"},
		{"", "password"},
	},
	"airflow": {
		{"airflow", "airflow"},
		{"admin", "admin"},
		{"admin", "password"},
	},
	"metabase": {
		{"", ""},
		{"admin@metabase.local", "metabot1"},
	},
	"n8n": {
		{"", ""},
		{"admin", "admin"},
	},
	"mlflow": {
		{"", ""},
	},
	"weaviate": {
		{"", ""},
	},
	"keycloak": {
		{"admin", "admin"},
		{"admin", "password"},
		{"admin", "Pa55w0rd"},
	},
	"neo4j": {
		{"neo4j", "neo4j"},
		{"neo4j", "password"},
		{"neo4j", "admin"},
	},
	"influxdb": {
		{"", ""},
		{"admin", "admin"},
		{"admin", "password"},
	},
}

func init() {
	DefaultPairs["sftp"] = DefaultPairs["ssh"]
	DefaultPairs["postgresql"] = DefaultPairs["postgres"]
	DefaultPairs["mariadb"] = DefaultPairs["mysql"]
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
	// Wire protocols
	"ssh":        CheckSSH,
	"sftp":       CheckSSH,
	"ftp":        CheckFTP,
	"postgres":   CheckPostgres,
	"postgresql": CheckPostgres,
	"mysql":      CheckMySQL,
	"mariadb":    CheckMySQL,
	"redis":      CheckRedis,
	"mongodb":    CheckMongoDB,
	// Wire protocols (new)
	"mssql":     CheckMSSQL,
	"telnet":    CheckTelnet,
	"smtp":      CheckSMTP,
	"memcached": CheckMemcached,
	"snmp":      CheckSNMP,
	"vnc":       CheckVNC,
	"ldap":      CheckLDAP,
	// HTTP-based services (generic framework)
	"elasticsearch": CheckHTTPService("elasticsearch"),
	"couchdb":       CheckHTTPService("couchdb"),
	"tomcat":        CheckHTTPService("tomcat"),
	"jenkins":       CheckHTTPService("jenkins"),
	"grafana":       CheckHTTPService("grafana"),
	"rabbitmq":      CheckHTTPService("rabbitmq"),
	"docker":        CheckHTTPService("docker"),
	"kubernetes":    CheckHTTPService("kubernetes"),
	"consul":        CheckHTTPService("consul"),
	"minio":         CheckHTTPService("minio"),
	"portainer":     CheckHTTPService("portainer"),
	"traefik":       CheckHTTPService("traefik"),
	"prometheus":    CheckHTTPService("prometheus"),
	"harbor":        CheckHTTPService("harbor"),
	"argocd":        CheckHTTPService("argocd"),
	"gitea":         CheckHTTPService("gitea"),
	"jupyter":       CheckHTTPService("jupyter"),
	"ollama":        CheckHTTPService("ollama"),
	"chromadb":      CheckHTTPService("chromadb"),
	"qdrant":        CheckHTTPService("qdrant"),
	"airflow":       CheckHTTPService("airflow"),
	"metabase":      CheckHTTPService("metabase"),
	"n8n":           CheckHTTPService("n8n"),
	"mlflow":        CheckHTTPService("mlflow"),
	"weaviate":      CheckHTTPService("weaviate"),
	"keycloak":      CheckHTTPService("keycloak"),
	"neo4j":         CheckHTTPService("neo4j"),
	"influxdb":      CheckHTTPService("influxdb"),
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
