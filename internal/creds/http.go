package creds

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const httpDialTimeout = 5 * time.Second

// httpServiceDef describes an HTTP-based service's auth check.
type httpServiceDef struct {
	Service string

	// No-auth detection: GET this path; if status is in NoAuthCodes and
	// (NoAuthBody=="" or body contains NoAuthBody), no auth is required.
	NoAuthPath  string
	NoAuthCodes []int
	NoAuthBody  string

	// Credential check method.
	AuthMethod string // "basic", "json", "form", "bearer", "header"
	AuthPath   string
	AuthHeader string // for "header" method: custom header name (e.g. "X-Api-Key")

	// For "json" method: template with %s for user and password.
	JSONTemplate string
	// Success detection for credential checks.
	SuccessCodes []int
	SuccessBody  string // substring match
	// Failure detection (some APIs return 200 with error in body).
	FailBody string
}

// httpServices defines every HTTP-based service groma can check.
var httpServices = map[string]httpServiceDef{
	"elasticsearch": {
		Service: "elasticsearch", NoAuthPath: "/", NoAuthCodes: []int{200}, NoAuthBody: "cluster_name",
		AuthMethod: "basic", AuthPath: "/", SuccessCodes: []int{200}, SuccessBody: "cluster_name",
	},
	"couchdb": {
		Service: "couchdb", NoAuthPath: "/_all_dbs", NoAuthCodes: []int{200},
		AuthMethod: "basic", AuthPath: "/_session", SuccessCodes: []int{200},
	},
	"tomcat": {
		Service: "tomcat",
		AuthMethod: "basic", AuthPath: "/manager/html", SuccessCodes: []int{200}, SuccessBody: "Tomcat",
	},
	"jenkins": {
		Service: "jenkins", NoAuthPath: "/api/json", NoAuthCodes: []int{200}, NoAuthBody: "Jenkins",
		AuthMethod: "basic", AuthPath: "/api/json", SuccessCodes: []int{200}, SuccessBody: "Jenkins",
	},
	"grafana": {
		Service:    "grafana",
		AuthMethod: "json", AuthPath: "/api/login", JSONTemplate: `{"user":"%s","password":"%s"}`,
		SuccessCodes: []int{200}, SuccessBody: "Logged in",
	},
	"rabbitmq": {
		Service: "rabbitmq",
		AuthMethod: "basic", AuthPath: "/api/overview", SuccessCodes: []int{200}, SuccessBody: "cluster_name",
	},
	"docker": {
		Service: "docker", NoAuthPath: "/_ping", NoAuthCodes: []int{200}, NoAuthBody: "OK",
	},
	"kubernetes": {
		Service: "kubernetes", NoAuthPath: "/api", NoAuthCodes: []int{200}, NoAuthBody: "versions",
	},
	"consul": {
		Service: "consul", NoAuthPath: "/v1/agent/self", NoAuthCodes: []int{200}, NoAuthBody: "Config",
	},
	"minio": {
		Service: "minio",
		AuthMethod: "json", AuthPath: "/minio/login", JSONTemplate: `{"accessKey":"%s","secretKey":"%s"}`,
		SuccessCodes: []int{200}, SuccessBody: "token",
	},
	"portainer": {
		Service: "portainer", NoAuthPath: "/api/status", NoAuthCodes: []int{200},
		AuthMethod: "json", AuthPath: "/api/auth", JSONTemplate: `{"username":"%s","password":"%s"}`,
		SuccessCodes: []int{200}, SuccessBody: "jwt",
	},
	"traefik": {
		Service: "traefik", NoAuthPath: "/api/overview", NoAuthCodes: []int{200}, NoAuthBody: "http",
	},
	"prometheus": {
		Service: "prometheus", NoAuthPath: "/api/v1/status/config", NoAuthCodes: []int{200}, NoAuthBody: "status",
	},
	"harbor": {
		Service:    "harbor",
		AuthMethod: "basic", AuthPath: "/api/v2.0/users/current", SuccessCodes: []int{200}, SuccessBody: "username",
	},
	"argocd": {
		Service:    "argocd",
		AuthMethod: "json", AuthPath: "/api/v1/session", JSONTemplate: `{"username":"%s","password":"%s"}`,
		SuccessCodes: []int{200}, SuccessBody: "token",
	},
	"gitea": {
		Service: "gitea", NoAuthPath: "/api/v1/settings/api", NoAuthCodes: []int{200},
		AuthMethod: "basic", AuthPath: "/api/v1/user", SuccessCodes: []int{200}, SuccessBody: "login",
	},
	"jupyter": {
		Service: "jupyter", NoAuthPath: "/api/kernels", NoAuthCodes: []int{200},
		AuthMethod: "header", AuthPath: "/api/kernels", AuthHeader: "Authorization",
		SuccessCodes: []int{200},
	},
	"ollama": {
		Service: "ollama", NoAuthPath: "/api/tags", NoAuthCodes: []int{200}, NoAuthBody: "models",
	},
	"chromadb": {
		Service: "chromadb", NoAuthPath: "/api/v1/heartbeat", NoAuthCodes: []int{200},
	},
	"qdrant": {
		Service: "qdrant", NoAuthPath: "/collections", NoAuthCodes: []int{200}, NoAuthBody: "result",
		AuthMethod: "header", AuthPath: "/collections", AuthHeader: "api-key",
		SuccessCodes: []int{200}, SuccessBody: "result",
	},
	"airflow": {
		Service: "airflow",
		AuthMethod: "basic", AuthPath: "/api/v1/dags", SuccessCodes: []int{200}, SuccessBody: "dags",
	},
	"metabase": {
		Service: "metabase", NoAuthPath: "/api/session/properties", NoAuthCodes: []int{200},
		AuthMethod: "json", AuthPath: "/api/session", JSONTemplate: `{"username":"%s","password":"%s"}`,
		SuccessCodes: []int{200}, SuccessBody: "id",
	},
	"n8n": {
		Service: "n8n", NoAuthPath: "/api/v1/workflows", NoAuthCodes: []int{200},
		AuthMethod: "basic", AuthPath: "/api/v1/workflows", SuccessCodes: []int{200},
	},
	"mlflow": {
		Service: "mlflow", NoAuthPath: "/api/2.0/mlflow/experiments/search", NoAuthCodes: []int{200},
	},
	"weaviate": {
		Service: "weaviate", NoAuthPath: "/v1/meta", NoAuthCodes: []int{200}, NoAuthBody: "version",
	},
	"keycloak": {
		Service:    "keycloak",
		AuthMethod: "form", AuthPath: "/realms/master/protocol/openid-connect/token",
		SuccessCodes: []int{200}, SuccessBody: "access_token",
	},
	"neo4j": {
		Service:    "neo4j",
		AuthMethod: "basic", AuthPath: "/db/neo4j/tx", SuccessCodes: []int{200},
	},
	"influxdb": {
		Service: "influxdb", NoAuthPath: "/api/v2/authorizations", NoAuthCodes: []int{200},
		AuthMethod: "basic", AuthPath: "/api/v2/authorizations", SuccessCodes: []int{200},
	},
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: httpDialTimeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
			DialContext: (&net.Dialer{Timeout: httpDialTimeout}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

// CheckHTTPService is the generic checker for HTTP-based services.
func CheckHTTPService(svcName string) Checker {
	return func(ctx context.Context, host string, port int, attempts []Pair) (*Hit, error) {
		def, ok := httpServices[svcName]
		if !ok {
			return nil, nil
		}
		scheme := "http"
		if port == 443 || port == 8443 || port == 9443 {
			scheme = "https"
		}
		base := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, fmt.Sprintf("%d", port)))
		client := newHTTPClient()

		// Phase 1: no-auth detection.
		if def.NoAuthPath != "" {
			if noAuth, _ := httpCheckNoAuth(ctx, client, base, def); noAuth {
				return &Hit{
					Service:  def.Service,
					User:     "",
					Password: "(none — no authentication required)",
				}, nil
			}
		}

		// Phase 2: credential check.
		if def.AuthMethod == "" {
			return nil, nil
		}
		for i, p := range attempts {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			ok, err := httpTryAuth(ctx, client, base, def, p)
			if err != nil {
				return nil, fmt.Errorf("creds: %s %s: %w", def.Service, base, err)
			}
			if ok {
				return &Hit{Service: def.Service, User: p.User, Password: p.Password}, nil
			}
			if i < len(attempts)-1 {
				if err := sleepBetweenAttempts(ctx); err != nil {
					return nil, err
				}
			}
		}
		return nil, nil
	}
}

func httpCheckNoAuth(ctx context.Context, client *http.Client, base string, def httpServiceDef) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+def.NoAuthPath, nil)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	for _, code := range def.NoAuthCodes {
		if resp.StatusCode == code {
			if def.NoAuthBody == "" || strings.Contains(string(body), def.NoAuthBody) {
				return true, nil
			}
		}
	}
	return false, nil
}

func httpTryAuth(ctx context.Context, client *http.Client, base string, def httpServiceDef, p Pair) (bool, error) {
	var req *http.Request
	var err error

	switch def.AuthMethod {
	case "basic":
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, base+def.AuthPath, nil)
		if err != nil {
			return false, err
		}
		req.SetBasicAuth(p.User, p.Password)

	case "json":
		payload := fmt.Sprintf(def.JSONTemplate, p.User, p.Password)
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, base+def.AuthPath, strings.NewReader(payload))
		if err != nil {
			return false, err
		}
		req.Header.Set("Content-Type", "application/json")

	case "form":
		formData := fmt.Sprintf("grant_type=password&username=%s&password=%s&client_id=admin-cli",
			p.User, p.Password)
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, base+def.AuthPath, strings.NewReader(formData))
		if err != nil {
			return false, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	case "header":
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, base+def.AuthPath, nil)
		if err != nil {
			return false, err
		}
		if def.AuthHeader == "Authorization" {
			req.Header.Set("Authorization", "token "+p.Password)
		} else {
			req.Header.Set(def.AuthHeader, p.Password)
		}

	case "bearer":
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, base+def.AuthPath, nil)
		if err != nil {
			return false, err
		}
		req.Header.Set("Authorization", "Bearer "+p.Password)

	default:
		return false, nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	bodyStr := string(body)

	if def.FailBody != "" && strings.Contains(bodyStr, def.FailBody) {
		return false, nil
	}

	for _, code := range def.SuccessCodes {
		if resp.StatusCode == code {
			if def.SuccessBody == "" || strings.Contains(bodyStr, def.SuccessBody) {
				return true, nil
			}
		}
	}
	return false, nil
}

// jsonEscape escapes a string for safe embedding in a JSON template.
func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	// Strip surrounding quotes.
	return string(b[1 : len(b)-1])
}

// base64Plain encodes user+password as SMTP AUTH PLAIN: \x00user\x00password.
func base64Plain(user, password string) string {
	plain := "\x00" + user + "\x00" + password
	return base64.StdEncoding.EncodeToString([]byte(plain))
}
