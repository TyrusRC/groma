package creds

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHTTPServiceNoAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"cluster_name":"test"}`))
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portStr)

	checker := CheckHTTPService("elasticsearch")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hit, err := checker(ctx, host, port, DefaultPairs["elasticsearch"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected a hit for no-auth elasticsearch")
	}
	if !strings.Contains(hit.Password, "no authentication") {
		t.Errorf("expected no-auth message, got %q", hit.Password)
	}
}

func TestHTTPServiceBasicAuth(t *testing.T) {
	accepted := Pair{User: "admin", Password: "Harbor12345"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != accepted.User || pass != accepted.Password {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"username":"admin"}`))
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portStr)

	checker := CheckHTTPService("harbor")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hit, err := checker(ctx, host, port, DefaultPairs["harbor"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected a hit for harbor default creds")
	}
	if hit.User != "admin" || hit.Password != "Harbor12345" {
		t.Errorf("expected admin/Harbor12345, got %s/%s", hit.User, hit.Password)
	}
}

func TestHTTPServiceJSONAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/login" {
			// Accept admin/admin
			w.Write([]byte(`{"message":"Logged in"}`))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portStr)

	checker := CheckHTTPService("grafana")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hit, err := checker(ctx, host, port, DefaultPairs["grafana"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected a hit for grafana default creds")
	}
}

func TestHTTPServiceNoHit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized"))
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portStr)

	checker := CheckHTTPService("harbor")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hit, err := checker(ctx, host, port, DefaultPairs["harbor"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit != nil {
		t.Errorf("expected no hit, got %+v", hit)
	}
}

func TestHTTPServiceUnknownReturnsNil(t *testing.T) {
	checker := CheckHTTPService("nonexistent_service")
	hit, err := checker(context.Background(), "127.0.0.1", 9999, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit != nil {
		t.Errorf("expected nil for unknown service, got %+v", hit)
	}
}

func TestHTTPServiceDockerNoAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_ping" {
			w.Write([]byte("OK"))
		}
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portStr)

	checker := CheckHTTPService("docker")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hit, err := checker(ctx, host, port, DefaultPairs["docker"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected no-auth hit for docker")
	}
}

func TestHTTPServiceOllamaNoAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.Write([]byte(`{"models":[]}`))
		}
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portStr)

	checker := CheckHTTPService("ollama")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hit, err := checker(ctx, host, port, DefaultPairs["ollama"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected no-auth hit for ollama")
	}
}
