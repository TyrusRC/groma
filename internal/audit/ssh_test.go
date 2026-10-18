package audit

import (
	"context"
	"testing"
)

func TestParsePackageList(t *testing.T) {
	raw := "openssl\t1.1.1f\nopenssh-server\t8.2p1-4ubuntu0.5\n\nmalformed-line-no-tab\n"
	pkgs := parsePackageList(raw)

	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages (malformed/blank lines skipped), got %d: %+v", len(pkgs), pkgs)
	}
	if pkgs["openssl"] != "1.1.1f" {
		t.Errorf("expected openssl=1.1.1f, got %q", pkgs["openssl"])
	}
	if pkgs["openssh-server"] != "8.2p1-4ubuntu0.5" {
		t.Errorf("expected openssh-server=8.2p1-4ubuntu0.5, got %q", pkgs["openssh-server"])
	}
}

func TestAuthMethodsEmptyWithoutCredsOrAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	methods, err := authMethods(Credentials{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 0 {
		t.Errorf("expected no auth methods with no password/key/agent, got %d", len(methods))
	}
}

func TestAuthMethodsPasswordOnly(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	methods, err := authMethods(Credentials{User: "svc", Password: "hunter2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 1 {
		t.Errorf("expected exactly 1 auth method (password), got %d", len(methods))
	}
}

func TestAuthMethodsBadKeyPathErrors(t *testing.T) {
	_, err := authMethods(Credentials{User: "svc", PrivateKeyPath: "/nonexistent/path/to/key"})
	if err == nil {
		t.Fatal("expected an error for a private key path that doesn't exist")
	}
}

func TestHostKeyCallbackInsecureOptOutIsExplicit(t *testing.T) {
	cb, err := hostKeyCallback(Options{InsecureSkipHostKeyVerify: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cb == nil {
		t.Fatal("expected a non-nil callback")
	}
}

func TestHostKeyCallbackDefaultsToKnownHostsVerification(t *testing.T) {
	// A bogus known_hosts path should fail to load rather than silently
	// falling back to an insecure callback — fail closed, not fail open.
	_, err := hostKeyCallback(Options{KnownHostsPath: "/nonexistent/known_hosts"})
	if err == nil {
		t.Fatal("expected an error when known_hosts can't be loaded and insecure mode wasn't requested")
	}
}

func TestQueryRejectsMissingUser(t *testing.T) {
	_, err := Query(context.Background(), "127.0.0.1", Credentials{}, Options{InsecureSkipHostKeyVerify: true})
	if err == nil {
		t.Fatal("expected an error when no credentials/user are configured at all")
	}
}
