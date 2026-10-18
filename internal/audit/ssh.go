// Package audit implements groma's credentialed/local check pass — the
// other half of what makes a scanner "Nessus-class": SSH into a host,
// enumerate its installed packages, and feed (name, version) pairs
// through the SAME version-match engine (internal/checks) that drives
// groma's remote, unauthenticated checks.
//
// This is deliberately NOT a second matching engine. A credentialed check
// is a different INPUT SOURCE for an Observation (internal/checks), not a
// different kind of check — the laziness win here is recognizing that and
// not building parallel YAML/version-comparison logic for it. Point a
// check's `service.product` at a package name (e.g. "openssl",
// "openssh-server") instead of a naabu-fingerprinted service and it works
// unchanged.
//
// Scope: Linux targets only, via dpkg (Debian/Ubuntu) or rpm (RHEL/
// CentOS/Fedora) package queries over SSH. Windows/WinRM and other Linux
// package managers (pacman, apk, ...) are a parser addition, not an
// architecture change — add a probe function and a case in Query, nothing
// else moves.
package audit

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/TyrusRC/groma/internal/checks"
)

// Credentials for an SSH credentialed audit. Populated from environment
// variables ONLY — never from a CLI flag, which would leak a secret into
// the process list and shell history. See CredentialsFromEnv.
type Credentials struct {
	User                 string
	Password             string // GROMA_SSH_PASSWORD
	PrivateKeyPath       string // GROMA_SSH_KEY
	PrivateKeyPassphrase string // GROMA_SSH_KEY_PASSPHRASE
}

// CredentialsFromEnv reads SSH credentials from environment variables.
// GROMA_SSH_USER is required for an audit to run; everything else is
// optional (an SSH agent, if reachable via SSH_AUTH_SOCK, needs neither
// a password nor a key path from groma at all — the preferred mode).
func CredentialsFromEnv() Credentials {
	return Credentials{
		User:                 os.Getenv("GROMA_SSH_USER"),
		Password:             os.Getenv("GROMA_SSH_PASSWORD"),
		PrivateKeyPath:       os.Getenv("GROMA_SSH_KEY"),
		PrivateKeyPassphrase: os.Getenv("GROMA_SSH_KEY_PASSPHRASE"),
	}
}

// Options for an SSH credentialed audit run.
type Options struct {
	Port int // default 22

	// KnownHostsPath points at an OpenSSH-format known_hosts file used to
	// verify the target's host key. Empty = "~/.ssh/known_hosts". A host
	// not in it is REJECTED by default (fail closed) — set
	// InsecureSkipHostKeyVerify to bypass for a first-connect/lab target,
	// same trade-off as `ssh -o StrictHostKeyChecking=no`, opt-in only.
	KnownHostsPath            string
	InsecureSkipHostKeyVerify bool

	DialTimeout time.Duration // default 10s
}

func (o Options) withDefaults() Options {
	if o.Port == 0 {
		o.Port = 22
	}
	if o.DialTimeout == 0 {
		o.DialTimeout = 10 * time.Second
	}
	return o
}

// Dial opens an authenticated SSH connection to host, using the same
// credential/host-key policy as Query. Exported so other credentialed
// passes (internal/compliance) can share one connection across many
// commands instead of paying a fresh handshake per command.
func Dial(ctx context.Context, host string, creds Credentials, opts Options) (*ssh.Client, error) {
	opts = opts.withDefaults()

	hostKeyCB, err := hostKeyCallback(opts)
	if err != nil {
		return nil, fmt.Errorf("audit: host key verification: %w", err)
	}

	auths, err := authMethods(creds)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	if len(auths) == 0 {
		return nil, fmt.Errorf("audit: no credentials available (set GROMA_SSH_USER and either GROMA_SSH_PASSWORD, GROMA_SSH_KEY, or run an ssh-agent)")
	}
	if creds.User == "" {
		return nil, fmt.Errorf("audit: GROMA_SSH_USER is not set")
	}

	conf := &ssh.ClientConfig{
		User:            creds.User,
		Auth:            auths,
		HostKeyCallback: hostKeyCB,
		Timeout:         opts.DialTimeout,
	}

	dialCtx, cancel := context.WithTimeout(ctx, opts.DialTimeout)
	defer cancel()
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", opts.Port))
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("audit: dialing %s: %w", addr, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, conf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("audit: SSH handshake with %s: %w", addr, err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// Query SSHes into host and returns one checks.Observation per installed
// package it could enumerate. Protocol is always "local" on the returned
// observations (distinguishes a credentialed hit from a naabu/network
// one in reporting) and Port is 0 (not meaningful for a package).
func Query(ctx context.Context, host string, creds Credentials, opts Options) ([]checks.Observation, error) {
	client, err := Dial(ctx, host, creds, opts)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	pkgs, pm, err := queryPackages(client)
	if err != nil {
		return nil, fmt.Errorf("audit: %s: %w", host, err)
	}

	obs := make([]checks.Observation, 0, len(pkgs))
	for name, version := range pkgs {
		obs = append(obs, checks.Observation{
			Host:     host,
			Protocol: "local",
			Product:  name,
			Version:  version,
		})
	}
	_ = pm // kept for future per-manager findings metadata; not surfaced yet
	return obs, nil
}

// authMethods builds, in priority order: an explicit private key, an
// explicit password, then a running ssh-agent. All available methods are
// offered to the server (standard SSH client behavior) rather than
// guessing which one the server wants.
func authMethods(creds Credentials) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	if creds.PrivateKeyPath != "" {
		keyBytes, err := os.ReadFile(creds.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("reading private key %s: %w", creds.PrivateKeyPath, err)
		}
		var signer ssh.Signer
		if creds.PrivateKeyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(creds.PrivateKeyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(keyBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("parsing private key %s: %w", creds.PrivateKeyPath, err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if creds.Password != "" {
		methods = append(methods, ssh.Password(creds.Password))
	}

	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if agentConn, err := net.Dial("unix", sock); err == nil {
			ag := agent.NewClient(agentConn)
			methods = append(methods, ssh.PublicKeysCallback(ag.Signers))
		}
	}

	return methods, nil
}

// hostKeyCallback builds a knownhosts-backed verifier by default (fails
// closed on an unrecognized or changed host key — the same property TLS
// verification gives HTTPS). InsecureSkipHostKeyVerify is an explicit,
// loud opt-out for a first-connect or lab target.
func hostKeyCallback(opts Options) (ssh.HostKeyCallback, error) {
	if opts.InsecureSkipHostKeyVerify {
		fmt.Fprintln(os.Stderr, "groma: WARNING: SSH host key verification disabled (--ssh-insecure-host-key) — vulnerable to MITM, use only against a known lab/first-connect target")
		return ssh.InsecureIgnoreHostKey(), nil
	}
	path := opts.KnownHostsPath
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolving home directory for known_hosts: %w", err)
		}
		path = home + "/.ssh/known_hosts"
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("loading known_hosts %s (pass --ssh-insecure-host-key to bypass for a trusted lab target): %w", path, err)
	}
	return cb, nil
}

// queryPackages runs ONE fixed, non-interpolated command per package
// manager probe — never a string built from caller input, so there is no
// command-injection surface. dpkg is tried first (Debian/Ubuntu), then
// rpm (RHEL/CentOS/Fedora/SUSE).
func queryPackages(client *ssh.Client) (map[string]string, string, error) {
	if out, err := runCommand(client, `dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null`); err == nil && strings.TrimSpace(out) != "" {
		return parsePackageList(out), "dpkg", nil
	}
	if out, err := runCommand(client, `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null`); err == nil && strings.TrimSpace(out) != "" {
		return parsePackageList(out), "rpm", nil
	}
	return nil, "", fmt.Errorf("no supported package manager found (tried dpkg-query, rpm)")
}

func runCommand(client *ssh.Client, cmd string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("opening SSH session: %w", err)
	}
	defer session.Close()
	out, err := session.CombinedOutput(cmd)
	return string(out), err
}

// parsePackageList parses "name\tversion\n" lines. Malformed lines are
// skipped, not fatal.
func parsePackageList(raw string) map[string]string {
	pkgs := make(map[string]string)
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		name, version, ok := strings.Cut(line, "\t")
		if !ok || name == "" || version == "" {
			continue
		}
		pkgs[name] = version
	}
	return pkgs
}
