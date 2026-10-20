package creds

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fakeSMTPServer(t *testing.T, mode string, accepted Pair) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.Write([]byte("220 fake ESMTP\r\n"))
				r := bufio.NewReader(conn)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					cmd := strings.ToUpper(strings.TrimSpace(line))
					switch {
					case strings.HasPrefix(cmd, "EHLO"):
						if mode == "auth" {
							conn.Write([]byte("250-fake\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n"))
						} else {
							conn.Write([]byte("250-fake\r\n250 OK\r\n"))
						}
					case strings.HasPrefix(cmd, "AUTH PLAIN"):
						parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
						if len(parts) < 3 {
							conn.Write([]byte("535 Bad credentials\r\n"))
							continue
						}
						decoded, err := base64.StdEncoding.DecodeString(parts[2])
						if err != nil {
							conn.Write([]byte("535 Bad credentials\r\n"))
							continue
						}
						// \x00user\x00password
						fields := strings.SplitN(string(decoded), "\x00", 3)
						if len(fields) == 3 && fields[1] == accepted.User && fields[2] == accepted.Password {
							conn.Write([]byte("235 OK\r\n"))
						} else {
							conn.Write([]byte("535 Bad credentials\r\n"))
						}
					case strings.HasPrefix(cmd, "MAIL FROM"):
						conn.Write([]byte("250 OK\r\n"))
					case strings.HasPrefix(cmd, "RCPT TO"):
						if mode == "relay" {
							conn.Write([]byte("250 OK\r\n"))
						} else {
							conn.Write([]byte("550 Relay denied\r\n"))
						}
					case strings.HasPrefix(cmd, "RSET"):
						conn.Write([]byte("250 OK\r\n"))
					case strings.HasPrefix(cmd, "QUIT"):
						conn.Write([]byte("221 Bye\r\n"))
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestCheckSMTPAuthAccepted(t *testing.T) {
	accepted := Pair{User: "admin", Password: "password"}
	addr := fakeSMTPServer(t, "auth", accepted)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hit, err := CheckSMTP(ctx, host, port, []Pair{accepted})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil || hit.User != "admin" {
		t.Fatalf("expected hit for admin, got %+v", hit)
	}
}

func TestCheckSMTPAuthRejected(t *testing.T) {
	accepted := Pair{User: "admin", Password: "secret123"}
	addr := fakeSMTPServer(t, "auth", accepted)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hit, err := CheckSMTP(ctx, host, port, []Pair{{"admin", "wrong"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit != nil {
		t.Errorf("expected no hit, got %+v", hit)
	}
}

func TestCheckSMTPOpenRelay(t *testing.T) {
	addr := fakeSMTPServer(t, "relay", Pair{})
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hit, err := CheckSMTP(ctx, host, port, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected open relay hit")
	}
	if !strings.Contains(hit.Password, "open relay") {
		t.Errorf("expected open relay message, got %q", hit.Password)
	}
}
