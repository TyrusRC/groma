package creds

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeRedisServer accepts connections and handles PING / AUTH commands.
// If requireAuth is non-empty, PING returns -NOAUTH and AUTH checks the
// password. If requireAuth is empty, PING returns +PONG (no-auth mode).
func fakeRedisServer(t *testing.T, requireAuth string) string {
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
				r := bufio.NewReader(conn)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimSpace(line)
					parts := strings.Fields(line)
					if len(parts) == 0 {
						continue
					}
					cmd := strings.ToUpper(parts[0])
					switch cmd {
					case "PING":
						if requireAuth != "" {
							conn.Write([]byte("-NOAUTH Authentication required\r\n"))
						} else {
							conn.Write([]byte("+PONG\r\n"))
						}
					case "AUTH":
						if requireAuth == "" {
							conn.Write([]byte("-ERR Client sent AUTH, but no password is set\r\n"))
						} else if len(parts) == 2 && parts[1] == requireAuth {
							conn.Write([]byte("+OK\r\n"))
						} else if len(parts) == 3 && parts[2] == requireAuth {
							conn.Write([]byte("+OK\r\n"))
						} else {
							conn.Write([]byte("-ERR invalid password\r\n"))
						}
					default:
						conn.Write([]byte("-ERR unknown command\r\n"))
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestCheckRedisNoAuth(t *testing.T) {
	addr := fakeRedisServer(t, "")
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hit, err := CheckRedis(ctx, host, port, DefaultPairs["redis"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected a hit for no-auth Redis")
	}
	if hit.Service != "redis" {
		t.Errorf("expected service redis, got %s", hit.Service)
	}
	if !strings.Contains(hit.Password, "no authentication") {
		t.Errorf("expected no-auth password message, got %q", hit.Password)
	}
}

func TestCheckRedisWithPassword(t *testing.T) {
	addr := fakeRedisServer(t, "foobared")
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hit, err := CheckRedis(ctx, host, port, DefaultPairs["redis"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected a hit for default password 'foobared'")
	}
	if hit.Password != "foobared" {
		t.Errorf("expected password 'foobared', got %q", hit.Password)
	}
}

func TestCheckRedisNoHit(t *testing.T) {
	addr := fakeRedisServer(t, "very-unique-password-not-in-defaults")
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	hit, err := CheckRedis(ctx, host, port, DefaultPairs["redis"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit != nil {
		t.Errorf("expected no hit, got %+v", hit)
	}
}
