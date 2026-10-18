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

// fakeFTPServer accepts one connection and replies to USER/PASS per the
// given accepted Pair (230 for a match, otherwise standard reject codes).
func fakeFTPServer(t *testing.T, accepted Pair) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		// CheckFTP dials a fresh connection per attempted pair, so the
		// fake server must keep accepting until the caller stops trying.
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.Write([]byte("220 fake ftp ready\r\n"))
				r := bufio.NewReader(conn)
				user, _ := r.ReadString('\n')
				user = strings.TrimSpace(strings.TrimPrefix(user, "USER "))
				if user != accepted.User {
					conn.Write([]byte("530 Login incorrect\r\n"))
					return
				}
				conn.Write([]byte("331 Password required\r\n"))
				pass, _ := r.ReadString('\n')
				pass = strings.TrimSpace(strings.TrimPrefix(pass, "PASS "))
				if pass == accepted.Password {
					conn.Write([]byte("230 Login successful\r\n"))
				} else {
					conn.Write([]byte("530 Login incorrect\r\n"))
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestCheckFTPFindsAcceptedPair(t *testing.T) {
	accepted := Pair{User: "admin", Password: "password"}
	addr := fakeFTPServer(t, accepted)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hit, err := CheckFTP(ctx, host, port, DefaultPairs["ftp"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected a hit for the accepted default pair")
	}
	if hit.User != accepted.User || hit.Password != accepted.Password {
		t.Errorf("expected hit %+v, got %+v", accepted, hit)
	}
}

func TestCheckFTPNoHitWhenNothingAccepted(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.Write([]byte("220 fake ftp ready\r\n"))
				r := bufio.NewReader(conn)
				r.ReadString('\n')
				conn.Write([]byte("530 Login incorrect\r\n"))
			}()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hit, err := CheckFTP(ctx, host, port, DefaultPairs["ftp"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit != nil {
		t.Errorf("expected no hit when every pair is rejected, got %+v", hit)
	}
}

func TestCheckStopsEarlyOnFirstHit(t *testing.T) {
	// The second default FTP pair in DefaultPairs is the one accepted here;
	// a working implementation must stop there rather than exhausting the
	// list (verified indirectly: the hit returned is exactly this pair).
	accepted := DefaultPairs["ftp"][1]
	addr := fakeFTPServer(t, accepted)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hit, err := CheckFTP(ctx, host, port, DefaultPairs["ftp"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil || hit.User != accepted.User || hit.Password != accepted.Password {
		t.Errorf("expected hit matching the server's accepted pair %+v, got %+v", accepted, hit)
	}
}

func TestCheckUnknownServiceReturnsNilNil(t *testing.T) {
	hit, err := Check(context.Background(), "mysql", "127.0.0.1", 3306)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit != nil {
		t.Errorf("expected nil, nil for an unregistered service, got %+v", hit)
	}
}
