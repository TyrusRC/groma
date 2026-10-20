package creds

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fakeMemcachedServer(t *testing.T, open bool) string {
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
				buf := make([]byte, 256)
				n, _ := conn.Read(buf)
				cmd := strings.TrimSpace(string(buf[:n]))
				if cmd == "stats" {
					if open {
						conn.Write([]byte("STAT pid 12345\r\nSTAT version 1.6.21\r\nEND\r\n"))
					} else {
						conn.Write([]byte("ERROR\r\n"))
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestCheckMemcachedNoAuth(t *testing.T) {
	addr := fakeMemcachedServer(t, true)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hit, err := CheckMemcached(ctx, host, port, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected a hit for unauthenticated memcached")
	}
	if !strings.Contains(hit.Password, "no authentication") {
		t.Errorf("expected no-auth message, got %q", hit.Password)
	}
}

func TestCheckMemcachedAuthRequired(t *testing.T) {
	addr := fakeMemcachedServer(t, false)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hit, err := CheckMemcached(ctx, host, port, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit != nil {
		t.Errorf("expected no hit when auth required, got %+v", hit)
	}
}
