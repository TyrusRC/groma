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

func fakeTelnetServer(t *testing.T, accepted Pair) string {
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
				conn.Write([]byte("Welcome\r\nLogin: "))
				r := bufio.NewReader(conn)
				user, _ := r.ReadString('\n')
				user = strings.TrimSpace(user)
				conn.Write([]byte("Password: "))
				pass, _ := r.ReadString('\n')
				pass = strings.TrimSpace(pass)
				if user == accepted.User && pass == accepted.Password {
					conn.Write([]byte("user@host:~$ "))
				} else {
					conn.Write([]byte("Login incorrect\r\n"))
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestCheckTelnetAccepted(t *testing.T) {
	accepted := Pair{User: "admin", Password: "admin"}
	addr := fakeTelnetServer(t, accepted)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hit, err := CheckTelnet(ctx, host, port, []Pair{accepted})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected a hit for accepted pair")
	}
	if hit.User != "admin" {
		t.Errorf("expected user admin, got %s", hit.User)
	}
}

func TestCheckTelnetRejected(t *testing.T) {
	accepted := Pair{User: "root", Password: "secretXYZ"}
	addr := fakeTelnetServer(t, accepted)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hit, err := CheckTelnet(ctx, host, port, []Pair{{"admin", "wrong"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit != nil {
		t.Errorf("expected no hit, got %+v", hit)
	}
}
