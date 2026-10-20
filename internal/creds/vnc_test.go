package creds

import (
	"context"
	"crypto/des"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fakeVNCServer(t *testing.T, mode string, acceptedPassword string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	challenge := []byte("0123456789ABCDEF") // 16 bytes

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// Send protocol version.
				conn.Write([]byte("RFB 003.008\n"))
				// Read client version.
				var ver [12]byte
				mongoReadFull(conn, ver[:])

				switch mode {
				case "none":
					conn.Write([]byte{1, 1}) // 1 type: None
					// Read selected type.
					var sel [1]byte
					conn.Read(sel[:])
					// Send success.
					var ok [4]byte
					conn.Write(ok[:])
				case "vncauth":
					conn.Write([]byte{1, 2}) // 1 type: VNC Auth
					// Read selected type.
					var sel [1]byte
					conn.Read(sel[:])
					// Send challenge.
					conn.Write(challenge)
					// Read response.
					var resp [16]byte
					mongoReadFull(conn, resp[:])
					// Verify.
					expected := vncEncryptChallenge(challenge, acceptedPassword)
					var result [4]byte
					match := true
					for i := range resp {
						if resp[i] != expected[i] {
							match = false
							break
						}
					}
					if match {
						binary.BigEndian.PutUint32(result[:], 0) // OK
					} else {
						binary.BigEndian.PutUint32(result[:], 1) // Fail
					}
					conn.Write(result[:])
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestCheckVNCNoAuth(t *testing.T) {
	addr := fakeVNCServer(t, "none", "")
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hit, err := CheckVNC(ctx, host, port, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected hit for no-auth VNC")
	}
	if !strings.Contains(hit.Password, "no authentication") {
		t.Errorf("expected no-auth message, got %q", hit.Password)
	}
}

func TestCheckVNCPasswordMatch(t *testing.T) {
	addr := fakeVNCServer(t, "vncauth", "password")
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hit, err := CheckVNC(ctx, host, port, []Pair{{"", "password"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected hit for matching password")
	}
	if hit.Password != "password" {
		t.Errorf("expected 'password', got %q", hit.Password)
	}
}

func TestCheckVNCPasswordRejected(t *testing.T) {
	addr := fakeVNCServer(t, "vncauth", "secretXYZ")
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hit, err := CheckVNC(ctx, host, port, []Pair{{"", "wrong"}, {"", "alsobad"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit != nil {
		t.Errorf("expected no hit, got %+v", hit)
	}
}

func TestVNCReverseBits(t *testing.T) {
	// 0x41 = 01000001 → 10000010 = 0x82
	if got := vncReverseBits(0x41); got != 0x82 {
		t.Errorf("reverseBits(0x41) = 0x%02x, want 0x82", got)
	}
}

func TestVNCEncryptRoundTrip(t *testing.T) {
	challenge := []byte("AAAAAAAABBBBBBBB")
	password := "test"

	encrypted := vncEncryptChallenge(challenge, password)
	if len(encrypted) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(encrypted))
	}

	// Decrypt to verify.
	key := make([]byte, 8)
	for i := 0; i < len(password) && i < 8; i++ {
		key[i] = vncReverseBits(password[i])
	}
	block, _ := des.NewCipher(key)
	var decrypted [16]byte
	block.Decrypt(decrypted[0:8], encrypted[0:8])
	block.Decrypt(decrypted[8:16], encrypted[8:16])
	if string(decrypted[:]) != string(challenge) {
		t.Errorf("round-trip failed: got %q, want %q", decrypted[:], challenge)
	}
}
