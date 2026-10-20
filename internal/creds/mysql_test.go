package creds

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"net"
	"strconv"
	"testing"
	"time"
)

// fakeMySQLServer speaks just enough of the handshake to exercise
// CheckMySQL. authPlugin controls the auth method advertised;
// accepted is the pair that will succeed.
func fakeMySQLServer(t *testing.T, authPlugin string, accepted Pair) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	scramble := []byte("AABBCCDDEEAABBCCDDEE") // 20-byte scramble

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				greeting := fakeMySQLGreeting(scramble, authPlugin)
				mysqlWritePacketRaw(conn, 0, greeting)

				// Read client auth packet.
				pkt, err := fakeMySQLReadPacket(conn)
				if err != nil {
					return
				}

				// Parse username from auth packet:
				// 4 caps + 4 maxpkt + 1 charset + 23 reserved = 32 bytes
				if len(pkt) < 33 {
					mysqlWriteErrPacket(conn, 2)
					return
				}
				userStart := 32
				userEnd := userStart
				for userEnd < len(pkt) && pkt[userEnd] != 0 {
					userEnd++
				}
				user := string(pkt[userStart:userEnd])

				if authPlugin != "mysql_native_password" {
					// Unsupported auth — send auth switch.
					switchPkt := []byte{0xFE}
					switchPkt = append(switchPkt, []byte("caching_sha2_password")...)
					switchPkt = append(switchPkt, 0)
					switchPkt = append(switchPkt, scramble...)
					switchPkt = append(switchPkt, 0)
					mysqlWritePacketRaw(conn, 2, switchPkt)
					return
				}

				// Extract auth response.
				pos := userEnd + 1 // past NUL
				if pos >= len(pkt) {
					mysqlWriteErrPacket(conn, 2)
					return
				}
				authLen := int(pkt[pos])
				pos++
				var authResp []byte
				if pos+authLen <= len(pkt) {
					authResp = pkt[pos : pos+authLen]
				}

				if user == accepted.User && mysqlVerifyNative(accepted.Password, scramble, authResp) {
					mysqlWriteOkPacket(conn, 2)
				} else {
					mysqlWriteErrPacket(conn, 2)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func mysqlVerifyNative(password string, scramble, authResp []byte) bool {
	if password == "" {
		return len(authResp) == 0
	}
	expected := mysqlNativePassword(password, scramble)
	if len(expected) != len(authResp) {
		return false
	}
	for i := range expected {
		if expected[i] != authResp[i] {
			return false
		}
	}
	return true
}

func fakeMySQLGreeting(scramble []byte, plugin string) []byte {
	var pkt []byte
	pkt = append(pkt, 10) // protocol version
	pkt = append(pkt, []byte("5.7.42-fake")...)
	pkt = append(pkt, 0) // NUL terminator
	// Connection ID (4 bytes LE)
	connID := make([]byte, 4)
	binary.LittleEndian.PutUint32(connID, 1)
	pkt = append(pkt, connID...)
	// Auth data part 1 (8 bytes)
	pkt = append(pkt, scramble[:8]...)
	pkt = append(pkt, 0) // filler
	// Capability flags lower (2 bytes): PROTOCOL_41 | SECURE_CONNECTION
	caps := uint16(0x0200 | 0x8000)
	b2 := make([]byte, 2)
	binary.LittleEndian.PutUint16(b2, caps)
	pkt = append(pkt, b2...)
	pkt = append(pkt, 33)    // charset utf8
	pkt = append(pkt, 0, 0)  // status flags
	pkt = append(pkt, 0, 0)  // capability flags upper
	pkt = append(pkt, 21)    // auth data length (8+12+NUL=21)
	pkt = append(pkt, make([]byte, 10)...) // reserved
	// Auth data part 2 (max(13, 21-8)=13 bytes)
	part2 := make([]byte, 13)
	copy(part2, scramble[8:])
	pkt = append(pkt, part2...)
	// Auth plugin name
	pkt = append(pkt, []byte(plugin)...)
	pkt = append(pkt, 0)
	return pkt
}

func mysqlWritePacketRaw(conn net.Conn, seq byte, payload []byte) {
	hdr := []byte{
		byte(len(payload)),
		byte(len(payload) >> 8),
		byte(len(payload) >> 16),
		seq,
	}
	conn.Write(append(hdr, payload...))
}

func mysqlWriteOkPacket(conn net.Conn, seq byte) {
	mysqlWritePacketRaw(conn, seq, []byte{0x00, 0, 0, 0, 0})
}

func mysqlWriteErrPacket(conn net.Conn, seq byte) {
	pkt := []byte{0xFF}
	pkt = append(pkt, 0x15, 0x04) // error code 1045
	pkt = append(pkt, '#')
	pkt = append(pkt, []byte("28000")...)
	pkt = append(pkt, []byte("Access denied")...)
	mysqlWritePacketRaw(conn, seq, pkt)
}

func fakeMySQLReadPacket(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := mongoReadFull(conn, hdr); err != nil {
		return nil, err
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if length == 0 {
		return nil, nil
	}
	payload := make([]byte, length)
	if _, err := mongoReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func TestCheckMySQLAccepted(t *testing.T) {
	accepted := Pair{User: "root", Password: ""}
	addr := fakeMySQLServer(t, "mysql_native_password", accepted)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hit, err := CheckMySQL(ctx, host, port, DefaultPairs["mysql"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected a hit for root with blank password")
	}
	if hit.User != "root" {
		t.Errorf("expected user root, got %s", hit.User)
	}
}

func TestCheckMySQLPasswordMatch(t *testing.T) {
	accepted := Pair{User: "root", Password: "mysql"}
	addr := fakeMySQLServer(t, "mysql_native_password", accepted)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hit, err := CheckMySQL(ctx, host, port, DefaultPairs["mysql"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected a hit for root/mysql")
	}
	if hit.Password != "mysql" {
		t.Errorf("expected password 'mysql', got %q", hit.Password)
	}
}

func TestCheckMySQLUnsupportedAuth(t *testing.T) {
	addr := fakeMySQLServer(t, "caching_sha2_password", Pair{})
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hit, err := CheckMySQL(ctx, host, port, DefaultPairs["mysql"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit != nil {
		t.Errorf("unsupported auth method should return nil, got %+v", hit)
	}
}

func TestCheckMySQLNoHit(t *testing.T) {
	accepted := Pair{User: "nonexistent", Password: "impossiblepassword"}
	addr := fakeMySQLServer(t, "mysql_native_password", accepted)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	hit, err := CheckMySQL(ctx, host, port, DefaultPairs["mysql"])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit != nil {
		t.Errorf("expected no hit, got %+v", hit)
	}
}

func TestMySQLNativePasswordKnownVector(t *testing.T) {
	password := "test"
	scramble := []byte("12345678901234567890")
	result := mysqlNativePassword(password, scramble)
	// Verify: SHA1(password) XOR SHA1(scramble + SHA1(SHA1(password)))
	s1 := sha1.Sum([]byte(password))
	s2 := sha1.Sum(s1[:])
	h := sha1.New()
	h.Write(scramble)
	h.Write(s2[:])
	expected := h.Sum(nil)
	for i := range expected {
		expected[i] ^= s1[i]
	}
	if len(result) != len(expected) {
		t.Fatalf("length mismatch: got %d, want %d", len(result), len(expected))
	}
	for i := range result {
		if result[i] != expected[i] {
			t.Fatalf("byte %d mismatch: got %02x, want %02x", i, result[i], expected[i])
		}
	}
}
