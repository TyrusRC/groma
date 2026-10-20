package creds

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"testing"
	"time"
	"unicode/utf16"
)

func fakeMSSQLServer(t *testing.T, accepted Pair) string {
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
				// Read TDS header (8 bytes).
				var hdr [8]byte
				if _, err := mongoReadFull(conn, hdr[:]); err != nil {
					return
				}
				pktLen := int(binary.BigEndian.Uint16(hdr[2:4]))
				if pktLen < 8 {
					return
				}
				body := make([]byte, pktLen-8)
				if _, err := mongoReadFull(conn, body); err != nil {
					return
				}

				user, pass := fakeMSSQLExtractCreds(body)
				if user == accepted.User && pass == accepted.Password {
					fakeMSSQLSendLoginAck(conn)
				} else {
					fakeMSSQLSendError(conn)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func fakeMSSQLExtractCreds(body []byte) (string, string) {
	if len(body) < 94 {
		return "", ""
	}
	// Username offset/length at body[40:44].
	userOff := int(binary.LittleEndian.Uint16(body[40:42]))
	userLen := int(binary.LittleEndian.Uint16(body[42:44]))
	// Password offset/length at body[44:48].
	passOff := int(binary.LittleEndian.Uint16(body[44:46]))
	passLen := int(binary.LittleEndian.Uint16(body[46:48]))

	user := fromUTF16LE(body, userOff, userLen)

	// De-obfuscate password.
	passBytesStart := passOff
	passBytesEnd := passOff + passLen*2
	if passBytesEnd > len(body) {
		return user, ""
	}
	passBytes := make([]byte, passLen*2)
	copy(passBytes, body[passBytesStart:passBytesEnd])
	for i := range passBytes {
		b := passBytes[i] ^ 0xA5
		passBytes[i] = (b >> 4) | (b << 4)
	}
	pass := fromUTF16LEBytes(passBytes)
	return user, pass
}

func fromUTF16LE(data []byte, charOffset, charLen int) string {
	byteStart := charOffset
	byteEnd := charOffset + charLen*2
	if byteEnd > len(data) {
		return ""
	}
	return fromUTF16LEBytes(data[byteStart:byteEnd])
}

func fromUTF16LEBytes(data []byte) string {
	u16 := make([]uint16, len(data)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return string(utf16.Decode(u16))
}

func fakeMSSQLSendLoginAck(conn net.Conn) {
	// Token stream: LOGINACK (0xAD) + minimal data.
	payload := []byte{
		0xAD,       // LOGINACK token
		0x00, 0x06, // length
		0x00,                   // interface
		0x74, 0x00, 0x00, 0x04, // TDS version
		0x00, // progname length=0
	}
	sendTDSResponse(conn, payload)
}

func fakeMSSQLSendError(conn net.Conn) {
	// Token stream: ERROR (0xAA) + minimal data.
	msg := toUTF16LE("Login failed")
	payload := []byte{0xAA}
	// ERROR token length (2 bytes).
	errLen := 4 + 2 + len(msg) + 2 + 2 + 4 + 2
	payload = append(payload, byte(errLen), byte(errLen>>8))
	// Error number (4 bytes).
	payload = append(payload, 0x15, 0x04, 0x00, 0x00) // 18453
	// State (1 byte), Severity (1 byte).
	payload = append(payload, 0x01, 0x0E)
	// Message length (2 bytes) in chars.
	msgChars := len(msg) / 2
	payload = append(payload, byte(msgChars), byte(msgChars>>8))
	payload = append(payload, msg...)
	// Server name length + name (empty).
	payload = append(payload, 0x00)
	// Proc name length + name (empty).
	payload = append(payload, 0x00)
	// Line number (4 bytes).
	payload = append(payload, 0x00, 0x00, 0x00, 0x00)

	sendTDSResponse(conn, payload)
}

func sendTDSResponse(conn net.Conn, payload []byte) {
	hdr := make([]byte, 8)
	hdr[0] = 0x04 // TDS_RESPONSE
	hdr[1] = 0x01 // EOM
	binary.BigEndian.PutUint16(hdr[2:4], uint16(8+len(payload)))
	conn.Write(append(hdr, payload...))
}

func TestCheckMSSQLAccepted(t *testing.T) {
	accepted := Pair{User: "sa", Password: ""}
	addr := fakeMSSQLServer(t, accepted)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hit, err := CheckMSSQL(ctx, host, port, []Pair{accepted})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected a hit for sa with blank password")
	}
	if hit.User != "sa" {
		t.Errorf("expected user sa, got %s", hit.User)
	}
}

func TestCheckMSSQLPasswordMatch(t *testing.T) {
	accepted := Pair{User: "sa", Password: "Password1"}
	addr := fakeMSSQLServer(t, accepted)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pairs := []Pair{{"sa", "wrong"}, {"sa", "Password1"}}
	hit, err := CheckMSSQL(ctx, host, port, pairs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected a hit for sa/Password1")
	}
	if hit.Password != "Password1" {
		t.Errorf("expected Password1, got %q", hit.Password)
	}
}

func TestCheckMSSQLRejected(t *testing.T) {
	accepted := Pair{User: "sa", Password: "impossiblesecret"}
	addr := fakeMSSQLServer(t, accepted)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pairs := []Pair{{"sa", ""}, {"sa", "password"}}
	hit, err := CheckMSSQL(ctx, host, port, pairs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit != nil {
		t.Errorf("expected no hit, got %+v", hit)
	}
}

func TestTDSObfuscatePassword(t *testing.T) {
	raw := toUTF16LE("abc")
	obf := tdsObfuscatePassword(raw)
	// De-obfuscate and verify round-trip.
	deobf := make([]byte, len(obf))
	for i, b := range obf {
		b2 := b ^ 0xA5
		deobf[i] = (b2 >> 4) | (b2 << 4)
	}
	if string(deobf) != string(raw) {
		t.Errorf("obfuscation round-trip failed")
	}
}
