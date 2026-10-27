package discovery

import (
	"context"
	"testing"
	"time"
)

func TestValidDNSResponseChecksIDAndQRBit(t *testing.T) {
	sent := dnsQuery()
	// A reply echoes the ID and sets the QR (response) bit in byte 2.
	resp := append([]byte{sent[0], sent[1], 0x81, 0x80}, make([]byte, 8)...)
	if !validDNSResponse(sent, resp) {
		t.Errorf("a response echoing our ID with QR set should validate")
	}
	// Wrong ID must not validate (some other UDP service answering).
	bad := append([]byte{0xAA, 0xBB, 0x81, 0x80}, make([]byte, 8)...)
	if validDNSResponse(sent, bad) {
		t.Errorf("a reply with a different ID must not validate")
	}
	// A query (QR=0) echoed back must not validate.
	query := append([]byte{sent[0], sent[1], 0x01, 0x00}, make([]byte, 8)...)
	if validDNSResponse(sent, query) {
		t.Errorf("QR=0 must not validate as a response")
	}
}

func TestValidNTPResponseChecksMode(t *testing.T) {
	server := make([]byte, 48)
	server[0] = 0x1c // VN=3, Mode=4 (server)
	if !validNTPResponse(nil, server) {
		t.Errorf("a 48-byte mode-4 packet should validate")
	}
	short := make([]byte, 20)
	if validNTPResponse(nil, short) {
		t.Errorf("a short packet must not validate")
	}
	client := make([]byte, 48)
	client[0] = 0x1b // mode 3
	if validNTPResponse(nil, client) {
		t.Errorf("a mode-3 (client) packet must not validate as a server reply")
	}
}

func TestValidSNMPResponseNeedsResponsePDUAndCommunity(t *testing.T) {
	sent := snmpGetPublic()

	// A real reply is a SEQUENCE carrying the community and a GetResponse
	// PDU (tag 0xa2).
	ok := append([]byte{0x30, 0x20, 0x04, 0x06}, []byte("public")...)
	ok = append(ok, 0xa2, 0x05, 0x02, 0x01, 0x00)
	if !validSNMPResponse(sent, ok) {
		t.Errorf("a GetResponse PDU echoing the community should validate")
	}

	// A reflecting/echo service returns our probe verbatim — our payload
	// is itself a 0x30 sequence containing "public", so this is the FP the
	// validator must reject.
	if validSNMPResponse(sent, sent) {
		t.Errorf("an echoed probe (no GetResponse PDU) must not validate")
	}

	if validSNMPResponse(sent, []byte("random udp noise")) {
		t.Errorf("non-SNMP bytes must not validate")
	}
}

func TestProbeUDPUnroutableReturnsNothing(t *testing.T) {
	if r := ProbeUDP(context.Background(), "192.0.2.1", 300*time.Millisecond, nil); len(r) != 0 {
		t.Errorf("TEST-NET host should yield no UDP services, got %v", r)
	}
}
