package creds

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func fakeSNMPServer(t *testing.T, acceptedCommunity string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			community := extractSNMPCommunity(buf[:n])
			if community == acceptedCommunity {
				// Build a simple GetResponse.
				resp := snmpBuildGetResponse(acceptedCommunity, 1)
				pc.WriteTo(resp, addr)
			}
			// Wrong community: no reply (standard SNMP behavior).
		}
	}()
	return pc.LocalAddr().String()
}

// extractSNMPCommunity parses just enough BER to pull the community string
// from an SNMP packet: SEQUENCE { INTEGER(version), OCTET_STRING(community), ... }
func extractSNMPCommunity(data []byte) string {
	if len(data) < 2 || data[0] != 0x30 {
		return ""
	}
	_, content := berParseTL(data)
	if content == nil {
		return ""
	}
	// Skip version INTEGER.
	_, content = berSkipElement(content)
	if content == nil {
		return ""
	}
	// Community is an OCTET STRING.
	if len(content) < 2 || content[0] != 0x04 {
		return ""
	}
	_, val := berParseTL(content)
	return string(val)
}

// snmpBuildGetResponse builds a minimal SNMPv2c GetResponse.
func snmpBuildGetResponse(community string, requestID int32) []byte {
	oid := []byte{0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
	val := berOctetString([]byte("FakeDevice"))
	varbind := berSequence(append(oid, val...))
	varbindList := berSequence(varbind)

	reqID := berInteger([]byte{0x00, 0x00, 0x00, 0x01})
	errStatus := berInteger([]byte{0x00})
	errIndex := berInteger([]byte{0x00})

	pduContent := append(reqID, errStatus...)
	pduContent = append(pduContent, errIndex...)
	pduContent = append(pduContent, varbindList...)
	pdu := berTagLenVal(0xA2, pduContent) // GetResponse tag

	version := berInteger([]byte{0x01})
	communityTLV := berOctetString([]byte(community))

	msgContent := append(version, communityTLV...)
	msgContent = append(msgContent, pdu...)

	return berSequence(msgContent)
}

func TestCheckSNMPAccepted(t *testing.T) {
	addr := fakeSNMPServer(t, "public")
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pairs := []Pair{{"", "public"}}
	hit, err := CheckSNMP(ctx, host, port, pairs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit == nil {
		t.Fatal("expected a hit for community 'public'")
	}
	if hit.Password != "public" {
		t.Errorf("expected community 'public', got %q", hit.Password)
	}
}

func TestCheckSNMPRejected(t *testing.T) {
	addr := fakeSNMPServer(t, "secretcommunity")
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pairs := []Pair{{"", "public"}, {"", "private"}}
	hit, err := CheckSNMP(ctx, host, port, pairs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit != nil {
		t.Errorf("expected no hit, got %+v", hit)
	}
}
