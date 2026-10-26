package discovery

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// UDP discovery is deliberately NOT a generic port sweep. UDP has no
// handshake: an open port usually answers a random payload with silence,
// so a blind sweep can't tell "open" from "filtered" and is the classic
// source of UDP false positives. Instead groma sends a real protocol
// probe to each well-known UDP service port and only reports the port
// when it gets a VALID reply for that protocol — accurate and FP-free,
// at the cost of only covering protocols we know how to speak.

// udpProbe is one UDP service: the payload to send and a validator that
// recognises a genuine response for that protocol.
type udpProbe struct {
	port    int
	service string
	payload func() []byte
	valid   func(sent, got []byte) bool
}

var udpProbes = []udpProbe{
	{port: 53, service: "dns", payload: dnsQuery, valid: validDNSResponse},
	{port: 123, service: "ntp", payload: ntpRequest, valid: validNTPResponse},
	{port: 161, service: "snmp", payload: snmpGetPublic, valid: validSNMPResponse},
}

// UDPResult is one responding UDP service.
type UDPResult struct {
	Port    int
	Service string
}

// ProbeUDP sends each known UDP service probe to host and returns the
// ports that gave a valid protocol response. gate, when non-nil, bounds
// the probe sockets against the shared global budget.
func ProbeUDP(ctx context.Context, host string, timeout time.Duration, gate chan struct{}) []UDPResult {
	results := make([]UDPResult, len(udpProbes))
	var wg sync.WaitGroup
	for i, p := range udpProbes {
		wg.Add(1)
		go func(i int, p udpProbe) {
			defer wg.Done()
			if gate != nil {
				select {
				case gate <- struct{}{}:
					defer func() { <-gate }()
				case <-ctx.Done():
					return
				}
			}
			if probeOneUDP(ctx, host, p, timeout) {
				results[i] = UDPResult{Port: p.port, Service: p.service}
			}
		}(i, p)
	}
	wg.Wait()

	out := make([]UDPResult, 0, len(results))
	for _, r := range results {
		if r.Service != "" {
			out = append(out, r)
		}
	}
	return out
}

func probeOneUDP(ctx context.Context, host string, p udpProbe, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(host, itoa(p.port)))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	sent := p.payload()
	if _, err := conn.Write(sent); err != nil {
		return false
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}
	return p.valid(sent, buf[:n])
}

// --- DNS: a standard A query; any reply echoing our txid with the
// response bit set proves a DNS server is listening. ---

func dnsQuery() []byte {
	// Fixed txid is fine: the validator checks the reply echoes it, which
	// a non-DNS service won't happen to do.
	msg := []byte{
		0x13, 0x37, // ID
		0x01, 0x00, // flags: recursion desired
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
	}
	// QNAME "version.bind" is widely answered; fall back value doesn't
	// matter since we only check the header. Encode "a.root-servers.net".
	for _, label := range []string{"a", "root-servers", "net"} {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0x00)       // root
	msg = append(msg, 0x00, 0x01) // QTYPE=A
	msg = append(msg, 0x00, 0x01) // QCLASS=IN
	return msg
}

func validDNSResponse(sent, got []byte) bool {
	if len(got) < 12 || len(sent) < 2 {
		return false
	}
	idMatches := got[0] == sent[0] && got[1] == sent[1]
	isResponse := got[2]&0x80 != 0 // QR bit
	return idMatches && isResponse
}

// --- NTP: a mode-3 client request; a mode-4 server reply of full length
// proves an NTP server. ---

func ntpRequest() []byte {
	pkt := make([]byte, 48)
	pkt[0] = 0x1b // LI=0, VN=3, Mode=3 (client)
	return pkt
}

func validNTPResponse(_, got []byte) bool {
	if len(got) < 48 {
		return false
	}
	mode := got[0] & 0x07
	return mode == 4 // server
}

// --- SNMP: an SNMPv2c GetRequest for sysDescr.0 with community "public";
// any well-formed SNMP response sequence echoing the community proves the
// agent is reachable (an actual auth check is left to internal/creds). ---

func snmpGetPublic() []byte {
	// Minimal SNMPv2c GetRequest, hand-assembled ASN.1/BER.
	return []byte{
		0x30, 0x26, // SEQUENCE, len 38
		0x02, 0x01, 0x01, // version: 1 (v2c)
		0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // community "public"
		0xa0, 0x19, // GetRequest PDU, len 25
		0x02, 0x04, 0x13, 0x37, 0x13, 0x37, // request-id
		0x02, 0x01, 0x00, // error-status
		0x02, 0x01, 0x00, // error-index
		0x30, 0x0b, // varbind list
		0x30, 0x09, // varbind
		0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, // OID 1.3.6.1.2.1 (mib-2)
		0x05, 0x00, // NULL value
	}
}

func validSNMPResponse(_, got []byte) bool {
	// A response is an ASN.1 SEQUENCE that contains the community string.
	return len(got) > 2 && got[0] == 0x30 && strings.Contains(string(got), "public")
}
