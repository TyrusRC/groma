package creds

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const snmpTimeout = 2 * time.Second

// CheckSNMP tries each pair's Password as an SNMPv2c community string
// by sending a GetRequest for sysDescr.0. A valid GetResponse means the
// community string is accepted. This is UDP — no response typically
// means wrong community string. The User field is ignored (SNMP v1/v2c
// has no username concept).
func CheckSNMP(ctx context.Context, host string, port int, attempts []Pair) (*Hit, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	for i, p := range attempts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ok, err := trySNMPCommunity(ctx, addr, p.Password)
		if err != nil {
			return nil, fmt.Errorf("creds: snmp %s: %w", addr, err)
		}
		if ok {
			return &Hit{Service: "snmp", User: "", Password: p.Password}, nil
		}
		if i < len(attempts)-1 {
			if err := sleepBetweenAttempts(ctx); err != nil {
				return nil, err
			}
		}
	}
	return nil, nil
}

func trySNMPCommunity(ctx context.Context, addr, community string) (bool, error) {
	dialCtx, cancel := context.WithTimeout(ctx, snmpTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "udp", addr)
	if err != nil {
		return false, fmt.Errorf("dialing: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(snmpTimeout))

	pkt := snmpBuildGetRequest(community, 1)
	if _, err := conn.Write(pkt); err != nil {
		return false, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return false, nil // timeout = no response = wrong community
	}

	return snmpIsGetResponse(buf[:n]), nil
}

// snmpBuildGetRequest builds an SNMPv2c GetRequest for OID 1.3.6.1.2.1.1.1.0
// (sysDescr.0) with the given community string.
func snmpBuildGetRequest(community string, requestID int32) []byte {
	// OID 1.3.6.1.2.1.1.1.0 encoded as BER
	oid := []byte{0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
	null := []byte{0x05, 0x00}

	// VarBind: SEQUENCE { OID, NULL }
	varbind := berSequence(append(oid, null...))
	// VarBindList: SEQUENCE { varbind }
	varbindList := berSequence(varbind)

	// Request ID as INTEGER
	reqIDBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(reqIDBuf, uint32(requestID))
	reqID := berInteger(reqIDBuf)

	// Error status = 0, error index = 0
	errStatus := berInteger([]byte{0x00})
	errIndex := berInteger([]byte{0x00})

	// GetRequest-PDU (context class, constructed, tag 0 = 0xA0)
	pduContent := append(reqID, errStatus...)
	pduContent = append(pduContent, errIndex...)
	pduContent = append(pduContent, varbindList...)
	pdu := berTagLenVal(0xA0, pduContent)

	// Version = 1 (SNMPv2c)
	version := berInteger([]byte{0x01})

	// Community string
	communityTLV := berOctetString([]byte(community))

	// Message: SEQUENCE { version, community, PDU }
	msgContent := append(version, communityTLV...)
	msgContent = append(msgContent, pdu...)

	return berSequence(msgContent)
}

// snmpIsGetResponse checks if the packet contains a GetResponse PDU (tag 0xA2).
func snmpIsGetResponse(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	// Outer SEQUENCE
	if data[0] != 0x30 {
		return false
	}
	_, content := berParseTL(data)
	if content == nil {
		return false
	}
	// Skip version INTEGER
	_, content = berSkipElement(content)
	if content == nil {
		return false
	}
	// Skip community OCTET STRING
	_, content = berSkipElement(content)
	if content == nil {
		return false
	}
	// Next element should be GetResponse-PDU (0xA2)
	return len(content) > 0 && content[0] == 0xA2
}

func berSequence(content []byte) []byte {
	return berTagLenVal(0x30, content)
}

func berInteger(val []byte) []byte {
	return berTagLenVal(0x02, val)
}

func berOctetString(val []byte) []byte {
	return berTagLenVal(0x04, val)
}

func berTagLenVal(tag byte, val []byte) []byte {
	out := []byte{tag}
	l := len(val)
	if l < 128 {
		out = append(out, byte(l))
	} else if l <= 0xFF {
		out = append(out, 0x81, byte(l))
	} else {
		out = append(out, 0x82, byte(l>>8), byte(l))
	}
	return append(out, val...)
}

// berParseTL parses the tag and length of a BER element and returns the
// content slice (past the TL) or nil on error.
func berParseTL(data []byte) (tag byte, content []byte) {
	if len(data) < 2 {
		return 0, nil
	}
	tag = data[0]
	offset := 1
	length := int(data[offset])
	offset++
	if length&0x80 != 0 {
		numBytes := length & 0x7F
		if numBytes > 2 || offset+numBytes > len(data) {
			return tag, nil
		}
		length = 0
		for i := 0; i < numBytes; i++ {
			length = length<<8 | int(data[offset])
			offset++
		}
	}
	if offset+length > len(data) {
		return tag, nil
	}
	return tag, data[offset : offset+length]
}

// berSkipElement skips one BER TLV element and returns (element, rest).
func berSkipElement(data []byte) (element []byte, rest []byte) {
	if len(data) < 2 {
		return nil, nil
	}
	offset := 1
	length := int(data[offset])
	offset++
	if length&0x80 != 0 {
		numBytes := length & 0x7F
		if numBytes > 2 || offset+numBytes > len(data) {
			return nil, nil
		}
		length = 0
		for i := 0; i < numBytes; i++ {
			length = length<<8 | int(data[offset])
			offset++
		}
	}
	end := offset + length
	if end > len(data) {
		return nil, nil
	}
	return data[:end], data[end:]
}
