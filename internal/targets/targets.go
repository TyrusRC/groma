// Package targets turns the target specifications an operator types on the
// command line into the concrete list of hosts a scan actually runs
// against. It accepts the same shapes every other network scanner does —
// plain host or IP, CIDR block, and hyphenated IP range — so groma can be
// pointed at a subnet ("10.0.0.0/24") instead of one host at a time.
//
// Hostnames are passed through untouched (DNS resolution stays with the
// dialer, which is where a per-address timeout belongs); only literal IP
// specs are expanded here.
package targets

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// MaxTargets caps how many hosts a single invocation will expand to. A /16
// (65 536 addresses) is the largest block we materialize; a /8 would be
// ~16 million and is almost always a mistake, so we refuse it with a clear
// error rather than exhausting memory.
//
// NOTE: this is a hard materialization ceiling, not a streaming scanner.
// Genuinely scanning something larger than a /16 in one shot means
// splitting it into blocks (or reaching for masscan, which is built for
// internet-scale). Raising this number is not the fix.
const MaxTargets = 65536

// Expand resolves target specs into a deduplicated, first-seen-ordered list
// of concrete host strings. Supported spec forms:
//
//	10.0.0.5            a single IPv4/IPv6 address
//	example.com         a hostname (passed through, resolved at dial time)
//	10.0.0.0/24         a CIDR block (network and broadcast included, as
//	                    nmap and naabu do)
//	10.0.0.1-50         a last-octet range
//	10.0.0.1-10.0.0.50  a full-address range
//
// It returns an error on a malformed spec, a descending or cross-family
// range, or a target set larger than MaxTargets.
func Expand(specs []string) ([]string, error) {
	out := make([]string, 0, len(specs))
	seen := make(map[string]struct{})

	add := func(host string) error {
		if _, ok := seen[host]; ok {
			return nil
		}
		if len(out) >= MaxTargets {
			return fmt.Errorf("target set exceeds %d hosts: narrow the range or split the scan into smaller blocks", MaxTargets)
		}
		seen[host] = struct{}{}
		out = append(out, host)
		return nil
	}

	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		switch {
		case strings.Contains(spec, "/"):
			if err := expandCIDR(spec, add); err != nil {
				return nil, err
			}
		case isRange(spec):
			if err := expandRange(spec, add); err != nil {
				return nil, err
			}
		default:
			// A literal IP is canonicalized so it dedupes against the same
			// address reached via a CIDR or range; anything else is treated
			// as a hostname and passed through verbatim.
			if addr, err := netip.ParseAddr(spec); err == nil {
				if err := add(addr.String()); err != nil {
					return nil, err
				}
			} else if err := add(spec); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// isRange reports whether spec is an IP range ("A-B") rather than a
// hostname that merely contains a hyphen (e.g. "my-host.example.com").
// The left side of the first hyphen must itself parse as an IP address.
func isRange(spec string) bool {
	lo, _, ok := strings.Cut(spec, "-")
	if !ok {
		return false
	}
	_, err := netip.ParseAddr(strings.TrimSpace(lo))
	return err == nil
}

func expandCIDR(spec string, add func(string) error) error {
	prefix, err := netip.ParsePrefix(spec)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", spec, err)
	}
	for addr := prefix.Masked().Addr(); prefix.Contains(addr); addr = addr.Next() {
		if err := add(addr.String()); err != nil {
			return err
		}
		if !addr.Next().IsValid() {
			break // last address in the family; avoid wrapping
		}
	}
	return nil
}

func expandRange(spec string, add func(string) error) error {
	loStr, hiStr, _ := strings.Cut(spec, "-")
	loStr, hiStr = strings.TrimSpace(loStr), strings.TrimSpace(hiStr)

	lo, err := netip.ParseAddr(loStr)
	if err != nil {
		return fmt.Errorf("invalid range start %q: %w", loStr, err)
	}

	// A bare number after the hyphen ("10.0.0.1-50") is a last-octet
	// shorthand: reuse the start address's high bytes and swap the final
	// octet. Only meaningful for IPv4.
	var hi netip.Addr
	if n, numErr := strconv.Atoi(hiStr); numErr == nil {
		if !lo.Is4() {
			return fmt.Errorf("last-octet range %q requires an IPv4 start address", spec)
		}
		if n < 0 || n > 255 {
			return fmt.Errorf("invalid last-octet range %q: %d is out of 0-255", spec, n)
		}
		b := lo.As4()
		b[3] = byte(n)
		hi = netip.AddrFrom4(b)
	} else {
		hi, err = netip.ParseAddr(hiStr)
		if err != nil {
			return fmt.Errorf("invalid range end %q: %w", hiStr, err)
		}
	}

	if lo.BitLen() != hi.BitLen() {
		return fmt.Errorf("range %q mixes IPv4 and IPv6 addresses", spec)
	}
	if lo.Compare(hi) > 0 {
		return fmt.Errorf("range %q is descending: start must be <= end", spec)
	}

	for addr := lo; addr.Compare(hi) <= 0; addr = addr.Next() {
		if err := add(addr.String()); err != nil {
			return err
		}
		if !addr.Next().IsValid() {
			break
		}
	}
	return nil
}
