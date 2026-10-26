package targets

import (
	"reflect"
	"testing"
)

func TestExpand(t *testing.T) {
	tests := []struct {
		name  string
		specs []string
		want  []string
	}{
		{
			name:  "plain ipv4 passthrough",
			specs: []string{"10.0.0.5"},
			want:  []string{"10.0.0.5"},
		},
		{
			name:  "hostname passthrough",
			specs: []string{"scanme.nmap.org"},
			want:  []string{"scanme.nmap.org"},
		},
		{
			name:  "cidr /30 includes network and broadcast",
			specs: []string{"10.0.0.0/30"},
			want:  []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"},
		},
		{
			name:  "cidr /32 is a single host",
			specs: []string{"192.168.1.1/32"},
			want:  []string{"192.168.1.1"},
		},
		{
			name:  "last-octet range",
			specs: []string{"10.0.0.1-3"},
			want:  []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
		},
		{
			name:  "full-ip range",
			specs: []string{"10.0.0.254-10.0.1.1"},
			want:  []string{"10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"},
		},
		{
			name:  "dedup overlapping cidr and explicit host, first-seen order",
			specs: []string{"10.0.0.1", "10.0.0.0/30"},
			want:  []string{"10.0.0.1", "10.0.0.0", "10.0.0.2", "10.0.0.3"},
		},
		{
			name:  "whitespace and empty tokens ignored",
			specs: []string{"  10.0.0.5 ", "", "   "},
			want:  []string{"10.0.0.5"},
		},
		{
			name:  "ipv6 single host passthrough",
			specs: []string{"::1"},
			want:  []string{"::1"},
		},
		{
			name:  "ipv6 /126 cidr",
			specs: []string{"2001:db8::/126"},
			want:  []string{"2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Expand(tt.specs)
			if err != nil {
				t.Fatalf("Expand(%v) error: %v", tt.specs, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Expand(%v) = %v, want %v", tt.specs, got, tt.want)
			}
		})
	}
}

func TestExpandErrors(t *testing.T) {
	tests := []struct {
		name  string
		specs []string
	}{
		{"descending last-octet range", []string{"10.0.0.5-1"}},
		{"descending full-ip range", []string{"10.0.0.10-10.0.0.1"}},
		{"range across address families", []string{"10.0.0.1-::5"}},
		{"garbage range bound", []string{"10.0.0.1-nope"}},
		{"bad cidr", []string{"10.0.0.0/33"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Expand(tt.specs); err == nil {
				t.Errorf("Expand(%v) = nil error, want error", tt.specs)
			}
		})
	}
}

// A /8 would be 16M addresses; materializing it is a memory bomb, so
// Expand must refuse anything above MaxTargets rather than try.
func TestExpandRefusesOversizedRange(t *testing.T) {
	if _, err := Expand([]string{"10.0.0.0/8"}); err == nil {
		t.Fatalf("Expand(/8) = nil error, want over-limit error")
	}
	// A /16 (65 536 addresses) is right at the ceiling and must succeed.
	got, err := Expand([]string{"10.0.0.0/16"})
	if err != nil {
		t.Fatalf("Expand(/16) error: %v", err)
	}
	if len(got) != 65536 {
		t.Fatalf("Expand(/16) returned %d addresses, want 65536", len(got))
	}
}
