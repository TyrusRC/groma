package discovery

import "testing"

func TestFingerprintBannerSSH(t *testing.T) {
	cases := []struct {
		banner  string
		product string
		version string
	}{
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1", "OpenSSH", "8.9p1"},
		{"SSH-2.0-OpenSSH_9.3", "OpenSSH", "9.3"},
		{"SSH-2.0-dropbear_2022.83", "Dropbear SSH", "2022.83"},
	}
	for _, c := range cases {
		si := FingerprintBanner(c.banner)
		if si == nil {
			t.Errorf("expected match for %q, got nil", c.banner)
			continue
		}
		if si.Product != c.product {
			t.Errorf("banner %q: product = %q, want %q", c.banner, si.Product, c.product)
		}
		if si.Version != c.version {
			t.Errorf("banner %q: version = %q, want %q", c.banner, si.Version, c.version)
		}
	}
}

func TestFingerprintBannerFTP(t *testing.T) {
	cases := []struct {
		banner  string
		product string
		version string
	}{
		{"220 ProFTPD 1.3.5e Server (Debian)", "ProFTPD", "1.3.5e"},
		{"220 (vsFTPd 3.0.3)", "vsftpd", "3.0.3"},
		{"220---------- Welcome to Pure-FTPd ----------", "Pure-FTPd", ""},
	}
	for _, c := range cases {
		si := FingerprintBanner(c.banner)
		if si == nil {
			t.Errorf("expected match for %q, got nil", c.banner)
			continue
		}
		if si.Product != c.product {
			t.Errorf("banner %q: product = %q, want %q", c.banner, si.Product, c.product)
		}
		if si.Version != c.version {
			t.Errorf("banner %q: version = %q, want %q", c.banner, si.Version, c.version)
		}
	}
}

func TestFingerprintBannerSMTP(t *testing.T) {
	cases := []struct {
		banner  string
		product string
	}{
		{"220 mail.example.com ESMTP Postfix", "Postfix"},
		{"220-mail.example.com ESMTP Exim 4.96", "Exim"},
		{"220 mail.example.com Sendmail 8.15.2", "Sendmail"},
		{"220 mail.example.com Microsoft ESMTP MAIL Service", "Microsoft Exchange"},
	}
	for _, c := range cases {
		si := FingerprintBanner(c.banner)
		if si == nil {
			t.Errorf("expected match for %q, got nil", c.banner)
			continue
		}
		if si.Product != c.product {
			t.Errorf("banner %q: product = %q, want %q", c.banner, si.Product, c.product)
		}
	}
}

func TestFingerprintBannerHTTP(t *testing.T) {
	cases := []struct {
		banner  string
		product string
		version string
	}{
		{"Server: Apache/2.4.49 (Unix)", "Apache", "2.4.49"},
		{"Server: nginx/1.21.6", "nginx", "1.21.6"},
		{"Server: Microsoft-IIS/10.0", "Microsoft IIS", "10.0"},
		{"Server: nginx", "nginx", ""},
	}
	for _, c := range cases {
		si := FingerprintBanner(c.banner)
		if si == nil {
			t.Errorf("expected match for %q, got nil", c.banner)
			continue
		}
		if si.Product != c.product {
			t.Errorf("banner %q: product = %q, want %q", c.banner, si.Product, c.product)
		}
		if si.Version != c.version {
			t.Errorf("banner %q: version = %q, want %q", c.banner, si.Version, c.version)
		}
	}
}

func TestFingerprintBannerEmpty(t *testing.T) {
	if si := FingerprintBanner(""); si != nil {
		t.Errorf("expected nil for empty banner, got %+v", si)
	}
}

func TestFingerprintBannerUnknown(t *testing.T) {
	if si := FingerprintBanner("some random garbled data"); si != nil {
		t.Errorf("expected nil for unrecognized banner, got %+v", si)
	}
}

func TestFingerprintByPort(t *testing.T) {
	cases := []struct {
		port int
		svc  string
	}{
		{22, "ssh"},
		{21, "ftp"},
		{23, "telnet"},
		{25, "smtp"},
		{80, "http"},
		{161, "snmp"},
		{389, "ldap"},
		{443, "https"},
		{1433, "mssql"},
		{2375, "docker"},
		{3000, "grafana"},
		{3306, "mysql"},
		{3389, "rdp"},
		{5432, "postgres"},
		{5900, "vnc"},
		{5984, "couchdb"},
		{6379, "redis"},
		{6443, "kubernetes"},
		{8888, "jupyter"},
		{9000, "minio"},
		{9090, "prometheus"},
		{9200, "elasticsearch"},
		{11211, "memcached"},
		{11434, "ollama"},
		{15672, "rabbitmq"},
		{27017, "mongodb"},
		{12345, ""},
	}
	for _, c := range cases {
		got := FingerprintByPort(c.port)
		if got != c.svc {
			t.Errorf("port %d: got %q, want %q", c.port, got, c.svc)
		}
	}
}
