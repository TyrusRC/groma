package discovery

import (
	"regexp"
	"strings"
)

// ServiceInfo is a service identified from a TCP banner or well-known port.
type ServiceInfo struct {
	Product string
	Version string
	CPEs    []string
}

// bannerRule is one regex-based banner → service mapping, modeled after
// nmap-service-probes. Each rule matches a banner line and extracts a
// product name and (optional) version.
type bannerRule struct {
	re      *regexp.Regexp
	product string
	verIdx  int // submatch index for version, 0 = none
	cpeFmt  string
}

var bannerRules = []bannerRule{
	// SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
	{
		re:      regexp.MustCompile(`^SSH-[\d.]+-(OpenSSH)[_\s](\S+)`),
		product: "OpenSSH",
		verIdx:  2,
		cpeFmt:  "cpe:/a:openbsd:openssh",
	},
	{
		re:      regexp.MustCompile(`^SSH-[\d.]+-dropbear[_\s]?(\S*)`),
		product: "Dropbear SSH",
		verIdx:  1,
		cpeFmt:  "cpe:/a:dropbear_ssh_project:dropbear_ssh",
	},
	// FTP: "220 ProFTPD 1.3.5e Server" / "220 (vsFTPd 3.0.3)"
	{
		re:      regexp.MustCompile(`(?i)220[- ].*ProFTPD\s+(\S+)`),
		product: "ProFTPD",
		verIdx:  1,
		cpeFmt:  "cpe:/a:proftpd:proftpd",
	},
	{
		re:      regexp.MustCompile(`(?i)220[- ].*vsFTPd\s+([\d.]+)`),
		product: "vsftpd",
		verIdx:  1,
		cpeFmt:  "cpe:/a:vsftpd_project:vsftpd",
	},
	{
		re:      regexp.MustCompile(`(?i)220[- ].*Pure-FTPd`),
		product: "Pure-FTPd",
		cpeFmt:  "cpe:/a:pureftpd:pure-ftpd",
	},
	{
		re:      regexp.MustCompile(`(?i)220[- ].*FileZilla Server\s+(\S+)`),
		product: "FileZilla Server",
		verIdx:  1,
	},
	// SMTP: "220 mail.example.com ESMTP Postfix" / "220 ... Exim ..."
	{
		re:      regexp.MustCompile(`(?i)220[- ].*\bPostfix\b`),
		product: "Postfix",
		cpeFmt:  "cpe:/a:postfix:postfix",
	},
	{
		re:      regexp.MustCompile(`(?i)220[- ].*\bExim\b\s+(\S+)`),
		product: "Exim",
		verIdx:  1,
		cpeFmt:  "cpe:/a:exim:exim",
	},
	{
		re:      regexp.MustCompile(`(?i)220[- ].*Microsoft ESMTP MAIL`),
		product: "Microsoft Exchange",
		cpeFmt:  "cpe:/a:microsoft:exchange_server",
	},
	{
		re:      regexp.MustCompile(`(?i)220[- ].*\bSendmail\b[/ ]*(\S*)`),
		product: "Sendmail",
		verIdx:  1,
		cpeFmt:  "cpe:/a:sendmail:sendmail",
	},
	// MySQL greeting banner (decoded from binary by the scanner's banner grab).
	// The native scanner reads the first line as text; a MySQL greeting's
	// version string starts at byte offset 5 in the packet, but the banner
	// grab sees: <garbled bytes><version>\x00... — we match the version
	// pattern tolerantly.
	{
		re:      regexp.MustCompile(`(\d+\.\d+\.\d+)[-\w]*-MariaDB`),
		product: "MariaDB",
		verIdx:  1,
		cpeFmt:  "cpe:/a:mariadb:mariadb",
	},
	// HTTP: "HTTP/1.1 200 OK" followed by Server header in banner
	{
		re:      regexp.MustCompile(`(?i)Server:\s*Apache(?:/(\S+))?`),
		product: "Apache",
		verIdx:  1,
		cpeFmt:  "cpe:/a:apache:http_server",
	},
	{
		re:      regexp.MustCompile(`(?i)Server:\s*nginx(?:/(\S+))?`),
		product: "nginx",
		verIdx:  1,
		cpeFmt:  "cpe:/a:nginx:nginx",
	},
	{
		re:      regexp.MustCompile(`(?i)Server:\s*Microsoft-IIS(?:/(\S+))?`),
		product: "Microsoft IIS",
		verIdx:  1,
		cpeFmt:  "cpe:/a:microsoft:internet_information_services",
	},
	{
		re:      regexp.MustCompile(`(?i)Server:\s*openresty(?:/(\S+))?`),
		product: "OpenResty",
		verIdx:  1,
		cpeFmt:  "cpe:/a:openresty:openresty",
	},
	{
		re:      regexp.MustCompile(`(?i)Server:\s*LiteSpeed`),
		product: "LiteSpeed",
		cpeFmt:  "cpe:/a:litespeedtech:litespeed_web_server",
	},
	// POP3: "+OK Dovecot ready." / "+OK Courier ..."
	{
		re:      regexp.MustCompile(`(?i)^\+OK.*\bDovecot\b`),
		product: "Dovecot",
		cpeFmt:  "cpe:/a:dovecot:dovecot",
	},
	// IMAP: "* OK [CAPABILITY IMAP4rev1 ...] Dovecot ready."
	{
		re:      regexp.MustCompile(`(?i)^\* OK.*\bDovecot\b`),
		product: "Dovecot",
		cpeFmt:  "cpe:/a:dovecot:dovecot",
	},
	// Redis (banner on connect): "-NOAUTH ..." or raw RESP
	// Redis doesn't send a greeting; we rely on port-based guessing for it.
}

// FingerprintBanner matches a banner string against known service patterns
// (modeled after nmap service probes) and returns the identified service
// info, or nil if unrecognized.
func FingerprintBanner(banner string) *ServiceInfo {
	banner = strings.TrimSpace(banner)
	if banner == "" {
		return nil
	}
	for _, rule := range bannerRules {
		m := rule.re.FindStringSubmatch(banner)
		if m == nil {
			continue
		}
		si := &ServiceInfo{Product: rule.product}
		if rule.verIdx > 0 && rule.verIdx < len(m) && m[rule.verIdx] != "" {
			si.Version = m[rule.verIdx]
		}
		if rule.cpeFmt != "" {
			si.CPEs = []string{rule.cpeFmt}
		}
		return si
	}
	return nil
}

// FingerprintByPort returns a best-guess service name for well-known ports
// when no banner fingerprint is available. This is the fallback for the
// native scanner path (no naabu) — it maps ports to service names so the
// default-credential checker and CVE engine have something to work with.
// Modeled after nmap-services.
func FingerprintByPort(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25, 587:
		return "smtp"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 143:
		return "imap"
	case 161:
		return "snmp"
	case 389, 636:
		return "ldap"
	case 443:
		return "https"
	case 445:
		return "smb"
	case 993:
		return "imaps"
	case 995:
		return "pop3s"
	case 1433:
		return "mssql"
	case 1521:
		return "oracle"
	case 2375, 2376:
		return "docker"
	case 3000:
		return "grafana"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgres"
	case 5672:
		return "rabbitmq"
	case 5900:
		return "vnc"
	case 5984:
		return "couchdb"
	case 6333, 6334:
		return "qdrant"
	case 6379:
		return "redis"
	case 6443:
		return "kubernetes"
	case 8080:
		return "http"
	case 8443:
		return "https"
	case 8500:
		return "consul"
	case 8888:
		return "jupyter"
	case 9000:
		return "minio"
	case 9090:
		return "prometheus"
	case 9200:
		return "elasticsearch"
	case 11211:
		return "memcached"
	case 11434:
		return "ollama"
	case 15672:
		return "rabbitmq"
	case 27017:
		return "mongodb"
	default:
		return ""
	}
}
