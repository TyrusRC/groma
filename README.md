# groma

Network vulnerability scanner. Discovers open ports, fingerprints services, checks for default credentials, and matches versions against CVEs. The network-lane counterpart to [assay](https://github.com/TyrusRC/assay) (web/DAST) — assay targets Acunetix's job, groma targets Nessus/OpenVAS.

## Features

- **Full-range port scan** — default is 1-65535, not a top-100 sample
- **Native service fingerprinting** — active probing (NULL → HTTP → TLS) with nmap-style banner matching, no external binary required
- **[naabu](https://github.com/projectdiscovery/naabu) integration** — SYN-speed port discovery when available, native TCP-connect fallback when not
- **NVD CVE lookup** — live query against NIST NVD API 2.0 with CPE matching, 200k+ CVE coverage, disk caching (`--nvd`)
- **48 built-in YAML CVE checks** — OpenSSH, Apache, nginx, PostgreSQL, MySQL, Redis, Elasticsearch, Exim, Postfix, Dovecot, ProFTPD, vsftpd
- **35+ default-credential checkers** — wire protocols (SSH, FTP, PostgreSQL, MySQL, Redis, MongoDB, MSSQL, VNC, LDAP, SNMP/UDP, Telnet, SMTP, Memcached) and HTTP services (Elasticsearch, Tomcat, Jenkins, Grafana, RabbitMQ, Docker, Kubernetes, Consul, MinIO, Portainer, Harbor, ArgoCD, Gitea, Jupyter, Ollama, ChromaDB, Qdrant, Airflow, Metabase, n8n, MLflow, Weaviate, Keycloak, Neo4j, InfluxDB). Pairs sourced from [SecLists](https://github.com/danielmiessler/SecLists)
- **SSH credentialed audit** — `dpkg`/`rpm` package version matching through the same CVE engine
- **CIS/DISA-STIG compliance** — Tenable `.audit` policy evaluation over SSH (`CMD_EXEC`/`FILE_CHECK`)
- **[Haruspex](https://github.com/TyrusRC/haruspex) triage** — optional finding confidence scoring, fail-open
- **Output** — text, JSON, SARIF 2.1.0

## Install

```sh
go build -o groma ./cmd/groma
```

Optional: [naabu](https://github.com/projectdiscovery/naabu) on `$PATH` for faster port discovery.

## Usage

```sh
# basic scan
./groma scan 10.0.0.5

# with CVE checks + NVD lookup
./groma scan --checks ./checks/examples --nvd 10.0.0.5

# default credential check
./groma scan --check-default-creds 10.0.0.5

# credentialed audit
export GROMA_SSH_USER=admin
export GROMA_SSH_KEY=~/.ssh/id_ed25519
./groma scan --checks ./checks/examples --ssh-audit 10.0.0.5

# compliance
./groma scan --compliance CIS_Ubuntu_22.04.audit 10.0.0.5

# CI gate
./groma scan --checks ./checks/examples --nvd --fail-on high -o report.json --format json 10.0.0.5
```

### Flags

```
--checks <dir>          YAML check directory
--nvd                   live NVD CVE lookup (set GROMA_NVD_API_KEY for higher rate limits)
--nvd-cache <dir>       NVD response cache (default ~/.cache/groma/nvd)
--check-default-creds   test 35+ services for vendor default credentials
--ssh-audit             SSH in, audit installed packages against CVE checks
--compliance <file>     Tenable .audit CIS/DISA-STIG policy
--ports <spec>          port list/range (nmap format, default 1-65535)
--fast                  top-N ports only
--format <fmt>          text | json | sarif
--fail-on <sev>         exit 2 if finding at/above severity (low|medium|high|critical)
--haruspex-url <url>    Haruspex triage server
--no-triage             skip Haruspex
-o, --output <file>     output file
-v, --verbose           verbose output
```

### Writing a check

```yaml
id: CVE-2024-6387
info:
  name: "OpenSSH regreSSHion RCE"
  severity: critical
  classification:
    cve-id: CVE-2024-6387
    cwe-id: CWE-362
    cvss-score: 8.1
  remediation: "Upgrade to OpenSSH >= 9.8p1."
service:
  product: OpenSSH
  cpe: "cpe:/a:openbsd:openssh"
  version:
    gte: "8.5"
    lt: "9.8"
```

## Architecture

```
cmd/groma/              CLI (Cobra)
internal/
  core/                 Finding, Severity, Target
  discovery/            TCP-connect scanner, active service prober, banner fingerprinting
  detection/            legacy protocol checks (Telnet, FTP anon)
  checks/               YAML CVE check engine + observation bridges
  creds/                default-credential checkers (wire + HTTP)
  nvd/                  NVD API client with CPE 2.2→2.3 conversion + caching
  audit/                SSH credentialed package audit
  compliance/           .audit CIS/DISA-STIG parser + evaluator
  haruspex/             finding triage client
  reporting/            text / JSON / SARIF output
  tools/naabu/          naabu CLI wrapper for port discovery
  tools/nmap/           nmap XML parser (optional enrichment)
  sysnet/               ulimit-aware concurrency
checks/examples/        48 CVE YAML checks
```

## License

Apache-2.0
