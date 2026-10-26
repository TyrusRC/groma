# groma

Network vulnerability scanner. Discovers open ports, fingerprints services, checks for default credentials, and matches versions against CVEs. The network-lane counterpart to [assay](https://github.com/TyrusRC/assay) (web/DAST) — assay targets Acunetix's job, groma targets Nessus/OpenVAS.

## Features

- **Targets** — hosts, CIDR blocks, and IP ranges; `--target-file` (or stdin) for lists. Hosts scan in parallel under one global connection budget.
- **Full range by default** — all 65535 TCP ports, not a top-N sample.
- **Accurate, not sprayed** — connect scans confirm every open port with a real handshake, dropped probes are retried, and duplicate results are collapsed. `--scan-type syn` (root) auto-verifies each hit.
- **Service fingerprinting** — active NULL → HTTP → TLS probing with nmap-style banner matching, no external binary required.
- **UDP** — protocol-specific probes for DNS, NTP, and SNMP (`--udp`); a port is reported only on a valid reply, never a blind UDP sweep.
- **[naabu](https://github.com/projectdiscovery/naabu)** — used for port discovery when on `$PATH`, native TCP-connect scanner otherwise.
- **CVE matching** — built-in YAML checks plus live NVD lookup with CPE matching and on-disk caching (`--nvd`).
- **Default credentials** — wire protocols and common HTTP services, vendor defaults only ([SecLists](https://github.com/danielmiessler/SecLists)).
- **Credentialed audit** — SSH in and match installed `dpkg`/`rpm` versions through the same CVE engine.
- **Compliance** — Tenable `.audit` CIS/DISA-STIG policies over SSH.
- **Triage** — optional [Haruspex](https://github.com/TyrusRC/haruspex) confidence scoring, fail-open.
- **Output** — text (grouped by host, worst-first, color in a terminal), JSON, SARIF 2.1.0.

## Install

```sh
go install -v github.com/TyrusRC/groma/cmd/groma@latest
```

Or build from source:

```sh
git clone https://github.com/TyrusRC/groma.git
cd groma
go build -o groma ./cmd/groma
```

Optional: [naabu](https://github.com/projectdiscovery/naabu) on `$PATH` for faster port discovery.

## Usage

```sh
# scan a host — port discovery, service fingerprinting, bundled CVE
# checks, live NVD lookup, and default-credential checks all run by default
./groma scan 10.0.0.5

# a whole subnet, a range, or a file of targets — same defaults
./groma scan 10.0.0.0/24
./groma scan 10.0.0.1-50
./groma scan --target-file targets.txt

# fully offline / lean (skip the network CVE lookup and cred checks)
./groma scan --nvd=false --check-default-creds=false 10.0.0.5

# credentialed audit
export GROMA_SSH_USER=admin
export GROMA_SSH_KEY=~/.ssh/id_ed25519
./groma scan --checks ./checks/examples --ssh-audit 10.0.0.5

# compliance
./groma scan --compliance CIS_Ubuntu_22.04.audit 10.0.0.5

# CI gate
./groma scan --fail-on high -o report.json --format json 10.0.0.5
```

### Flags

```
--checks <dir>          YAML check directory (default: checks bundled into the binary)
--nvd                   live NVD CVE lookup (default on; --nvd=false for offline)
--nvd-cache <dir>       NVD response cache (default ~/.cache/groma/nvd)
--check-default-creds   test services for vendor default credentials (default on)
--ssh-audit             SSH in, audit installed packages against CVE checks
--compliance <file>     Tenable .audit CIS/DISA-STIG policy
--ports <spec>          port list/range (nmap format, default 1-65535)
--fast                  top-N ports only
--scan-type <type>      connect (default, no privileges) or syn (faster, needs root; auto-verified)
--ping                  host discovery: skip targets that don't answer a quick TCP probe
--udp                   probe common UDP services (DNS, NTP, SNMP); only valid replies reported
--target-file <file>    read targets (one host/CIDR/range per line; '-' = stdin)
--host-concurrency <n>  hosts analysed in parallel (0 = auto)
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
checks/examples/        example CVE YAML checks
```

## License

Apache-2.0
