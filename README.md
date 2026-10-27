# groma

Network vulnerability scanner. Discovers open ports, fingerprints services, checks for default credentials, and matches versions against CVEs. The network-lane counterpart to [vigil](https://github.com/TyrusRC/vigil) (web/DAST) — vigil targets Acunetix's job, groma targets Nessus/OpenVAS.

## Features

- **Targets** — hosts, CIDR blocks, and IP ranges; `--target-file` (or stdin) for lists. Hosts scan in parallel under one global connection budget.
- **Full range by default** — all 65535 TCP ports, not a top-N sample.
- **Native engine by default** — groma's own TCP-connect scanner runs every scan; no external binary required. [naabu](https://github.com/projectdiscovery/naabu) is used only for an explicit `--scan-type syn` (faster on large ranges, needs root), and even then its empty results are re-checked natively.
- **Accurate, not sprayed** — every open port is confirmed with a real handshake; the connect timeout adapts to the target's measured RTT, so slow hosts aren't missed and fast ones aren't slowed; dropped probes are retried and duplicates collapsed. A scan that can't finish in its budget is flagged **incomplete** rather than reported as a clean host.
- **Gentle when it needs to be** — full speed by default, but `--rate` caps new connections/sec (spread evenly, no burst) so a scan can stay under a defended host's rate-based block instead of getting the source IP banned.
- **Service fingerprinting** — active NULL → HTTP → TLS probing with nmap-style banner matching.
- **UDP** — protocol-specific probes for DNS, NTP, and SNMP (`--udp`); a port is reported only on a valid reply, never a blind UDP sweep.
- **CVE matching** — built-in YAML checks plus live NVD lookup with CPE matching and on-disk caching (`--nvd`). Fewer false positives: a CVE is never emitted without a concrete version, duplicates across sources are collapsed, and version-based matches on distro-packaged hosts are flagged *unproven* (distros backport fixes) — `--ssh-audit` confirms against real package versions.
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

Optional: [naabu](https://github.com/projectdiscovery/naabu) on `$PATH`, only for `--scan-type syn` (faster SYN sweeps on large ranges). Not needed for normal scans.

## Usage

Give it a target. Everything runs automatically — port and service
discovery, the bundled CVE checks, the live NVD lookup, default-credential
checks, and UDP service probing. There are no flags to learn for a normal
scan.

```sh
# a host, a subnet, a range, or a file of targets — all the same
./groma scan 10.0.0.5
./groma scan 10.0.0.0/24
./groma scan 10.0.0.1-50
./groma scan --target-file targets.txt
```

It adapts to its environment on its own:

- **Default** → the native connect scanner: reliable, deterministic, no
  external binary. For very large ranges, `--scan-type syn` (needs root
  and naabu) is faster and auto-verifies each hit.
- **`GROMA_SSH_*` set** → runs the credentialed package audit too, which
  confirms version-based findings against the real installed versions.

```sh
export GROMA_SSH_USER=admin
export GROMA_SSH_KEY=~/.ssh/id_ed25519
./groma scan 10.0.0.5            # credentialed audit now runs automatically
```

### Flags

The common ones — most scans need none of them:

```
--ports <spec>          port list/range (nmap format, default 1-65535)
--fast                  top-N ports only
--ping                  skip targets that don't answer a quick TCP probe (sparse subnets)
--target-file <file>    read targets (one host/CIDR/range per line; '-' = stdin)
--compliance <file>     run a Tenable .audit CIS/DISA-STIG policy over SSH
--fail-on <sev>         exit 2 on a confirmed finding at/above severity (low|medium|high|critical)
--format <fmt>          text | json | sarif
-o, --output <file>     output file
-v, --verbose           verbose output
```

Advanced overrides exist but are hidden from `--help` to keep it simple —
e.g. `--nvd=false` / `--check-default-creds=false` / `--udp=false` for a
lean or offline scan, `--scan-type`, `--fail-on-unproven`, and the tuning
flags (`--concurrency`, `--rate`, `--timeout`, …). `--rate` caps new
connections/sec, spread evenly — set it to probe a host gently enough not to
trip a rate-based block (it also passes through to naabu on a SYN scan).

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
  tools/naabu/          naabu CLI wrapper (optional SYN scans only)
  tools/nmap/           nmap XML parser (optional enrichment)
  sysnet/               ulimit-aware concurrency
checks/examples/        example CVE YAML checks
```

## License

Apache-2.0
