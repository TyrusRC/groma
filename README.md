# groma — network vulnerability scanner

groma discovers open ports and services on a host, fingerprints service
versions, and matches them against a declarative YAML check library to
find known vulnerabilities. It's the network-lane counterpart to
[assay](https://github.com/TyrusRC/assay) (web/DAST): assay aims at
Acunetix's job, groma aims at Nessus's/OpenVAS's.

## Why groma

- **Never silently narrows coverage.** The default scan is every TCP
  port, 1-65535 — not a top-100 sample. A scanner that quietly skips
  ports is a scanner that misses findings; groma treats "which ports
  did you actually check" as a correctness question, not a performance
  knob to default away.
- **Fast without sacrificing that.** Port discovery uses
  [naabu](https://github.com/projectdiscovery/naabu) when it's on
  `$PATH` — including its native nmap-service-probes-compatible
  fingerprint engine (`-sV`), so product/version data comes back in the
  same pass, no second tool, no XML to parse. Without naabu, groma falls
  back to its own zero-dependency TCP-connect scanner — ulimit-aware
  concurrency, same full-range default, just slower against a network
  that drops (rather than rejects) unused ports.
- **Declarative checks, not a scripting VM.** A check is a YAML file:
  a service match (product name or CPE prefix) plus an optional version
  range. No knowledge base, no execution-phase scheduler, no NASL-style
  interpreter — the format mirrors assay's nuclei-compatible templates
  (same `info`/`classification` field names) so maintaining both feels
  consistent.
- **Honest about what it didn't check.** If a scan's context times out
  mid-sweep, groma says so and tells you how many ports were never
  reached — it does not quietly report them as "closed."

## What groma does *not* do (yet)

Credentialed/local checks (SSH/WinRM into a host to audit installed
packages — the biggest differentiator of a real Nessus/OpenVAS) and
`.audit`-format CIS/DISA-STIG compliance checks are deliberately not
built. Both are big, separate engines in their own right, not bolted
onto the version-match format above.

## Quickstart

```sh
# install Go 1.24+, then:
go build -o groma ./cmd/groma

# scan a single host, every TCP port (the default)
./groma scan 10.0.0.5

# load a check library and emit JSON
./groma scan --checks ./checks/examples -o report.json --format json 10.0.0.5

# CI gate: exit code 2 if a high-or-above finding is found
./groma scan --checks ./checks/examples --fail-on high 10.0.0.5
```

## Installation

### Requirements

- Go 1.24+ to build.
- [naabu](https://github.com/projectdiscovery/naabu) on `$PATH`,
  optional but recommended — without it, groma still discovers ports
  (via its own TCP-connect scanner) but has no service/version
  fingerprinting, so YAML checks have nothing to match against.

### From source

```sh
git clone https://github.com/TyrusRC/groma.git
cd groma
go build -o groma ./cmd/groma
```

## Usage

```
groma scan <host> [host...] [flags]

Flags:
      --checks string       directory of check YAML files to load and match
      --fail-on string      exit code 2 if a finding at or above this severity
                             is found (none|low|medium|high|critical)
      --fast                scan a top-N ports subset instead of the full
                             1-65535 default (quicker, NOT exhaustive)
      --format string       output format: text, json, sarif (default "text")
  -o, --output string       output file (default: stdout)
      --ports string        explicit port list/range, nmap format
                             (e.g. "80,443" or "1-1000"); overrides --fast
      --rate int             packets/sec rate limit passed to naabu
      --concurrency int      worker concurrency passed to naabu
                             (0 = auto, ulimit-aware)
      --timeout duration    scan timeout per host (default 5m0s)
  -v, --verbose              enable verbose output
```

### Output formats

- `text` — human-readable, worst-finding-first.
- `json` — the full `Report` structure (targets, summary, findings),
  stable and meant for scripting.
- `sarif` — SARIF 2.1.0, for GitHub code scanning and similar CI
  security tabs. Network findings use a synthetic
  `network://host:port` artifact URI since there's no source file.

### Writing a check

```yaml
id: CVE-2021-41773
info:
  name: "Apache HTTP Server 2.4.49-2.4.50 Path Traversal / RCE"
  severity: critical
  reference:
    - https://httpd.apache.org/security/vulnerabilities_24.html
  remediation: "Upgrade to Apache HTTP Server 2.4.51 or later."
  classification:
    cve-id: CVE-2021-41773
    cwe-id: CWE-22
    cvss-score: 7.5
service:
  product: apache
  cpe: "cpe:/a:apache:http_server"
  version:
    gte: "2.4.49"
    lte: "2.4.50"
```

`service.product`/`service.cpe` are alternatives (either matching is
enough); `service.version` bounds are all optional and ANDed together
when present. See `checks/examples/` for a real, verified-working
example.

## Architecture

```
internal/core        — Target, Severity, Finding (shaped like assay's)
internal/discovery    — native TCP-connect scanner (zero-dependency fallback)
internal/detection/legacyprotocol — seed protocol checks (Telnet exposure, FTP anon login)
internal/tools/naabu   — optional naabu wrapper (fast sweep + native -sV fingerprint)
internal/checks        — declarative YAML check format + matching engine
internal/sysnet        — shared ulimit-aware concurrency helper
internal/reporting     — JSON / text / SARIF report rendering
cmd/groma              — the CLI (Cobra)
```

## License

Apache-2.0
