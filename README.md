# MSF Web Vulnerability Scanner Advanced

Advanced Metasploit auxiliary scanner for web assessment with structured reporting, probe orchestration, enrichment, and triage-friendly findings.

- Module path: `auxiliary/scanner/http/web_vuln_scanner_advanced`
- Source file: `/root/web_vuln_scanner_advanced.rb`

## Features

- Port scan with optional service banner grabbing
- Security header audit + header quality checks
- Cookie security checks (`Secure`, `HttpOnly`, `SameSite`)
- TLS posture checks (certificate expiry, weak TLS versions/ciphers)
- Endpoint discovery + lightweight crawl
- Passive discovery:
  - crt.sh subdomain enrichment
  - Wayback CDX historical endpoints
- Injection probes (potential findings):
  - XSS, LFI/path traversal, SQLi (GET/POST/headers)
  - SSTI, SSRF, command injection, NoSQLi, XXE
- Misconfiguration checks:
  - sensitive files, backup file variants, security.txt
  - CORS + CORS preflight abuse
  - cache-control on sensitive endpoints
  - open redirect checks
  - WAF heuristic detection
  - response fuzzing / verbose error leakage
  - optional session fixation + CSRF enforcement heuristics
- NVD + Shodan enrichment
- Exports: `html`, `json`, `csv`, `txt`
- Per-finding confidence scoring (`low|medium|high`)

## Install

```bash
mkdir -p ~/.msf4/modules/auxiliary/scanner/http
cp /root/web_vuln_scanner_advanced.rb ~/.msf4/modules/auxiliary/scanner/http/
chmod 644 ~/.msf4/modules/auxiliary/scanner/http/web_vuln_scanner_advanced.rb
```

In `msfconsole`:

```text
reload_all
search web_vuln_scanner_advanced
use auxiliary/scanner/http/web_vuln_scanner_advanced
```

## Quick Start

```text
set RHOSTS example.com
set SSL true
set RPORT 443
set TARGETURI /
set FORMAT html
set OUTFILE /tmp/vuln_report
run
```

Output files:

- `/tmp/vuln_report.html`
- `/tmp/vuln_report.json`
- `/tmp/vuln_report.csv` (if `FORMAT csv`)
- `/tmp/vuln_report.txt` (if `FORMAT txt`)

## High-Coverage Profile

```text
set THREADS 12
set VERBOSE false
set TIMEOUT 10

set FULL_PORTS false
set BANNER_CHECK true

set CRAWL true
set CRAWL_DEPTH 1
set CRAWL_MAX_PAGES 40

set PROBE_XSS true
set PROBE_LFI true
set PROBE_SQLI true
set SQLI_LEVEL normal
set PROBE_SSTI true
set PROBE_SSRF true
set PROBE_CMDI true
set PROBE_NOSQLI true
set PROBE_XXE true

set CHECK_TRACE true
set CHECK_SENSITIVE_FILES true
set CHECK_BACKUP_FILES true
set CHECK_COOKIE_SECURITY true
set CHECK_TLS true
set CHECK_SECURITY_TXT true
set CHECK_CORS_PREFLIGHT true
set CHECK_CACHE_CONTROL true
set CHECK_WAF true
set CHECK_RESPONSE_FUZZING true
set CHECK_OPEN_REDIRECT true

set PASSIVE_SUBDOMAIN_ENUM false
set WAYBACK_ENUM false
set CHECK_SESSION_FIXATION false
set CHECK_CSRF false

set FORMAT html
run
```

## Option Reference

### Core

- `RHOSTS` target host(s)
- `RPORT` target port
- `SSL` use HTTPS
- `TARGETURI` base URI path
- `FORMAT` one of `txt|csv|json|html`
- `OUTFILE` output file prefix
- `TIMEOUT` HTTP timeout seconds
- `THREADS` endpoint discovery threads
- `VERBOSE` verbose module logging

### Recon / Discovery

- `FULL_PORTS` extended common-port set
- `BANNER_CHECK` service banner grab on open ports
- `CRAWL` enable lightweight crawl
- `CRAWL_DEPTH` crawl depth
- `CRAWL_MAX_PAGES` page limit
- `PASSIVE_SUBDOMAIN_ENUM` query crt.sh for related hosts
- `WAYBACK_ENUM` pull historical endpoints from Wayback CDX

### Probe Controls

- `PROBE_XSS`
- `PROBE_LFI`
- `PROBE_SQLI`
- `SQLI_LEVEL` `low|normal|aggressive`
- `PROBE_SSTI`
- `PROBE_SSRF`
- `PROBE_CMDI`
- `PROBE_NOSQLI`
- `PROBE_XXE`

### Security / Misconfig Checks

- `CHECK_TRACE`
- `CHECK_SENSITIVE_FILES`
- `CHECK_BACKUP_FILES`
- `CHECK_COOKIE_SECURITY`
- `CHECK_TLS`
- `CHECK_SECURITY_TXT`
- `CHECK_CORS_PREFLIGHT`
- `CHECK_CACHE_CONTROL`
- `CHECK_WAF`
- `CHECK_RESPONSE_FUZZING`
- `CHECK_OPEN_REDIRECT`
- `CHECK_SESSION_FIXATION` (heuristic)
- `CHECK_CSRF` (heuristic)

### Enrichment

- `NVD_ENRICH`
- `NVD_API_KEY`
- `SHODAN_ENRICH`
- `SHODAN_API_KEY`

## NVD + Shodan Usage

In `msfconsole`:

```text
set NVD_ENRICH true
set NVD_API_KEY <your_nvd_key>
set SHODAN_ENRICH true
set SHODAN_API_KEY <your_shodan_key>
run
```

Or set environment variables before starting Metasploit:

```bash
export NVD_API_KEY="..."
export SHODAN_API_KEY="..."
```

## Reporting

### HTML

- Risk score + risk tier
- Open ports
- Discovered endpoints
- Findings table with severity + confidence + evidence

### JSON

Includes:

- `open_ports`
- `port_banners`
- `discovered_endpoints`
- `findings`
- `nvd_matches`
- `shodan`

## Troubleshooting

### `NoMethodError: rand_text_alphanumeric`

Old module copy loaded by Metasploit.

```bash
cp /root/web_vuln_scanner_advanced.rb ~/.msf4/modules/auxiliary/scanner/http/web_vuln_scanner_advanced.rb
```

Then in `msfconsole`:

```text
reload_all
```

### `Invalid option RHOSTS: Host resolution failed`

DNS resolution issue.

```bash
dig +short <domain>
nslookup <domain>
```

Fallback:

```text
set RHOSTS <ip>
set VHOST <domain>
```

## Safety Notes

- Use only on authorized targets.
- Do not hardcode API keys in source.
- Rotate keys if exposed.
- Treat all `Potential` findings as verification-required before disclosure.
