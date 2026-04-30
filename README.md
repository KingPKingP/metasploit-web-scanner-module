# README - MSF Web Vulnerability Scanner Advanced

This guide is for the module:

- `auxiliary/scanner/http/web_vuln_scanner_advanced`
- source file: `/home/god/tools/AI_ramverk/web_vuln_scanner_advanced.rb`

## 1) Install in Metasploit

Copy the module to your local MSF module path:

```bash
mkdir -p ~/.msf4/modules/auxiliary/scanner/http
cp /home/god/web_vuln_scanner_advanced.rb ~/.msf4/modules/auxiliary/scanner/http/
chmod 644 ~/.msf4/modules/auxiliary/scanner/http/web_vuln_scanner_advanced.rb
```

Reload in `msfconsole`:

```text
reload_all
search web_vuln_scanner_advanced
use auxiliary/scanner/http/web_vuln_scanner_advanced
```

## 2) Quick Run

```text
set RHOSTS example.com
set SSL true
set RPORT 443
set TARGETURI /
set FORMAT html
set OUTFILE /tmp/vuln_report
run
```

Generates:

- `/tmp/vuln_report.html`
- `/tmp/vuln_report.json`

## 3) Important Options

- `RHOSTS` - target host(s) (required)
- `RPORT` - port (default 80)
- `SSL` - HTTPS on/off
- `TARGETURI` - starting path (default `/`)
- `FORMAT` - `txt|csv|json|html`
- `OUTFILE` - report output prefix
- `THREADS` - endpoint discovery threads
- `VERBOSE` - verbose runtime output in module console
- `TIMEOUT` - HTTP timeout in seconds
- `FULL_PORTS` - extended common port scan
- `BANNER_CHECK` - banner grabbing on open ports
- `CHECK_TRACE` - checks TRACE/Allow headers
- `CRAWL` - lightweight internal crawl before probes
- `CRAWL_DEPTH` - crawl depth
- `CRAWL_MAX_PAGES` - max crawled pages
- `PROBE_XSS` - reflected XSS probing
- `PROBE_LFI` - LFI/path traversal probing
- `PROBE_SQLI` - SQL injection probing (GET/POST/headers)
- `SQLI_LEVEL` - SQLi intensity: `low|normal|aggressive`

## 4) NVD + Shodan Enrichment

Enable in `msfconsole`:

```text
set NVD_ENRICH true
set NVD_API_KEY <your_nvd_key>
set SHODAN_ENRICH true
set SHODAN_API_KEY <your_shodan_key>
run
```

Or via environment variables:

```bash
export NVD_API_KEY="..."
export SHODAN_API_KEY="..."
```

Notes:

- Keys are runtime-only (not hardcoded in the module).
- Rotate keys if they were exposed in logs/chat.

## 5) What the Module Does

- Common/open port scan
- Service banner grabbing on open ports (optional)
- Security header audit (presence + quality checks)
- CORS checks including origin reflection test
- HTTP method checks (TRACE/PUT/DELETE)
- Threaded endpoint discovery (`/admin`, `/swagger`, `/.env`, `/.git/config`, etc.)
- Lightweight crawl to discover additional paths
- Reflected XSS probes (potential finding)
- LFI/path traversal probes (potential finding)
- SQLi probes on GET/POST/headers (potential finding)
- Baseline-vs-response diff to reduce false positives
- Confidence per finding (`low|medium|high`)
- Export to TXT/CSV/JSON/HTML

## 6) Output and Findings

Reports include:

- Severity
- Confidence
- OWASP category
- Description
- Evidence/snippets
- Discovered endpoints/ports
- (optional) NVD correlation + Shodan data

## 7) Common Errors and Fixes

### A) `NoMethodError: rand_text_alphanumeric`

You are likely running an old module copy.

Fix:

```bash
cp /home/god/web_vuln_scanner_advanced.rb ~/.msf4/modules/auxiliary/scanner/http/web_vuln_scanner_advanced.rb
```

Verify:

```bash
rg -n "Rex::Text.rand_text_alphanumeric" ~/.msf4/modules/auxiliary/scanner/http/web_vuln_scanner_advanced.rb
```

Then:

```text
reload_all
```

### B) `Invalid option RHOSTS: Host resolution failed`

This is a DNS issue in your environment. Test:

```bash
dig +short <domain>
nslookup <domain>
```

Or run with IP:

```text
set RHOSTS <ip>
set VHOST <domain>
```

## 8) Safe Operating Practices

- Run only against targets you are explicitly authorized to test.
- Store API keys in runtime/env, not in source code.
- Do not share reports containing secrets in plain channels.
- Treat `Potential` findings as verification-required before reporting.

## 9) Recommended Profile (Balanced Speed/Coverage)

```text
set THREADS 12
set VERBOSE false
set TIMEOUT 10
set CRAWL true
set CRAWL_DEPTH 1
set CRAWL_MAX_PAGES 40
set PROBE_XSS true
set PROBE_LFI true
set PROBE_SQLI true
set SQLI_LEVEL normal
set CHECK_TRACE true
set FULL_PORTS false
set BANNER_CHECK true
set FORMAT html
```

## 10) Triage Playbook: Potential -> Confirmed

The goal is to quickly verify whether a `Potential` finding is real and reproducible.

### A) Reflected XSS (Potential)

1. Take URL/path + parameter from evidence.
2. Replay request manually in Burp Repeater or curl.
3. Test at least 3 payload variants:
   - HTML context: `<svg/onload=alert(1)>`
   - Attribute breakout: `" onmouseover=alert(1) x="`
   - JS string breakout: `';alert(1);//`
4. Confirm:
   - payload is reflected unsanitized in response
   - execution is possible in browser context (not only raw text)
5. Mark `Confirmed` only when context + executability is clear.

### B) LFI / Path Traversal (Potential)

1. Replay the same endpoint using payload from evidence.
2. Test multiple encoded variants:
   - `../../../../etc/passwd`
   - `..%2f..%2f..%2f..%2fetc%2fpasswd`
   - `..%252f..%252f..%252f..%252fetc%252fpasswd`
3. Confirm with stable markers:
   - `root:x:0:0:` or other passwd signatures
4. Run a benign control request to rule out false positives.
5. Mark `Confirmed` only when file content is actually disclosed.

### C) CORS Reflection / Misconfiguration

1. Send request with attacker origin, for example:
   - `Origin: https://evil.example`
2. Confirm response headers:
   - `Access-Control-Allow-Origin` reflects origin
   - and/or `Access-Control-Allow-Credentials: true`
3. Verify impact:
   - is credentialed cross-origin data access possible?
4. If wildcard + credentials or reflection + credentials: prioritize high.

### D) Endpoint Exposure

1. Confirm endpoint status with at least two requests.
2. Check whether sensitive data is exposed:
   - `/actuator`, `/swagger`, `/.env`, `/.git/config`, `/phpinfo.php`
3. Assess access level:
   - public 200/OK vs auth-required 401/403
4. `Confirmed` when actual data leakage/misconfiguration is demonstrated.

### E) Confidence Interpretation

- `high`: multiple signals match (status/content shift + clear payload marker)
- `medium`: partial signals, requires manual confirmation
- `low`: weak signal, lower triage priority

### F) Minimum Reporting Criteria

1. Reproducible steps (request/response evidence).
2. Clear impact statement.
3. Scope/affected surface (which paths/parameters).
4. Recommended fix (input validation/output encoding/access control).

### G) SQL Injection (Potential) - GET / POST / Headers

1. Replay endpoint from evidence in Burp Repeater.
2. Test GET parameters like `id`, `q`, `search` with payloads:
   - `' OR '1'='1`
   - `" OR "1"="1`
   - `' UNION SELECT NULL-- `
3. Test POST body with same payloads (for example `username`, `password`, `search`).
4. Test headers with payloads:
   - `X-Forwarded-For`
   - `X-Api-Version`
   - `User-Agent`
5. Confirm clear SQL signatures in responses:
   - `SQL syntax`, `Unclosed quotation mark`, `MySQL`, `PostgreSQL`, `ODBC`
6. Compare against baseline/benign request to rule out false positives.
7. Mark `Confirmed` when payload causes reproducible SQL-error signal or clear behavior deviation.
