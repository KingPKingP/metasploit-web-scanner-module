# README - MSF Web Vulnerability Scanner Advanced

Den här guiden gäller modulen:

- `auxiliary/scanner/http/web_vuln_scanner_advanced`
- källfil: `/home/god/tools/AI_ramverk/web_vuln_scanner_advanced.rb`

## 1) Installation i Metasploit

Kopiera modulen till din lokala MSF-modulpath:

```bash
mkdir -p ~/.msf4/modules/auxiliary/scanner/http
cp /home/god/tools/AI_ramverk/web_vuln_scanner_advanced.rb ~/.msf4/modules/auxiliary/scanner/http/
chmod 644 ~/.msf4/modules/auxiliary/scanner/http/web_vuln_scanner_advanced.rb
```

Ladda om i `msfconsole`:

```text
reload_all
search web_vuln_scanner_advanced
use auxiliary/scanner/http/web_vuln_scanner_advanced
```

## 2) Snabbkörning

```text
set RHOSTS example.com
set SSL true
set RPORT 443
set TARGETURI /
set FORMAT html
set OUTFILE /tmp/vuln_report
run
```

Genererar:

- `/tmp/vuln_report.html`
- `/tmp/vuln_report.json`

## 3) Viktiga options

- `RHOSTS` - målhost/ar (krävs)
- `RPORT` - port (default 80)
- `SSL` - HTTPS av/på
- `TARGETURI` - path att starta från (default `/`)
- `FORMAT` - `txt|csv|json|html`
- `OUTFILE` - filprefix för rapport
- `THREADS` - antal trådar för endpoint discovery
- `VERBOSE` - verbose runtime output i modul-konsolen
- `TIMEOUT` - HTTP-timeout i sekunder
- `FULL_PORTS` - utökad common-portscan
- `BANNER_CHECK` - banner-grabbing på öppna portar
- `CHECK_TRACE` - kollar TRACE/Allow headers
- `CRAWL` - enkel intern crawl före probes
- `CRAWL_DEPTH` - crawl-djup
- `CRAWL_MAX_PAGES` - max antal crawlande sidor
- `PROBE_XSS` - reflekterad XSS-probing
- `PROBE_LFI` - LFI/path traversal-probing
- `PROBE_SQLI` - SQL injection-probing (GET/POST/headers)
- `SQLI_LEVEL` - SQLi-intensitet: `low|normal|aggressive`

## 4) NVD + Shodan enrichment

Aktivera i `msfconsole`:

```text
set NVD_ENRICH true
set NVD_API_KEY <din_nvd_nyckel>
set SHODAN_ENRICH true
set SHODAN_API_KEY <din_shodan_nyckel>
run
```

Alternativt via environment:

```bash
export NVD_API_KEY="..."
export SHODAN_API_KEY="..."
```

Notera:

- Nycklar är runtime-only (inte hårdkodade i modulen).
- Rotera nycklar om de exponerats i loggar/chat.

## 5) Vad modulen gör

- Common/open-port scan
- Security header audit (presence + quality checks)
- CORS checks inkl. origin reflection-test
- HTTP method checks (TRACE/PUT/DELETE)
- Threaded endpoint discovery (`/admin`, `/swagger`, `/.env`, `/.git/config`, etc.)
- Reflected XSS probes (potential finding)
- LFI/path traversal probes (potential finding)
- Baseline-vs-response diff för att minska falska positiva
- Confidence per finding (`low|medium|high`)
- Export till TXT/CSV/JSON/HTML

## 6) Output och fynd

Rapporten innehåller:

- Severity
- Confidence
- OWASP-kategori
- Beskrivning
- Evidence/snippets
- Upptäckta endpoints/ports
- (valfritt) NVD-korrelation + Shodan-data

## 7) Vanliga fel och fix

### A) `NoMethodError: rand_text_alphanumeric`

Du kör sannolikt gammal modulfil.

Fix:

```bash
cp /home/god/tools/AI_ramverk/web_vuln_scanner_advanced.rb ~/.msf4/modules/auxiliary/scanner/http/web_vuln_scanner_advanced.rb
```

Verifiera:

```bash
rg -n "Rex::Text.rand_text_alphanumeric" ~/.msf4/modules/auxiliary/scanner/http/web_vuln_scanner_advanced.rb
```

Sedan:

```text
reload_all
```

### B) `Invalid option RHOSTS: Host resolution failed`

DNS-problem i miljön. Testa:

```bash
dig +short <domän>
nslookup <domän>
```

Eller kör med IP:

```text
set RHOSTS <ip>
set VHOST <domän>
```

## 8) Säkert arbetssätt

- Kör endast mot mål där du har explicit tillstånd.
- Lagra API-nycklar i runtime/env, inte i kod.
- Dela inte rapporter med hemligheter okrypterat.
- Behandla `Potential` findings som verifieringskrävande innan rapportering.

## 9) Rekommenderad profil (balans fart/täckning)

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

Målet är att snabbt verifiera om ett `Potential`-fynd är verkligt och reproducerbart.

### A) Reflected XSS (Potential)

1. Ta URL/path + parameter från evidence.
2. Repetera request manuellt i Burp Repeater eller curl.
3. Testa minst 3 payload-varianter:
   - HTML context: `<svg/onload=alert(1)>`
   - Attribute breakout: `" onmouseover=alert(1) x="`
   - JS string breakout: `';alert(1);//`
4. Bekräfta:
   - payload reflekteras osanerad i respons
   - exekvering möjlig i browser-context (inte bara rå text)
5. Markera `Confirmed` först när context + exekverbarhet är tydlig.

### B) LFI / Path Traversal (Potential)

1. Repetera samma endpoint med payload från evidence.
2. Testa flera encoding-varianter:
   - `../../../../etc/passwd`
   - `..%2f..%2f..%2f..%2fetc%2fpasswd`
   - `..%252f..%252f..%252f..%252fetc%252fpasswd`
3. Bekräfta med stabila markörer:
   - `root:x:0:0:` eller andra passwd-signaturer
4. Kör kontrollrequest (benign värde) för att utesluta falsk positiv.
5. Markera `Confirmed` först när filinnehåll faktiskt läcks.

### C) CORS Reflection / Misconfiguration

1. Skicka request med attacker-origin, ex:
   - `Origin: https://evil.example`
2. Bekräfta responsheaders:
   - `Access-Control-Allow-Origin` reflekterar origin
   - och/eller `Access-Control-Allow-Credentials: true`
3. Verifiera impact:
   - credentialed cross-origin data access möjlig?
4. Om wildcard + credentials eller reflektion + credentials: hög prioritet.

### D) Endpoint Exposure

1. Bekräfta endpoint-status i minst två requests.
2. Kontrollera om känslig data exponeras:
   - `/actuator`, `/swagger`, `/.env`, `/.git/config`, `/phpinfo.php`
3. Bedöm åtkomstnivå:
   - publik 200/OK vs auth-required 401/403
4. `Confirmed` när faktisk informationsläcka/misconfig visas.

### E) Confidence-tolkning

- `high`: flera signaler matchar (status-/content-skifte + tydlig payloadmarkör)
- `medium`: vissa signaler matchar men kräver manuell bekräftelse
- `low`: svag signal, prioritera sist


### G) SQL Injection (Potential) - GET / POST / Headers

1. Repetera endpoint från evidence i Burp Repeater.
2. Testa GET-parametrar: `id`, `q`, `search` med payloads:
   - `' OR '1'='1`
   - `" OR "1"="1`
   - `' UNION SELECT NULL-- `
3. Testa POST-body med samma payloads (t.ex. `username`, `password`, `search`).
4. Testa headers med payloads:
   - `X-Forwarded-For`
   - `X-Api-Version`
   - `User-Agent`
5. Bekräfta med tydliga SQL-signaturer i svar:
   - `SQL syntax`, `Unclosed quotation mark`, `MySQL`, `PostgreSQL`, `ODBC`
6. Jämför mot baseline/benign request för att utesluta falsk positiv.
7. Markera `Confirmed` när payload ger reproducerbar SQL-felindikator eller tydlig beteendeavvikelse.

### F) Minimikrav innan rapportering

1. Reproducerbara steg (kopiera request/response).
2. Tydlig impact-beskrivning.
3. Avgränsning (vilka paths/parametrar påverkas).
4. Rekommenderad fix (input-validering/output-encoding/access-kontroll).
