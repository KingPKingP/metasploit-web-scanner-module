##
# Web Vulnerability Scanner Advanced
# Metasploit Auxiliary Module
#
# Upgraded from a baseline scanner:
# - Threaded endpoint discovery
# - Header value quality checks (not only presence)
# - Additional weak-config checks
# - CORS reflection checks with custom Origin
# - Finding dedupe + evidence fields
# - Safer HTML escaping in reports
# - JSON export includes metadata and endpoint evidence
##

require 'json'
require 'csv'
require 'socket'
require 'timeout'
require 'cgi'
require 'uri'
require 'net/http'
require 'openssl'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'Web Vulnerability Scanner Advanced',
      'Description' => 'Scans ports, headers, CORS, endpoints, and weak web exposures with evidence-rich reports',
      'Author' => ['Dhananjay DK', 'Codex Upgrade'],
      'License' => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(80),
        OptBool.new('SSL', [false, 'Use HTTPS', false]),
        OptString.new('TARGETURI', [true, 'Target URI', '/']),
        OptString.new('FORMAT', [true, 'txt/csv/json/html', 'html']),
        OptString.new('OUTFILE', [true, 'Output file path', '/tmp/vulnerability_report']),
        OptInt.new('TIMEOUT', [true, 'HTTP timeout seconds', 10]),
        OptInt.new('THREADS', [true, 'Endpoint discovery threads', 12]),
        OptBool.new('VERBOSE', [true, 'Verbose runtime output', false]),
        OptBool.new('FULL_PORTS', [false, 'Scan extended common ports', false]),
        OptBool.new('BANNER_CHECK', [true, 'Grab service banners on open ports', true]),
        OptBool.new('CHECK_TRACE', [true, 'Check TRACE method enabled', true]),
        OptBool.new('CRAWL', [true, 'Enable lightweight crawl before probes', true]),
        OptInt.new('CRAWL_DEPTH', [true, 'Crawl depth (0-3 recommended)', 1]),
        OptInt.new('CRAWL_MAX_PAGES', [true, 'Max pages to crawl', 40]),
        OptBool.new('PROBE_XSS', [true, 'Probe for reflected XSS patterns', true]),
        OptBool.new('PROBE_LFI', [true, 'Probe for path traversal/LFI patterns', true]),
        OptBool.new('PROBE_SQLI', [true, 'Probe for SQL injection patterns (GET/POST/headers)', true]),
        OptString.new('SQLI_LEVEL', [true, 'SQLi probe intensity: low|normal|aggressive', 'normal']),
        OptBool.new('PROBE_SSTI', [true, 'Probe for SSTI patterns', true]),
        OptBool.new('PROBE_SSRF', [true, 'Probe for SSRF patterns', true]),
        OptBool.new('PROBE_CMDI', [true, 'Probe for command injection patterns', true]),
        OptBool.new('PROBE_NOSQLI', [true, 'Probe for NoSQL injection patterns', true]),
        OptBool.new('PROBE_XXE', [true, 'Probe for XXE patterns', true]),
        OptBool.new('CHECK_SENSITIVE_FILES', [true, 'Check sensitive file exposure', true]),
        OptBool.new('CHECK_BACKUP_FILES', [true, 'Check backup/old/temporary file variants', true]),
        OptBool.new('CHECK_COOKIE_SECURITY', [true, 'Check Secure/HttpOnly/SameSite cookie flags', true]),
        OptBool.new('CHECK_TLS', [true, 'Check TLS versions/ciphers/certificate validity', true]),
        OptBool.new('CHECK_SECURITY_TXT', [true, 'Check /.well-known/security.txt', true]),
        OptBool.new('CHECK_CORS_PREFLIGHT', [true, 'Check CORS preflight abuse patterns', true]),
        OptBool.new('CHECK_CACHE_CONTROL', [true, 'Check sensitive endpoints for cacheable responses', true]),
        OptBool.new('CHECK_WAF', [true, 'Probe and detect common WAF patterns', true]),
        OptBool.new('CHECK_RESPONSE_FUZZING', [true, 'Fuzz malformed requests and detect verbose errors', true]),
        OptBool.new('CHECK_OPEN_REDIRECT', [true, 'Probe open redirect parameters', true]),
        OptBool.new('CHECK_SESSION_FIXATION', [false, 'Heuristic session fixation check on login flow', false]),
        OptBool.new('PASSIVE_SUBDOMAIN_ENUM', [false, 'Passive subdomain discovery via crt.sh', false]),
        OptBool.new('WAYBACK_ENUM', [false, 'Fetch historical paths from Wayback Machine CDX API', false]),
        OptBool.new('CHECK_CSRF', [false, 'Heuristic CSRF token enforcement check', false]),
        OptBool.new('NVD_ENRICH', [false, 'Enrich findings with NVD CVE data', false]),
        OptString.new('NVD_API_KEY', [false, 'NVD API key (or use ENV NVD_API_KEY)', '']),
        OptBool.new('SHODAN_ENRICH', [false, 'Enrich target host with Shodan data', false]),
        OptString.new('SHODAN_API_KEY', [false, 'Shodan API key (or use ENV SHODAN_API_KEY)', ''])
      ]
    )
  end

  def run_host(ip)
    @findings = []
    @present_headers = []
    @open_ports = []
    @port_banners = []
    @endpoints = []
    @finding_keys = {}
    @nvd_matches = []
    @shodan_data = {}

    print_status("#{ip} - Starting advanced vulnerability scan")
    scan_ports(ip)
    run_web_checks(ip)
    enrich_with_shodan(ip) if datastore['SHODAN_ENRICH']
    enrich_with_nvd(ip) if datastore['NVD_ENRICH']
    show_summary(ip)
    export_report(ip)
  end

  def vprint_status(msg)
    print_status(msg) if datastore['VERBOSE']
  end

  def vprint_good(msg)
    print_good(msg) if datastore['VERBOSE']
  end

  def nvd_api_key
    k = datastore['NVD_API_KEY'].to_s.strip
    return k unless k.empty?
    ENV['NVD_API_KEY'].to_s.strip
  end

  def shodan_api_key
    k = datastore['SHODAN_API_KEY'].to_s.strip
    return k unless k.empty?
    ENV['SHODAN_API_KEY'].to_s.strip
  end

  def add_finding(type, severity, message, owasp, evidence = {})
    type_s = utf8_clean(type.to_s)
    severity_s = utf8_clean(severity.to_s)
    message_s = utf8_clean(message.to_s)
    owasp_s = utf8_clean(owasp.to_s)
    evidence_h = deep_utf8(evidence)
    key = [type_s, severity_s, message_s, owasp_s].join('|')
    return if @finding_keys[key]

    confidence = confidence_from_evidence(evidence_h)
    @finding_keys[key] = true
    @findings << {
      type: type_s,
      severity: severity_s,
      message: message_s,
      owasp: owasp_s,
      confidence: confidence,
      evidence: evidence_h
    }
  end

  def utf8_clean(value)
    s = value.to_s.dup
    s.force_encoding('UTF-8')
    s.encode('UTF-8', invalid: :replace, undef: :replace, replace: '?')
  rescue
    value.to_s.encode('UTF-8', invalid: :replace, undef: :replace, replace: '?')
  end

  def deep_utf8(obj)
    case obj
    when String
      utf8_clean(obj)
    when Array
      obj.map { |v| deep_utf8(v) }
    when Hash
      obj.each_with_object({}) { |(k, v), h| h[deep_utf8(k)] = deep_utf8(v) }
    else
      obj
    end
  end

  def confidence_from_evidence(evidence)
    return 'low' unless evidence.is_a?(Hash)

    score = 0
    score += 1 if evidence[:status]
    score += 1 if evidence[:snippet].to_s.length >= 40
    score += 1 if evidence[:marker].to_s.length > 0
    score += 1 if evidence[:payload].to_s.length > 0
    score += 1 if evidence[:digest_changed] == true
    score += 1 if evidence[:status_changed] == true
    score += 1 if evidence[:len_delta].to_i > 40

    return 'high' if score >= 4
    return 'medium' if score >= 2
    'low'
  end

  def scan_ports(ip)
    base_ports = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 5432, 6379, 8080, 8443]
    extra_ports = [135, 139, 445, 9200, 11211, 27017, 5000, 5601]
    ports = datastore['FULL_PORTS'] ? (base_ports + extra_ports).uniq : base_ports

    print_status("#{ip} - Scanning ports (#{ports.length} targets)")
    ports.each do |port|
      begin
        Timeout.timeout(1) do
          sock = TCPSocket.new(ip, port)
          @open_ports << port
          vprint_good("#{ip} - Port #{port} OPEN")
          if datastore['BANNER_CHECK']
            banner = grab_banner(sock, ip, port)
            if banner && !banner.empty?
              @port_banners << { port: port, banner: banner }
              if banner =~ /openssh|apache|nginx|postgresql|mysql|redis|vsftpd|proftpd/i
                add_finding('Service Banner Disclosure', 'Low', "Service banner exposed on port #{port}", 'A05 Security Misconfiguration', { port: port, banner: banner })
              end
            end
          end
          sock.close
        end
      rescue
      end
    end
  end

  def grab_banner(sock, ip, port)
    begin
      sock.write("HEAD / HTTP/1.0\r\nHost: #{ip}\r\n\r\n") if [80, 8080, 8000, 8888].include?(port)
      sock.write("QUIT\r\n") if [21, 25, 110, 143].include?(port)
      sock.write("\n") if [22, 3306, 5432, 6379].include?(port)
      if IO.select([sock], nil, nil, 1.0)
        data = sock.recv(512).to_s
        data = data.gsub(/[\r\n\t]+/, ' ').strip
        return utf8_clean(data[0, 220])
      end
    rescue
    end
    ''
  end

  def run_web_checks(ip)
    res = send_request_cgi(
      {
        'uri' => normalize_uri(datastore['TARGETURI']),
        'method' => 'GET'
      }, datastore['TIMEOUT']
    )

    if res.nil?
      print_error("#{ip} - No HTTP response from target URI")
      return
    end

    base_uri = normalize_uri(datastore['TARGETURI'])
    print_good("#{ip} - HTTP #{res.code}")
    audit_headers(ip, res.headers)
    check_cookie_security(ip, res) if datastore['CHECK_COOKIE_SECURITY']
    audit_server_fingerprint(ip, res.headers)
    check_security_txt(ip) if datastore['CHECK_SECURITY_TXT']
    check_tls_posture(ip) if datastore['CHECK_TLS']
    audit_cors(ip, base_uri)
    check_http_methods(ip, base_uri) if datastore['CHECK_TRACE']
    discover_endpoints(ip)
    crawl_endpoints(ip) if datastore['CRAWL']
    passive_subdomain_enum(ip) if datastore['PASSIVE_SUBDOMAIN_ENUM']
    wayback_enum(ip) if datastore['WAYBACK_ENUM']
    run_reflected_xss_probes(ip) if datastore['PROBE_XSS']
    run_lfi_traversal_probes(ip) if datastore['PROBE_LFI']
    run_sqli_probes(ip) if datastore['PROBE_SQLI']
    run_ssti_probes(ip) if datastore['PROBE_SSTI']
    run_ssrf_probes(ip) if datastore['PROBE_SSRF']
    run_cmdi_probes(ip) if datastore['PROBE_CMDI']
    run_nosqli_probes(ip) if datastore['PROBE_NOSQLI']
    run_xxe_probes(ip) if datastore['PROBE_XXE']
    check_sensitive_files(ip) if datastore['CHECK_SENSITIVE_FILES']
    check_backup_file_variants(ip) if datastore['CHECK_BACKUP_FILES']
    check_cors_preflight(ip, base_uri) if datastore['CHECK_CORS_PREFLIGHT']
    check_cache_control(ip) if datastore['CHECK_CACHE_CONTROL']
    detect_waf(ip, base_uri) if datastore['CHECK_WAF']
    check_response_fuzzing(ip, base_uri) if datastore['CHECK_RESPONSE_FUZZING']
    check_open_redirect(ip) if datastore['CHECK_OPEN_REDIRECT']
    check_session_fixation(ip) if datastore['CHECK_SESSION_FIXATION']
    check_csrf_enforcement(ip) if datastore['CHECK_CSRF']
  rescue ::Exception => e
    print_error("#{ip} - #{e.class}: #{e}")
  end

  def audit_headers(ip, h)
    print_status("#{ip} - Checking security headers")
    check_header(ip, h, 'Content-Security-Policy', 'High', 'Missing CSP increases XSS risk', 'A03 Injection')
    check_header(ip, h, 'Strict-Transport-Security', 'High', 'Missing HSTS may allow downgrade attacks', 'A02 Cryptographic Failures')
    check_header(ip, h, 'X-Frame-Options', 'Medium', 'Missing clickjacking protection', 'A05 Security Misconfiguration')
    check_header(ip, h, 'X-Content-Type-Options', 'Medium', 'Missing MIME sniffing protection', 'A05 Security Misconfiguration')
    check_header(ip, h, 'X-XSS-Protection', 'Low', 'Missing X-XSS-Protection header', 'A05 Security Misconfiguration')
    check_header(ip, h, 'Referrer-Policy', 'Low', 'Sensitive URLs may leak', 'A01 Broken Access Control')
    check_header(ip, h, 'Permissions-Policy', 'Low', 'Browser features overexposed', 'A05 Security Misconfiguration')

    # Quality checks
    csp = h['Content-Security-Policy'].to_s
    if !csp.empty? && csp =~ /unsafe-inline|unsafe-eval/i
      add_finding('Content-Security-Policy', 'Medium', 'Weak CSP contains unsafe-inline or unsafe-eval', 'A05 Security Misconfiguration', { csp: csp[0, 300] })
    end

    xfo = h['X-Frame-Options'].to_s
    if !xfo.empty? && !(xfo.casecmp('DENY').zero? || xfo.casecmp('SAMEORIGIN').zero?)
      add_finding('X-Frame-Options', 'Low', "Unexpected X-Frame-Options value: #{xfo}", 'A05 Security Misconfiguration', { value: xfo })
    end

    xcto = h['X-Content-Type-Options'].to_s
    if !xcto.empty? && xcto.downcase != 'nosniff'
      add_finding('X-Content-Type-Options', 'Low', "Unexpected X-Content-Type-Options value: #{xcto}", 'A05 Security Misconfiguration', { value: xcto })
    end
  end

  def check_header(ip, headers, key, sev, msg, owasp)
    if headers[key]
      @present_headers << key
      vprint_good("#{ip} - #{key}: PRESENT")
    else
      print_warning("#{ip} - #{key}: MISSING")
      add_finding(key, sev, msg, owasp)
    end
  end

  def audit_server_fingerprint(ip, h)
    server = h['Server'].to_s
    powered = h['X-Powered-By'].to_s

    if !server.empty?
      if server =~ /apache\/2\.2|nginx\/1\.[0-9]\b|iis\/6|php\/5/i
        add_finding('Server Banner', 'Medium', "Potentially outdated server banner: #{server}", 'A06 Vulnerable and Outdated Components', { server: server })
      else
        add_finding('Server Banner Disclosure', 'Low', "Server header discloses technology: #{server}", 'A05 Security Misconfiguration', { server: server })
      end
    end

    if !powered.empty?
      add_finding('X-Powered-By Disclosure', 'Low', "X-Powered-By header present: #{powered}", 'A05 Security Misconfiguration', { powered_by: powered })
    end
  end

  def audit_cors(ip, base_uri)
    test_origin = "https://evil.example"
    res = send_request_cgi(
      {
        'uri' => base_uri,
        'method' => 'GET',
        'headers' => { 'Origin' => test_origin }
      }, datastore['TIMEOUT']
    )
    return if res.nil?

    acao = res.headers['Access-Control-Allow-Origin'].to_s
    acac = res.headers['Access-Control-Allow-Credentials'].to_s.downcase

    if acao == '*'
      add_finding('CORS', 'High', 'Wildcard origin enabled', 'A05 Security Misconfiguration', { acao: acao, acac: acac })
    end
    if acao == '*' && acac == 'true'
      add_finding('CORS', 'Critical', 'Wildcard origin with credentials=true', 'A01 Broken Access Control', { acao: acao, acac: acac })
    end
    if acao == test_origin
      sev = acac == 'true' ? 'Critical' : 'High'
      add_finding('CORS Reflection', sev, 'Origin reflected from attacker-controlled Origin header', 'A01 Broken Access Control', { reflected_origin: acao, acac: acac })
    end
  rescue
  end

  def check_http_methods(ip, base_uri)
    res = send_request_cgi({ 'uri' => base_uri, 'method' => 'OPTIONS' }, datastore['TIMEOUT'])
    return if res.nil?

    allow = res.headers['Allow'].to_s
    if allow =~ /\bTRACE\b/i
      add_finding('HTTP Methods', 'Medium', 'TRACE method appears enabled', 'A05 Security Misconfiguration', { allow: allow })
    end
    if allow =~ /\bPUT\b|\bDELETE\b/i
      add_finding('HTTP Methods', 'Medium', "Potentially risky methods allowed: #{allow}", 'A05 Security Misconfiguration', { allow: allow })
    end
  rescue
  end

  def check_tls_posture(ip)
    return unless datastore['SSL']
    begin
      tcp = TCPSocket.new(ip, datastore['RPORT'].to_i)
      ssl = OpenSSL::SSL::SSLSocket.new(tcp, OpenSSL::SSL::SSLContext.new)
      ssl.hostname = ip if ssl.respond_to?(:hostname=)
      ssl.connect
      cert = ssl.peer_cert
      proto = ssl.ssl_version.to_s
      cipher = ssl.cipher&.first.to_s

      if cert
        if cert.not_after < Time.now
          add_finding('TLS Certificate', 'High', 'TLS certificate is expired', 'A02 Cryptographic Failures', { expires_at: cert.not_after.to_s })
        elsif cert.not_after < Time.now + (14 * 24 * 3600)
          add_finding('TLS Certificate', 'Medium', 'TLS certificate expires within 14 days', 'A02 Cryptographic Failures', { expires_at: cert.not_after.to_s })
        end
      end
      if proto =~ /TLSv1(\.0|\.1)?/i
        add_finding('TLS Version', 'High', "Legacy TLS version in use: #{proto}", 'A02 Cryptographic Failures', { protocol: proto, cipher: cipher })
      end
      if cipher =~ /RC4|3DES|DES|NULL|MD5/i
        add_finding('TLS Cipher', 'High', "Weak TLS cipher negotiated: #{cipher}", 'A02 Cryptographic Failures', { protocol: proto, cipher: cipher })
      end
      ssl.close rescue nil
      tcp.close rescue nil
    rescue
    end
  end

  def check_cookie_security(ip, res)
    raw = res.headers['Set-Cookie'].to_s
    return if raw.empty?
    cookies = raw.split(/\n|,\s*(?=[^;]+=)/).map(&:strip).reject(&:empty?)
    cookies.each do |cookie|
      flags = cookie.downcase
      add_finding('Cookie Security', 'Medium', 'Cookie missing Secure flag', 'A05 Security Misconfiguration', { cookie: cookie[0, 120] }) unless flags.include?('secure')
      add_finding('Cookie Security', 'Medium', 'Cookie missing HttpOnly flag', 'A05 Security Misconfiguration', { cookie: cookie[0, 120] }) unless flags.include?('httponly')
      add_finding('Cookie Security', 'Low', 'Cookie missing SameSite attribute', 'A05 Security Misconfiguration', { cookie: cookie[0, 120] }) unless flags.include?('samesite')
    end
  end

  def check_security_txt(ip)
    r = send_request_cgi({ 'uri' => '/.well-known/security.txt', 'method' => 'GET' }, datastore['TIMEOUT'])
    return if r.nil?
    if r.code.to_i == 200
      body = r.body.to_s
      contacts = body.scan(/^Contact:\s*(.+)$/i).flatten
      add_finding('security.txt', 'Low', "security.txt discovered (contacts: #{contacts.length})", 'A05 Security Misconfiguration', { contacts: contacts.take(5), snippet: body[0, 240] })
    else
      add_finding('security.txt', 'Low', 'security.txt not found', 'A05 Security Misconfiguration', { status: r.code })
    end
  rescue
  end

  def check_sensitive_files(ip)
    paths = %w[/.git/config /.env /.DS_Store /phpinfo.php /server-status /web.config /backup/ /config.php.bak]
    paths.each do |path|
      begin
        r = send_request_cgi({ 'uri' => path, 'method' => 'GET' }, datastore['TIMEOUT'])
        next if r.nil?
        if [200, 206].include?(r.code.to_i)
          add_finding('Sensitive File Exposure', 'High', "Sensitive path accessible: #{path}", 'A05 Security Misconfiguration', { path: path, status: r.code })
        end
      rescue
      end
    end
  end

  def check_backup_file_variants(ip)
    suffixes = %w[.bak .old .backup .save ~ .swp .swo .orig .copy .back]
    targets = @endpoints.map { |e| e[:path].to_s }.select { |p| p.start_with?('/') }.take(80)
    targets << normalize_uri(datastore['TARGETURI'])
    targets.uniq.each do |path|
      suffixes.each do |suf|
        begin
          candidate = "#{path}#{suf}"
          r = send_request_cgi({ 'uri' => candidate, 'method' => 'GET' }, datastore['TIMEOUT'])
          next if r.nil?
          if [200, 206].include?(r.code.to_i)
            add_finding('Backup File Exposure', 'High', "Backup/temporary file exposed: #{candidate}", 'A05 Security Misconfiguration', { path: candidate, status: r.code })
          end
        rescue
        end
      end
    end
  end

  def run_ssti_probes(ip)
    payloads = ['{{7*7}}', '${7*7}', '<%= 7*7 %>']
    probe_candidates.each do |path|
      payloads.each do |pl|
        begin
          baseline = fetch_baseline_signature(path)
          r = send_request_cgi({ 'uri' => path, 'method' => 'GET', 'vars_get' => { 'q' => pl, 'name' => pl } }, datastore['TIMEOUT'])
          next if r.nil?
          b = r.body.to_s
          next unless b.include?('49') || b.include?('343')
          next unless significant_response_shift?(baseline, r)
          sc, dc, ld = response_shift_metrics(baseline, r)
          add_finding('SSTI (Potential)', 'High', "Template expression appears evaluated at #{path}", 'A03 Injection', { path: path, payload: pl, status: r.code, snippet: b[0, 240], status_changed: sc, digest_changed: dc, len_delta: ld })
          break
        rescue
        end
      end
    end
  end

  def run_ssrf_probes(ip)
    payload = 'http://169.254.169.254/latest/meta-data/'
    probe_candidates.each do |path|
      begin
        r = send_request_cgi({ 'uri' => path, 'method' => 'GET', 'vars_get' => { 'url' => payload, 'next' => payload, 'dest' => payload } }, datastore['TIMEOUT'])
        next if r.nil?
        b = r.body.to_s
        if b =~ /ami-id|instance-id|meta-data|ec2/i
          add_finding('SSRF (Potential)', 'Critical', "Cloud metadata marker found at #{path}", 'A10 Server-Side Request Forgery', { path: path, payload: payload, status: r.code, snippet: b[0, 240] })
        end
      rescue
      end
    end
  end

  def run_cmdi_probes(ip)
    payloads = [';id', '`id`', '$(id)']
    probe_candidates.each do |path|
      payloads.each do |pl|
        begin
          r = send_request_cgi({ 'uri' => path, 'method' => 'GET', 'vars_get' => { 'cmd' => pl, 'exec' => pl } }, datastore['TIMEOUT'])
          next if r.nil?
          b = r.body.to_s
          if b =~ /uid=\d+\(.+\)\s+gid=\d+/i
            add_finding('Command Injection (Potential)', 'Critical', "Command output marker observed at #{path}", 'A03 Injection', { path: path, payload: pl, status: r.code, snippet: b[0, 240] })
            break
          end
        rescue
        end
      end
    end
  end

  def run_nosqli_probes(ip)
    payloads = ['{"$gt":""}', '{"$ne":null}']
    probe_candidates.each do |path|
      payloads.each do |pl|
        begin
          r = send_request_cgi({ 'uri' => path, 'method' => 'POST', 'ctype' => 'application/json', 'data' => "{\"username\":#{pl},\"password\":#{pl}}" }, datastore['TIMEOUT'])
          next if r.nil?
          b = r.body.to_s
          if b =~ /mongo|mongodb|\$gt|\$ne|bson|nosql/i
            add_finding('NoSQL Injection (Potential)', 'High', "NoSQL-related marker observed at #{path}", 'A03 Injection', { path: path, payload: pl, status: r.code, snippet: b[0, 240] })
            break
          end
        rescue
        end
      end
    end
  end

  def run_xxe_probes(ip)
    payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
    probe_candidates.each do |path|
      begin
        r = send_request_cgi({ 'uri' => path, 'method' => 'POST', 'ctype' => 'application/xml', 'data' => payload }, datastore['TIMEOUT'])
        next if r.nil?
        b = r.body.to_s
        if b =~ /root:.*:0:0:/i || b =~ /xml parser|entity/i
          add_finding('XXE (Potential)', 'High', "XXE marker observed at #{path}", 'A05 Security Misconfiguration', { path: path, status: r.code, snippet: b[0, 240] })
        end
      rescue
      end
    end
  end

  def check_cors_preflight(ip, base_uri)
    r = send_request_cgi(
      {
        'uri' => base_uri,
        'method' => 'OPTIONS',
        'headers' => {
          'Origin' => 'https://evil.example',
          'Access-Control-Request-Method' => 'POST',
          'Access-Control-Request-Headers' => 'authorization,x-api-key'
        }
      }, datastore['TIMEOUT']
    )
    return if r.nil?
    acao = r.headers['Access-Control-Allow-Origin'].to_s
    acah = r.headers['Access-Control-Allow-Headers'].to_s
    if acao == '*' && acah =~ /authorization|x-api-key/i
      add_finding('CORS Preflight', 'High', 'Permissive preflight allows sensitive headers from any origin', 'A05 Security Misconfiguration', { acao: acao, acah: acah })
    end
  rescue
  end

  def check_cache_control(ip)
    sensitive = probe_candidates.select { |p| p =~ /login|account|profile|admin|checkout|order|cart/i }.take(30)
    sensitive.each do |path|
      begin
        r = send_request_cgi({ 'uri' => path, 'method' => 'GET' }, datastore['TIMEOUT'])
        next if r.nil?
        cc = r.headers['Cache-Control'].to_s.downcase
        unless cc.include?('no-store') || cc.include?('private')
          add_finding('Cache-Control', 'Medium', 'Sensitive endpoint appears cacheable', 'A05 Security Misconfiguration', { path: path, cache_control: r.headers['Cache-Control'] })
        end
      rescue
      end
    end
  end

  def detect_waf(ip, base_uri)
    r = send_request_cgi({ 'uri' => base_uri, 'method' => 'GET', 'vars_get' => { 'q' => "<script>alert(1)</script>' OR 1=1--" } }, datastore['TIMEOUT'])
    return if r.nil?
    h = r.headers || {}
    b = r.body.to_s.downcase
    waf = nil
    waf = 'Cloudflare' if h['CF-RAY'] || h['Server'].to_s =~ /cloudflare/i
    waf = 'AWS WAF' if h['x-amzn-waf'] || b =~ /aws waf/i
    waf = 'ModSecurity' if b =~ /mod_security|modsecurity|not acceptable/
    waf = 'F5 BIG-IP' if h['Server'].to_s =~ /big-ip/i
    waf = 'Generic WAF' if waf.nil? && r.code.to_i == 403 && b =~ /request rejected|blocked|firewall|security/
    add_finding('WAF Detected', 'Low', "Web Application Firewall detected: #{waf}", 'A05 Security Misconfiguration', { waf: waf }) if waf
  rescue
  end

  def check_response_fuzzing(ip, base_uri)
    fuzz = 'A' * 4096 + "%00%0d%0a<>'\""
    r = send_request_cgi({ 'uri' => base_uri, 'method' => 'GET', 'vars_get' => { 'q' => fuzz } }, datastore['TIMEOUT'])
    return if r.nil?
    b = r.body.to_s
    if b =~ /stack trace|exception|traceback|fatal error|warning:\s/i
      add_finding('Response Fuzzing', 'Medium', 'Malformed input triggered verbose error leakage', 'A05 Security Misconfiguration', { status: r.code, snippet: b[0, 260] })
    end
  rescue
  end

  def check_open_redirect(ip)
    payload = 'https://evil.example'
    keys = %w[redirect next url return returnTo continue dest]
    probe_candidates.each do |path|
      keys.each do |k|
        begin
          r = send_request_cgi({ 'uri' => path, 'method' => 'GET', 'vars_get' => { k => payload } }, datastore['TIMEOUT'])
          next if r.nil?
          loc = r.headers['Location'].to_s
          if [301, 302, 303, 307, 308].include?(r.code.to_i) && loc.start_with?(payload)
            add_finding('Open Redirect', 'Medium', "Open redirect via parameter #{k} at #{path}", 'A01 Broken Access Control', { path: path, parameter: k, location: loc })
            break
          end
        rescue
        end
      end
    end
  end

  def check_session_fixation(ip)
    login_path = '/login'
    before = send_request_cgi({ 'uri' => login_path, 'method' => 'GET' }, datastore['TIMEOUT'])
    return if before.nil?
    cookie_before = before.headers['Set-Cookie'].to_s
    after = send_request_cgi({ 'uri' => login_path, 'method' => 'POST', 'vars_post' => { 'username' => 'test', 'password' => 'test' } }, datastore['TIMEOUT'])
    return if after.nil?
    cookie_after = after.headers['Set-Cookie'].to_s
    return if cookie_before.empty? || cookie_after.empty?
    if cookie_before == cookie_after
      add_finding('Session Fixation (Potential)', 'Medium', 'Session cookie did not change after auth attempt', 'A07 Identification and Authentication Failures', { path: login_path })
    end
  rescue
  end

  def check_csrf_enforcement(ip)
    candidates = probe_candidates.select { |p| p =~ /profile|account|settings|email|password|checkout|cart/i }.take(20)
    candidates.each do |path|
      begin
        r = send_request_cgi({ 'uri' => path, 'method' => 'POST', 'vars_post' => { 'x' => '1' } }, datastore['TIMEOUT'])
        next if r.nil?
        body = r.body.to_s.downcase
        if [200, 302].include?(r.code.to_i) && !(body.include?('csrf') || body.include?('token'))
          add_finding('CSRF Protection (Potential)', 'Medium', "State-changing endpoint may not enforce CSRF token: #{path}", 'A01 Broken Access Control', { path: path, status: r.code })
        end
      rescue
      end
    end
  end

  def passive_subdomain_enum(ip)
    base = ip.to_s.downcase.strip
    return if base.empty?
    url = URI("https://crt.sh/?q=%25.#{base}&output=json")
    res = Net::HTTP.get_response(url)
    return unless res.is_a?(Net::HTTPSuccess)
    rows = JSON.parse(res.body) rescue []
    return unless rows.is_a?(Array)
    names = rows.map { |r| r['name_value'].to_s }.flat_map { |v| v.split(/\s+/) }.map(&:strip).select { |d| d.end_with?(base) }.uniq.take(200)
    names.each do |n|
      @endpoints << { path: "https://#{n}", code: 0 } unless @endpoints.any? { |e| e[:path] == "https://#{n}" }
    end
    add_finding('Passive Subdomain Discovery', 'Low', "crt.sh returned #{names.length} related hostnames", 'A05 Security Misconfiguration', { sample: names.take(20) }) if names.any?
  rescue
  end

  def wayback_enum(ip)
    host = ip.to_s.downcase.strip
    return if host.empty?
    url = URI("https://web.archive.org/cdx/search/cdx?url=#{host}/*&output=json&fl=original&collapse=urlkey")
    res = Net::HTTP.get_response(url)
    return unless res.is_a?(Net::HTTPSuccess)
    rows = JSON.parse(res.body) rescue []
    return unless rows.is_a?(Array) && rows.length > 1
    rows[1..250].each do |row|
      next unless row.is_a?(Array) && row[0]
      begin
        u = URI.parse(row[0].to_s)
        next unless u.path
        path = u.path
        path += "?#{u.query}" if u.query && !u.query.empty?
        @endpoints << { path: path, code: 0 } unless @endpoints.any? { |e| e[:path] == path }
      rescue
      end
    end
    add_finding('Wayback Discovery', 'Low', 'Historical endpoints added from Wayback CDX', 'A05 Security Misconfiguration', { total_endpoints: @endpoints.length })
  rescue
  end

  def discover_endpoints(ip)
    print_status("#{ip} - Discovering common endpoints (threaded)")
    paths = %w[
      /admin /login /dashboard /robots.txt /swagger /swagger-ui /api-docs
      /actuator /actuator/health /debug /phpinfo.php /.env /.git/config
      /server-status /graphql /openapi.json /v2/api-docs
    ]

    threads = []
    mutex = ::Mutex.new
    queue = paths.dup
    max_threads = [datastore['THREADS'].to_i, 1].max

    max_threads.times do
      threads << framework.threads.spawn("endpoint-discovery-#{ip}", false) do
        loop do
          path = nil
          mutex.synchronize { path = queue.shift }
          break if path.nil?

          begin
            r = send_request_cgi({ 'uri' => path, 'method' => 'GET' }, 5)
            next if r.nil?
            code = r.code.to_i
            next unless [200, 201, 204, 301, 302, 307, 308, 401, 403].include?(code)

            mutex.synchronize do
              @endpoints << { path: path, code: code }
            end
            vprint_good("#{ip} - Found #{path} (#{code})")

            if %w[/swagger /swagger-ui /api-docs /v2/api-docs /openapi.json /actuator /actuator/health /.env /.git/config /phpinfo.php /server-status].include?(path)
              add_finding('Endpoint Exposure', 'Medium', "#{path} accessible (#{code})", 'A05 Security Misconfiguration', { path: path, code: code })
            end
          rescue
          end
        end
      end
    end

    threads.each(&:join)
  end

  def crawl_endpoints(ip)
    depth_limit = [[datastore['CRAWL_DEPTH'].to_i, 0].max, 5].min
    max_pages = [[datastore['CRAWL_MAX_PAGES'].to_i, 1].max, 500].min
    seed = normalize_uri(datastore['TARGETURI'])
    print_status("#{ip} - Crawling endpoints (depth=#{depth_limit}, max_pages=#{max_pages})")

    queue = [[seed, 0]]
    visited = {}
    discovered = 0

    while !queue.empty? && visited.length < max_pages
      path, depth = queue.shift
      next if visited[path]
      visited[path] = true

      begin
        res = send_request_cgi({ 'uri' => path, 'method' => 'GET' }, datastore['TIMEOUT'])
        next if res.nil?
        code = res.code.to_i
        body = res.body.to_s
        unless @endpoints.any? { |e| e[:path] == path }
          @endpoints << { path: path, code: code }
          discovered += 1
        end
        next if depth >= depth_limit

        body.scan(/(?:href|src|action)\s*=\s*["']([^"']+)["']/i).each do |m|
          raw = m[0].to_s.strip
          next if raw.empty? || raw.start_with?('#', 'javascript:', 'mailto:', 'tel:')
          begin
            u = URI.parse(raw)
          rescue
            next
          end
          next if u.host # skip off-path absolute URLs
          next unless raw.start_with?('/') || raw.start_with?('./') || raw.start_with?('../') || raw =~ /\A[\w\-\.\?&=%]+\z/
          clean = normalize_uri(raw.start_with?('/') ? raw : "/#{raw.sub(%r{\A\./}, '')}")
          next unless clean.start_with?('/')
          queue << [clean, depth + 1] unless visited[clean]
        end
      rescue
      end
    end

    print_status("#{ip} - Crawl discovered #{discovered} paths (total endpoints: #{@endpoints.length})")
  end

  def run_reflected_xss_probes(ip)
    print_status("#{ip} - Running reflected XSS probes")
    payload = "xssprobe_#{Rex::Text.rand_text_alphanumeric(6)}<svg/onload=alert(1)>"
    candidates = probe_candidates
    candidates.each do |path|
      begin
        baseline = fetch_baseline_signature(path)
        res = send_request_cgi(
          {
            'uri' => path,
            'method' => 'GET',
            'vars_get' => { 'q' => payload, 'search' => payload, 's' => payload }
          }, datastore['TIMEOUT']
        )
        next if res.nil?
        body = res.body.to_s
        reflected = body.include?(payload)
        next unless reflected
        next unless significant_response_shift?(baseline, res)
        status_changed, digest_changed, len_delta = response_shift_metrics(baseline, res)
        add_finding(
          'Reflected XSS (Potential)',
          'High',
          "Payload reflected at #{path}",
          'A03 Injection',
          {
            path: path,
            marker: payload,
            status: res.code,
            snippet: body[0, 280],
            status_changed: status_changed,
            digest_changed: digest_changed,
            len_delta: len_delta
          }
        )
      rescue
      end
    end
  end

  def run_lfi_traversal_probes(ip)
    print_status("#{ip} - Running LFI/path traversal probes")
    lfi_payloads = [
      "../../../../etc/passwd",
      "..%2f..%2f..%2f..%2fetc%2fpasswd",
      "..%252f..%252f..%252f..%252fetc%252fpasswd",
      "....//....//....//....//etc/passwd"
    ]
    markers = [/root:.*:0:0:/i, /nobody:.*:[0-9]+:[0-9]+:/i]

    probe_candidates.each do |path|
      baseline = fetch_baseline_signature(path)
      lfi_payloads.each do |pl|
        begin
          res = send_request_cgi(
            {
              'uri' => path,
              'method' => 'GET',
              'vars_get' => { 'file' => pl, 'page' => pl, 'path' => pl, 'include' => pl }
            }, datastore['TIMEOUT']
          )
          next if res.nil?
          body = res.body.to_s
          marker_hit = markers.any? { |rx| body =~ rx }
          next unless marker_hit
          next unless significant_response_shift?(baseline, res)
          status_changed, digest_changed, len_delta = response_shift_metrics(baseline, res)
          add_finding(
            'LFI / Path Traversal (Potential)',
            'Critical',
            "LFI marker matched at #{path}",
            'A03 Injection',
            {
              path: path,
              payload: pl,
              status: res.code,
              snippet: body[0, 320],
              status_changed: status_changed,
              digest_changed: digest_changed,
              len_delta: len_delta
            }
          )
          break
        rescue
        end
      end
    end
  end

  def run_sqli_probes(ip)
    print_status("#{ip} - Running SQLi probes (GET/POST/headers)")
    level = datastore['SQLI_LEVEL'].to_s.strip.downcase
    level = 'normal' unless %w[low normal aggressive].include?(level)
    payloads = case level
               when 'low'
                 ["' OR '1'='1", "\" OR \"1\"=\"1"]
               when 'aggressive'
                 [
                   "' OR '1'='1",
                   "\" OR \"1\"=\"1",
                   "' UNION SELECT NULL-- ",
                   "' OR SLEEP(5)-- ",
                   "';WAITFOR DELAY '0:0:5'--",
                   "') OR ('1'='1'-- "
                 ]
               else
                 [
                   "' OR '1'='1",
                   "\" OR \"1\"=\"1",
                   "' UNION SELECT NULL-- ",
                   "' OR SLEEP(5)-- "
                 ]
               end
    get_keys = level == 'aggressive' ? %w[id q search uid page sort] : %w[id q search]
    post_keys = level == 'aggressive' ? %w[username password search email token] : %w[username password search]
    header_keys = level == 'aggressive' ? ['X-Forwarded-For', 'X-Api-Version', 'User-Agent', 'Referer', 'X-Original-URL'] : ['X-Forwarded-For', 'X-Api-Version', 'User-Agent']
    sql_errors = [
      /sql syntax/i,
      /mysql/i,
      /syntax error.*sql/i,
      /unclosed quotation mark/i,
      /pg_query|postgresql/i,
      /odbc sql server driver/i
    ]

    probe_candidates.each do |path|
      baseline = fetch_baseline_signature(path)

      # GET
      payloads.each do |pl|
        begin
          res = send_request_cgi(
            {
              'uri' => path,
              'method' => 'GET',
              'vars_get' => get_keys.each_with_object({}) { |k, h| h[k] = pl }
            }, datastore['TIMEOUT']
          )
          next if res.nil?
          body = res.body.to_s
          next unless sql_errors.any? { |rx| body =~ rx }
          next unless significant_response_shift?(baseline, res)
          status_changed, digest_changed, len_delta = response_shift_metrics(baseline, res)
          add_finding('SQL Injection (Potential, GET)', 'High', "SQL error signature found at #{path}", 'A03 Injection', {
            path: path, payload: pl, vector: 'GET', status: res.code, snippet: body[0, 320],
            status_changed: status_changed, digest_changed: digest_changed, len_delta: len_delta
          })
          break
        rescue
        end
      end

      # POST
      payloads.each do |pl|
        begin
          res = send_request_cgi(
            {
              'uri' => path,
              'method' => 'POST',
              'vars_post' => post_keys.each_with_object({}) { |k, h| h[k] = pl }
            }, datastore['TIMEOUT']
          )
          next if res.nil?
          body = res.body.to_s
          next unless sql_errors.any? { |rx| body =~ rx }
          next unless significant_response_shift?(baseline, res)
          status_changed, digest_changed, len_delta = response_shift_metrics(baseline, res)
          add_finding('SQL Injection (Potential, POST)', 'High', "SQL error signature found at #{path}", 'A03 Injection', {
            path: path, payload: pl, vector: 'POST', status: res.code, snippet: body[0, 320],
            status_changed: status_changed, digest_changed: digest_changed, len_delta: len_delta
          })
          break
        rescue
        end
      end

      # Headers
      payloads.each do |pl|
        begin
          hdrs = {}
          header_keys.each { |k| hdrs[k] = (k == 'User-Agent' ? "scanner #{pl}" : pl) }
          res = send_request_cgi(
            {
              'uri' => path,
              'method' => 'GET',
              'headers' => hdrs
            }, datastore['TIMEOUT']
          )
          next if res.nil?
          body = res.body.to_s
          next unless sql_errors.any? { |rx| body =~ rx }
          next unless significant_response_shift?(baseline, res)
          status_changed, digest_changed, len_delta = response_shift_metrics(baseline, res)
          add_finding('SQL Injection (Potential, Header)', 'Medium', "SQL error signature found at #{path}", 'A03 Injection', {
            path: path, payload: pl, vector: 'HEADER', status: res.code, snippet: body[0, 320],
            status_changed: status_changed, digest_changed: digest_changed, len_delta: len_delta
          })
          break
        rescue
        end
      end
    end
  end

  def probe_candidates
    paths = @endpoints.map { |e| e[:path].to_s }.uniq
    paths = [normalize_uri(datastore['TARGETURI'])] if paths.empty?
    paths.select { |p| p.start_with?('/') }
  end

  def fetch_baseline_signature(path)
    res = send_request_cgi({ 'uri' => path, 'method' => 'GET' }, datastore['TIMEOUT'])
    return { status: nil, len: 0, digest: '' } if res.nil?
    b = res.body.to_s
    { status: res.code.to_i, len: b.length, digest: b[0, 512] }
  rescue
    { status: nil, len: 0, digest: '' }
  end

  def significant_response_shift?(baseline, response)
    return false if response.nil?
    status_changed, digest_changed, len_delta = response_shift_metrics(baseline, response)
    status_changed || digest_changed || len_delta > 40
  end

  def response_shift_metrics(baseline, response)
    return [false, false, 0] if response.nil?
    body = response.body.to_s
    cur_len = body.length
    base_len = baseline[:len].to_i
    len_delta = (cur_len - base_len).abs
    status_changed = baseline[:status].to_i != response.code.to_i
    digest_changed = baseline[:digest].to_s != body[0, 512].to_s
    [status_changed, digest_changed, len_delta]
  end

  def show_summary(ip)
    print_line('')
    print_status("#{ip} - Final Summary")
    crit = @findings.count { |x| x[:severity] == 'Critical' }
    high = @findings.count { |x| x[:severity] == 'High' }
    med = @findings.count { |x| x[:severity] == 'Medium' }
    low = @findings.count { |x| x[:severity] == 'Low' }

    print_error("#{ip} - Critical: #{crit}") if crit > 0
    print_warning("#{ip} - High: #{high}") if high > 0
    print_warning("#{ip} - Medium: #{med}") if med > 0
    print_status("#{ip} - Low: #{low}") if low > 0
    print_status("#{ip} - Open endpoints: #{@endpoints.length}")
    print_status("#{ip} - Service banners: #{@port_banners.length}") unless @port_banners.empty?
    print_status("#{ip} - NVD matches: #{@nvd_matches.length}") if datastore['NVD_ENRICH']
    print_status("#{ip} - Shodan ports: #{@shodan_data['ports'].to_a.length}") if datastore['SHODAN_ENRICH']
  end

  def enrich_with_shodan(ip)
    key = shodan_api_key
    if key.empty?
      print_warning("#{ip} - SHODAN_ENRICH enabled but SHODAN_API_KEY missing")
      return
    end

    uri = URI("https://api.shodan.io/shodan/host/#{ip}?key=#{URI.encode_www_form_component(key)}")
    res = Net::HTTP.get_response(uri)
    return unless res.is_a?(Net::HTTPSuccess)
    data = JSON.parse(res.body) rescue {}
    @shodan_data = {
      'org' => data['org'],
      'isp' => data['isp'],
      'os' => data['os'],
      'ports' => data['ports'] || [],
      'hostnames' => data['hostnames'] || [],
      'vulns' => data['vulns'] || []
    }
    if @shodan_data['vulns'].is_a?(Array) && !@shodan_data['vulns'].empty?
      add_finding('Shodan Exposure', 'Medium', "Shodan reports #{ @shodan_data['vulns'].length } vulnerability tags", 'A06 Vulnerable and Outdated Components', { vulns: @shodan_data['vulns'].take(10) })
    end
  rescue => e
    print_warning("#{ip} - Shodan enrichment failed: #{e.class}")
  end

  def enrich_with_nvd(ip)
    key = nvd_api_key
    if key.empty?
      print_warning("#{ip} - NVD_ENRICH enabled but NVD_API_KEY missing")
      return
    end

    products = extract_product_tokens
    return if products.empty?

    products.take(4).each do |kw|
      qs = URI.encode_www_form({ keywordSearch: kw, resultsPerPage: 5 })
      uri = URI("https://services.nvd.nist.gov/rest/json/cves/2.0?#{qs}")
      req = Net::HTTP::Get.new(uri)
      req['apiKey'] = key
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      resp = http.request(req)
      next unless resp.is_a?(Net::HTTPSuccess)
      data = JSON.parse(resp.body) rescue {}
      vulns = data['vulnerabilities'] || []
      vulns.each do |entry|
        c = entry['cve'] || {}
        cve_id = c['id'].to_s
        metrics = c['metrics'] || {}
        cvss = extract_cvss_base(metrics)
        @nvd_matches << { keyword: kw, cve: cve_id, cvss: cvss }
      end
    end

    @nvd_matches.uniq! { |x| x[:cve] }
    @nvd_matches.take(10).each do |m|
      sev = m[:cvss].to_f >= 9.0 ? 'High' : (m[:cvss].to_f >= 7.0 ? 'Medium' : 'Low')
      add_finding('NVD CVE Correlation', sev, "Possible related CVE: #{m[:cve]} (keyword: #{m[:keyword]})", 'A06 Vulnerable and Outdated Components', { cve: m[:cve], cvss: m[:cvss], keyword: m[:keyword] })
    end
  rescue => e
    print_warning("#{ip} - NVD enrichment failed: #{e.class}")
  end

  def extract_product_tokens
    tokens = []
    @findings.each do |f|
      s = f[:evidence].to_s
      tokens << 'nginx' if s =~ /nginx/i
      tokens << 'apache http server' if s =~ /apache/i
      tokens << 'php' if s =~ /php/i
      tokens << 'node.js' if s =~ /node/i
    end
    tokens.uniq
  end

  def extract_cvss_base(metrics)
    %w[cvssMetricV31 cvssMetricV30 cvssMetricV2].each do |k|
      arr = metrics[k]
      next unless arr.is_a?(Array) && !arr.empty?
      score = arr[0].dig('cvssData', 'baseScore')
      return score.to_f if score
    end
    0.0
  end

  def export_report(ip)
    format = datastore['FORMAT'].downcase
    path = datastore['OUTFILE']
    case format
    when 'txt' then export_txt(path, ip)
    when 'csv' then export_csv(path, ip)
    when 'json' then export_json(path, ip)
    else export_html(path, ip)
    end
  end

  def export_txt(path, ip)
    outfile = "#{path}.txt"
    File.open(outfile, 'w') do |f|
      f.puts "Web Vulnerability Scanner Advanced Report - #{ip}"
      f.puts "Open Ports: #{@open_ports.sort.join(', ')}"
      if @port_banners.any?
        f.puts "Port Banners:"
        @port_banners.each { |b| f.puts "- #{b[:port]}: #{b[:banner]}" }
      end
      f.puts "Endpoints: #{@endpoints.length}"
      f.puts "NVD Matches: #{@nvd_matches.length}" unless @nvd_matches.empty?
      f.puts "Shodan Ports: #{@shodan_data['ports'].to_a.join(', ')}" unless @shodan_data.empty?
      @findings.each do |x|
        f.puts "[#{x[:severity]}|#{x[:confidence]}] #{x[:type]} - #{x[:message]} (#{x[:owasp]})"
      end
    end
    print_good("TXT report saved: #{outfile}")
  end

  def export_csv(path, ip)
    outfile = "#{path}.csv"
    CSV.open(outfile, 'w') do |csv|
      csv << %w[Target Type Severity Confidence Message OWASP Evidence]
      @findings.each do |x|
        csv << [
          utf8_clean(ip),
          utf8_clean(x[:type]),
          utf8_clean(x[:severity]),
          utf8_clean(x[:confidence]),
          utf8_clean(x[:message]),
          utf8_clean(x[:owasp]),
          deep_utf8(x[:evidence]).to_json
        ]
      end
    end
    print_good("CSV report saved: #{outfile}")
  end

  def export_json(path, ip)
    outfile = "#{path}.json"
    payload = {
      target: ip,
      timestamp: Time.now.utc.iso8601,
      open_ports: @open_ports.sort,
      port_banners: @port_banners,
      present_headers: @present_headers.sort.uniq,
      discovered_endpoints: @endpoints,
      nvd_matches: @nvd_matches,
      shodan: @shodan_data,
      findings: @findings
    }
    File.write(outfile, JSON.pretty_generate(deep_utf8(payload)))
    print_good("JSON report saved: #{outfile}")
  end

  def export_html(path, ip)
    outfile = "#{path}.html"
    score = [0, 100 - (@findings.length * 6)].max
    risk = score >= 80 ? 'LOW' : (score >= 60 ? 'MEDIUM' : 'HIGH')
    risk_class = risk == 'LOW' ? 'badge-low' : (risk == 'MEDIUM' ? 'badge-medium' : 'badge-high')

    html = +"<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
    html << "<title>Web Vulnerability Scanner Advanced Report</title>"
    html << "<style>body{font-family:Arial,sans-serif;background:#f3f6fb;color:#1f2937} .wrap{max-width:1200px;margin:20px auto;padding:0 12px} .card{background:#fff;border-radius:10px;padding:16px;margin-bottom:14px;box-shadow:0 2px 10px rgba(0,0,0,.08)} table{width:100%;border-collapse:collapse} th,td{border-bottom:1px solid #e5e7eb;padding:10px;text-align:left} .badge-low{background:#dcfce7;color:#166534;padding:3px 8px;border-radius:999px} .badge-medium{background:#fef3c7;color:#92400e;padding:3px 8px;border-radius:999px} .badge-high{background:#fee2e2;color:#991b1b;padding:3px 8px;border-radius:999px}</style></head><body><div class='wrap'>"
    html << "<div class='card'><h1>Web Vulnerability Scanner Advanced</h1><p><b>Target:</b> #{h(ip)}<br><b>Date:</b> #{h(Time.now.to_s)}<br><b>Score:</b> #{score}/100 <span class='#{risk_class}'>#{risk}</span></p></div>"
    html << "<div class='card'><h2>Open Ports</h2><p>#{h(@open_ports.sort.join(', '))}</p></div>"
    if @port_banners.any?
      html << "<div class='card'><h2>Service Banners</h2><ul>"
      @port_banners.each { |b| html << "<li>#{h(b[:port].to_s)}: #{h(b[:banner].to_s)}</li>" }
      html << "</ul></div>"
    end
    html << "<div class='card'><h2>Discovered Endpoints</h2><ul>"
    @endpoints.each { |e| html << "<li>#{h(e[:path])} -> HTTP #{h(e[:code].to_s)}</li>" }
    html << "</ul></div>"
    html << "<div class='card'><h2>Findings</h2><table><tr><th>Type</th><th>Severity</th><th>Confidence</th><th>Message</th><th>OWASP</th><th>Evidence</th></tr>"
    @findings.each do |f|
      html << "<tr><td>#{h(f[:type].to_s)}</td><td>#{h(f[:severity].to_s)}</td><td>#{h(f[:confidence].to_s)}</td><td>#{h(f[:message].to_s)}</td><td>#{h(f[:owasp].to_s)}</td><td><pre>#{h(JSON.pretty_generate(f[:evidence] || {}))}</pre></td></tr>"
    end
    html << "</table></div></div></body></html>"
    File.write(outfile, html)
    print_good("HTML report saved: #{outfile}")
  end

  def h(value)
    CGI.escapeHTML(utf8_clean(value))
  end
end
