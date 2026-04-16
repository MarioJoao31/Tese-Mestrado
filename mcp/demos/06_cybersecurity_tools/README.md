# 06 · Cybersecurity Tools

A set of MCP tools for security analysis, organised into four focused modules.

## Tool Groups

| Module | File | Tools |
|--------|------|-------|
| Network Analysis | `tools/network_tools.py` | `dns_lookup`, `port_scan`, `analyze_http_headers`, `check_ssl_certificate`, `whois_lookup` |
| Vulnerability Assessment | `tools/vulnerability_tools.py` | `cve_lookup`, `check_dependency_vulnerabilities`, `assess_cvss_score`, `generate_security_report`, `check_owasp_top10` |
| Cryptographic Analysis | `tools/crypto_tools.py` | `identify_hash_type`, `hash_text`, `analyze_password`, `generate_secure_token`, `check_encoding` |
| Log Analysis | `tools/log_analysis_tools.py` | `parse_access_log`, `detect_brute_force`, `extract_ips_from_log`, `detect_sqli_in_log`, `summarize_log_statistics` |

## Tool Reference

### Network Tools (`tools/network_tools.py`)

| Tool | Description |
|------|-------------|
| `dns_lookup(hostname)` | Resolve hostname to IPs; detect private-address anomalies |
| `port_scan(host, ports)` | TCP connect scan with risk classification |
| `analyze_http_headers(headers_json)` | Security header audit with A–F grading |
| `check_ssl_certificate(hostname, port)` | Certificate validity, TLS version, cipher suite |
| `whois_lookup(domain)` | Registration data with expiry and TLD risk notes |

### Vulnerability Tools (`tools/vulnerability_tools.py`)

| Tool | Description |
|------|-------------|
| `cve_lookup(cve_id)` | Look up a CVE in the local database |
| `check_dependency_vulnerabilities(packages_json)` | Audit Python packages for known CVEs |
| `assess_cvss_score(score)` | Interpret a CVSS v3 score with remediation SLA |
| `generate_security_report(findings_json, target)` | Produce a structured security report |
| `check_owasp_top10(code_or_text, language)` | Scan code for OWASP Top-10 indicators |

### Crypto Tools (`tools/crypto_tools.py`)

| Tool | Description |
|------|-------------|
| `identify_hash_type(hash_value)` | Guess hash algorithm from digest length |
| `hash_text(text, algorithm, as_base64)` | Hash text with SHA-256/SHA-512/BLAKE2 etc. |
| `analyze_password(password)` | Password strength with entropy estimate |
| `generate_secure_token(length, format)` | Cryptographically secure token (hex/base64) |
| `check_encoding(data)` | Detect Base64, URL encoding, hex, HTML entities |

### Log Analysis Tools (`tools/log_analysis_tools.py`)

| Tool | Description |
|------|-------------|
| `parse_access_log(log_text)` | Parse CLF/Combined access logs; detect anomalies |
| `detect_brute_force(log_text, threshold)` | Flag brute-force login attempts |
| `extract_ips_from_log(log_text)` | Extract and classify all IPv4 addresses |
| `detect_sqli_in_log(log_text)` | Find SQL injection attempts in request URLs |
| `summarize_log_statistics(log_text)` | High-level statistics and keyword frequencies |

## Usage

**Start the MCP server:**

```bash
cd mcp/demos/06_cybersecurity_tools
python server.py
```

**Run the standalone demo (no LLM required):**

```bash
cd mcp/demos/06_cybersecurity_tools
python demo.py
```

## Project Structure

```
demos/06_cybersecurity_tools/
├── server.py          # MCP server entry point
├── demo.py            # Standalone demonstration script
├── README.md          # This file
└── tools/
    ├── __init__.py              # Package exports
    ├── network_tools.py         # DNS, port scan, headers, SSL, WHOIS
    ├── vulnerability_tools.py   # CVE, dependencies, CVSS, OWASP
    ├── crypto_tools.py          # Hashing, passwords, tokens, encoding
    └── log_analysis_tools.py    # Log parsing, brute force, SQLi
```

## ⚠️ Ethical Use

- Only use scanning tools against systems you own or have **explicit written permission** to test.
- The CVE database is a small local subset for educational purposes; use [NVD](https://nvd.nist.gov) for production lookups.
- Vulnerable-package detection uses representative data; run `pip-audit` or `safety` for production audits.
