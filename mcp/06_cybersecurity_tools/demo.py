"""
demo.py  –  06_cybersecurity_tools
-------------------------------------
Standalone demonstration of all cybersecurity MCP tools.
No LLM or running MCP server required – calls tool functions directly.
"""

from __future__ import annotations

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tools.network_tools import dns_lookup, analyze_http_headers, whois_lookup
from tools.vulnerability_tools import (
    cve_lookup,
    check_dependency_vulnerabilities,
    assess_cvss_score,
    check_owasp_top10,
    generate_security_report,
)
from tools.crypto_tools import (
    identify_hash_type,
    hash_text,
    analyze_password,
    generate_secure_token,
    check_encoding,
)
from tools.log_analysis_tools import (
    parse_access_log,
    detect_brute_force,
    detect_sqli_in_log,
)

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def section(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print("="*60)


def show(label: str, result: str) -> None:
    print(f"\n[{label}]")
    try:
        print(json.dumps(json.loads(result), indent=2))
    except json.JSONDecodeError:
        print(result)


# ---------------------------------------------------------------------------
# Demo scenarios
# ---------------------------------------------------------------------------

def demo_network_tools() -> None:
    section("Network Tools")

    # DNS lookup
    show("dns_lookup('github.com')", dns_lookup("github.com"))

    # HTTP header analysis – good headers
    good_headers = json.dumps({
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Server": "nginx/1.25.3",  # leaking header
    })
    show("analyze_http_headers (partial headers)", analyze_http_headers(good_headers))

    # WHOIS
    show("whois_lookup('suspicious.tk')", whois_lookup("suspicious.tk"))


def demo_vulnerability_tools() -> None:
    section("Vulnerability Tools")

    # CVE lookup
    show("cve_lookup('CVE-2021-44228') [Log4Shell]", cve_lookup("CVE-2021-44228"))
    show("cve_lookup('CVE-2024-6387') [regreSSHion]", cve_lookup("CVE-2024-6387"))

    # Dependency audit
    packages = json.dumps([
        {"name": "requests", "version": "2.28.0"},
        {"name": "flask", "version": "2.3.0"},
        {"name": "pyyaml", "version": "5.4"},
        {"name": "django", "version": "4.2.9"},  # clean
    ])
    show("check_dependency_vulnerabilities", check_dependency_vulnerabilities(packages))

    # CVSS assessment
    show("assess_cvss_score(10.0) [Critical]", assess_cvss_score(10.0))
    show("assess_cvss_score(5.4) [Medium]",    assess_cvss_score(5.4))

    # OWASP Top 10 scan
    vulnerable_snippet = """
import os
def login(username, password):
    query = f"SELECT * FROM users WHERE name='{username}' AND pass='{password}'"
    os.system(f"log_attempt {username}")
    if password == "hardcoded_secret":
        return True
"""
    show("check_owasp_top10 (Python snippet)", check_owasp_top10(vulnerable_snippet, "python"))

    # Security report
    findings = json.dumps([
        {"title": "Unauthenticated RCE in API endpoint", "severity": "CRITICAL",
         "description": "Command injection via 'cmd' parameter.", "recommendation": "Sanitise input; use parameterised calls."},
        {"title": "Outdated TLS version", "severity": "HIGH",
         "description": "Server accepts TLS 1.0.", "recommendation": "Disable TLS < 1.2."},
        {"title": "Missing HSTS header", "severity": "MEDIUM",
         "description": "HSTS not set.", "recommendation": "Add Strict-Transport-Security header."},
        {"title": "Verbose error messages", "severity": "LOW",
         "description": "Stack traces exposed to users.", "recommendation": "Disable debug mode in production."},
    ])
    show("generate_security_report", generate_security_report(findings, "Example Corp – Web API"))


def demo_crypto_tools() -> None:
    section("Crypto Tools")

    # Hash identification
    show("identify_hash_type (MD5 length 32)", identify_hash_type("5d41402abc4b2a76b9719d911017c592"))
    show("identify_hash_type (SHA-256 length 64)", identify_hash_type("a" * 64))
    show("identify_hash_type (bcrypt)", identify_hash_type("$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"))

    # Hashing
    show("hash_text('hello world', sha256)", hash_text("hello world", "sha256"))
    show("hash_text('hello world', md5) [weak]", hash_text("hello world", "md5"))

    # Password analysis
    show("analyze_password('password123') [weak]", analyze_password("password123"))
    show("analyze_password('T3!s3-M3str4d0#2024') [strong]", analyze_password("T3!s3-M3str4d0#2024"))

    # Token generation
    show("generate_secure_token(32, hex)", generate_secure_token(32, "hex"))
    show("generate_secure_token(24, urlsafe_base64)", generate_secure_token(24, "urlsafe_base64"))

    # Encoding detection
    show("check_encoding (Base64 script)", check_encoding("PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="))
    show("check_encoding (URL encoded)", check_encoding("hello%20world%21"))


def demo_log_analysis() -> None:
    section("Log Analysis Tools")

    # Access log parsing
    sample_access_log = """\
192.168.1.100 - - [09/Mar/2024:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234
10.0.0.5 - - [09/Mar/2024:10:00:02 +0000] "POST /login HTTP/1.1" 401 89
192.168.1.100 - - [09/Mar/2024:10:00:03 +0000] "GET /admin HTTP/1.1" 403 0
203.0.113.42 - - [09/Mar/2024:10:00:04 +0000] "GET /api/v1/users HTTP/1.1" 200 5678
203.0.113.42 - - [09/Mar/2024:10:00:05 +0000] "GET /api/v1/orders HTTP/1.1" 500 90
"""
    show("parse_access_log", parse_access_log(sample_access_log))

    # Brute force detection
    sample_auth_log = """\
Mar  9 10:01:01 server sshd[1234]: Failed password for root from 198.51.100.1 port 52022
Mar  9 10:01:02 server sshd[1235]: Failed password for admin from 198.51.100.1 port 52023
Mar  9 10:01:03 server sshd[1236]: Failed password for ubuntu from 198.51.100.1 port 52024
Mar  9 10:01:04 server sshd[1237]: Failed password for deploy from 198.51.100.1 port 52025
Mar  9 10:01:05 server sshd[1238]: Failed password for test from 198.51.100.1 port 52026
Mar  9 10:01:06 server sshd[1239]: Failed password for root from 198.51.100.1 port 52027
Mar  9 10:02:01 server sshd[1300]: Accepted password for alice from 10.0.0.2 port 44500
"""
    show("detect_brute_force (threshold=5)", detect_brute_force(sample_auth_log, threshold=5))

    # SQL injection detection
    sample_sqli_log = """\
192.168.1.1 - - [09/Mar/2024:11:00:00 +0000] "GET /search?q=laptop HTTP/1.1" 200 2000
203.0.113.99 - - [09/Mar/2024:11:00:01 +0000] "GET /search?q=' OR '1'='1 HTTP/1.1" 500 0
203.0.113.99 - - [09/Mar/2024:11:00:02 +0000] "GET /users?id=1; DROP TABLE users-- HTTP/1.1" 500 0
203.0.113.99 - - [09/Mar/2024:11:00:03 +0000] "GET /items?cat=1 UNION SELECT table_name FROM information_schema.tables HTTP/1.1" 200 5000
192.168.1.1 - - [09/Mar/2024:11:00:04 +0000] "GET /products HTTP/1.1" 200 3000
"""
    show("detect_sqli_in_log", detect_sqli_in_log(sample_sqli_log))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════╗")
    print("║     06 · Cybersecurity Tools – Demo                 ║")
    print("╚══════════════════════════════════════════════════════╝")

    demo_network_tools()
    demo_vulnerability_tools()
    demo_crypto_tools()
    demo_log_analysis()

    print("\n✅  Demo complete.")
