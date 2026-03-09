"""
server.py  –  06_cybersecurity_tools
--------------------------------------
MCP server that exposes all cybersecurity tools grouped by category.

Tool groups (defined in tools/):
  network_tools      – DNS, port scan, header analysis, SSL, WHOIS
  vulnerability_tools – CVE lookup, dependency audit, CVSS, OWASP Top-10
  crypto_tools       – Hash identification, hashing, password analysis, tokens
  log_analysis_tools – Access log parsing, brute-force detection, SQLi scanning

Run with:
    python server.py
"""

from mcp.server.fastmcp import FastMCP

from tools.network_tools import (
    dns_lookup,
    port_scan,
    analyze_http_headers,
    check_ssl_certificate,
    whois_lookup,
)
from tools.vulnerability_tools import (
    cve_lookup,
    check_dependency_vulnerabilities,
    assess_cvss_score,
    generate_security_report,
    check_owasp_top10,
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
    extract_ips_from_log,
    detect_sqli_in_log,
    summarize_log_statistics,
)

# ---------------------------------------------------------------------------
# Main MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "Cybersecurity Tools",
    instructions=(
        "This server provides cybersecurity analysis tools organised into four groups:\n\n"
        "**Network Tools** – dns_lookup, port_scan, analyze_http_headers, "
        "check_ssl_certificate, whois_lookup\n\n"
        "**Vulnerability Tools** – cve_lookup, check_dependency_vulnerabilities, "
        "assess_cvss_score, generate_security_report, check_owasp_top10\n\n"
        "**Crypto Tools** – identify_hash_type, hash_text, analyze_password, "
        "generate_secure_token, check_encoding\n\n"
        "**Log Analysis Tools** – parse_access_log, detect_brute_force, "
        "extract_ips_from_log, detect_sqli_in_log, summarize_log_statistics\n\n"
        "⚠️  Only use network scanning tools against hosts you own or have "
        "explicit written permission to test."
    ),
)

# Register all tools
for _tool_fn in [
    # Network
    dns_lookup, port_scan, analyze_http_headers, check_ssl_certificate, whois_lookup,
    # Vulnerability
    cve_lookup, check_dependency_vulnerabilities, assess_cvss_score,
    generate_security_report, check_owasp_top10,
    # Crypto
    identify_hash_type, hash_text, analyze_password, generate_secure_token, check_encoding,
    # Log analysis
    parse_access_log, detect_brute_force, extract_ips_from_log,
    detect_sqli_in_log, summarize_log_statistics,
]:
    mcp.add_tool(_tool_fn)

if __name__ == "__main__":
    mcp.run()
