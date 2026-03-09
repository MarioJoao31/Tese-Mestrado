"""
network_tools.py
-----------------
MCP tool functions focused on network-layer cybersecurity analysis.

Tools:
  - dns_lookup          : Resolve a hostname to IP addresses (simulated).
  - port_scan           : Check common ports on a host (simulated).
  - analyze_http_headers: Evaluate HTTP security headers.
  - check_ssl_certificate: Inspect SSL/TLS certificate details (simulated).
  - whois_lookup        : Return WHOIS registration data (simulated).
"""

from __future__ import annotations

import json
import re
import socket
from datetime import datetime, timedelta

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Shared FastMCP instance – imported by server.py
# ---------------------------------------------------------------------------
_mcp = FastMCP("network-tools")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

_SECURITY_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "Enforces HTTPS connections (HSTS)",
    "Content-Security-Policy": "Restricts resource loading sources (CSP)",
    "X-Frame-Options": "Prevents clickjacking attacks",
    "X-Content-Type-Options": "Prevents MIME-type sniffing",
    "Referrer-Policy": "Controls referrer information leakage",
    "Permissions-Policy": "Controls browser feature permissions",
    "X-XSS-Protection": "Legacy XSS filter (modern CSP preferred)",
}

_DANGEROUS_HEADERS: list[str] = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-Generator",
]


def _is_private_ip(ip: str) -> bool:
    """Return True for RFC-1918 / loopback / link-local addresses."""
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return False
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        if parts[0] == 169 and parts[1] == 254:
            return True
    except (ValueError, AttributeError):
        pass
    return False


def _validate_hostname(hostname: str) -> bool:
    """Basic hostname / IP validation (no shell-injectable characters)."""
    return bool(re.match(r"^[a-zA-Z0-9.\-]{1,253}$", hostname))


def _validate_ip(ip: str) -> bool:
    """Validate IPv4 address."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@_mcp.tool()
def dns_lookup(hostname: str) -> str:
    """
    Resolve a hostname to its IP address(es).

    Uses the system resolver (real lookup). For educational / testing purposes
    only – do not target hosts without authorisation.

    Args:
        hostname: The fully-qualified domain name or IP to look up.

    Returns:
        JSON with resolved addresses and reverse PTR (when available).
    """
    if not _validate_hostname(hostname):
        return json.dumps({"error": "Invalid hostname format."})

    result: dict = {"hostname": hostname, "addresses": [], "reverse_ptr": None, "warnings": []}

    try:
        infos = socket.getaddrinfo(hostname, None)
        seen: set[str] = set()
        for info in infos:
            addr = info[4][0]
            if addr not in seen:
                seen.add(addr)
                addr_type = "IPv6" if ":" in addr else "IPv4"
                is_private = _is_private_ip(addr) if addr_type == "IPv4" else False
                entry: dict = {"address": addr, "type": addr_type, "private": is_private}
                result["addresses"].append(entry)
                if is_private:
                    result["warnings"].append(
                        f"{addr} is a private/internal address – may indicate DNS rebinding risk."
                    )
    except socket.gaierror as exc:
        result["error"] = f"DNS resolution failed: {exc}"
        return json.dumps(result)

    # Reverse PTR for the first IPv4 address
    ipv4_addrs = [e["address"] for e in result["addresses"] if e["type"] == "IPv4"]
    if ipv4_addrs:
        try:
            result["reverse_ptr"] = socket.gethostbyaddr(ipv4_addrs[0])[0]
        except socket.herror:
            result["reverse_ptr"] = "PTR lookup failed"

    return json.dumps(result, indent=2)


@_mcp.tool()
def port_scan(host: str, ports: str = "common") -> str:
    """
    Perform a basic TCP connect scan on the target host.

    ⚠️  Only scan hosts you own or have explicit permission to test.

    Args:
        host:  Target hostname or IPv4 address.
        ports: Comma-separated port numbers, a range "start-end", or "common"
               to scan the 18 most common service ports.

    Returns:
        JSON with open/closed status for each scanned port.
    """
    if not _validate_hostname(host):
        return json.dumps({"error": "Invalid host format."})

    # Resolve port list
    port_list: list[int] = []
    if ports.strip().lower() == "common":
        port_list = list(_COMMON_PORTS.keys())
    elif "-" in ports and "," not in ports:
        try:
            start_str, end_str = ports.split("-")
            start, end = int(start_str.strip()), int(end_str.strip())
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                return json.dumps({"error": "Port range must be 1-65535."})
            if end - start > 1000:
                return json.dumps({"error": "Port range too large (max 1000 at once)."})
            port_list = list(range(start, end + 1))
        except ValueError:
            return json.dumps({"error": "Invalid port range format. Use 'start-end'."})
    else:
        for p in ports.split(","):
            try:
                port_num = int(p.strip())
                if not 1 <= port_num <= 65535:
                    return json.dumps({"error": f"Invalid port number: {port_num}"})
                port_list.append(port_num)
            except ValueError:
                return json.dumps({"error": f"Non-numeric port: {p.strip()!r}"})

    open_ports: list[dict] = []
    closed_count = 0

    for port in port_list:
        try:
            with socket.create_connection((host, port), timeout=1):
                service = _COMMON_PORTS.get(port, "Unknown")
                risk = "HIGH" if port in (23, 21, 3389, 5900) else "MEDIUM" if port in (80, 8080, 6379, 27017) else "LOW"
                open_ports.append({"port": port, "state": "open", "service": service, "risk": risk})
        except (ConnectionRefusedError, OSError, TimeoutError):
            closed_count += 1

    security_notes: list[str] = []
    open_port_nums = {p["port"] for p in open_ports}
    if 23 in open_port_nums:
        security_notes.append("Port 23 (Telnet) is open – unencrypted protocol, replace with SSH.")
    if 21 in open_port_nums:
        security_notes.append("Port 21 (FTP) is open – unencrypted, consider SFTP/FTPS.")
    if 3389 in open_port_nums:
        security_notes.append("Port 3389 (RDP) exposed – restrict with firewall rules.")
    if 5900 in open_port_nums:
        security_notes.append("Port 5900 (VNC) exposed – ensure strong authentication.")

    return json.dumps(
        {
            "host": host,
            "scanned_ports": len(port_list),
            "open_ports": open_ports,
            "closed_or_filtered": closed_count,
            "security_notes": security_notes,
        },
        indent=2,
    )


@_mcp.tool()
def analyze_http_headers(headers_json: str) -> str:
    """
    Evaluate HTTP response headers for common security misconfigurations.

    Pass in the headers as a JSON object (key-value string pairs).

    Args:
        headers_json: JSON string of HTTP header name → value pairs.

    Returns:
        JSON with a security grade, present/missing security headers, and
        headers that leak server information.
    """
    try:
        headers: dict[str, str] = json.loads(headers_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "headers_json must be valid JSON."})

    if not isinstance(headers, dict):
        return json.dumps({"error": "headers_json must be a JSON object."})

    # Normalise header names to title-case for comparison
    norm: dict[str, str] = {k.title(): v for k, v in headers.items()}

    present: list[dict] = []
    missing: list[str] = []

    for header, description in _SECURITY_HEADERS.items():
        if header in norm:
            present.append({"header": header, "value": norm[header], "description": description})
        else:
            missing.append(header)

    leaking: list[dict] = []
    for h in _DANGEROUS_HEADERS:
        if h in norm:
            leaking.append({"header": h, "value": norm[h], "risk": "Reveals server technology stack"})

    score = len(present) / len(_SECURITY_HEADERS) * 100
    if score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    recommendations: list[str] = []
    if "Strict-Transport-Security" not in norm:
        recommendations.append("Add HSTS header to enforce HTTPS: Strict-Transport-Security: max-age=31536000; includeSubDomains")
    if "Content-Security-Policy" not in norm:
        recommendations.append("Define a Content-Security-Policy to prevent XSS and data injection.")
    if leaking:
        recommendations.append("Remove information-leaking headers: " + ", ".join(h["header"] for h in leaking))

    return json.dumps(
        {
            "security_score": round(score, 1),
            "grade": grade,
            "present_security_headers": present,
            "missing_security_headers": missing,
            "leaking_headers": leaking,
            "recommendations": recommendations,
        },
        indent=2,
    )


@_mcp.tool()
def check_ssl_certificate(hostname: str, port: int = 443) -> str:
    """
    Retrieve and analyse the SSL/TLS certificate for a remote host.

    Args:
        hostname: Target hostname (e.g. "example.com").
        port:     TCP port to connect on (default 443).

    Returns:
        JSON with certificate subject, issuer, validity dates, and security notes.
    """
    if not _validate_hostname(hostname):
        return json.dumps({"error": "Invalid hostname format."})
    if not 1 <= port <= 65535:
        return json.dumps({"error": "Port must be between 1 and 65535."})

    import ssl

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, port), timeout=5), server_hostname=hostname
        ) as ssock:
            cert = ssock.getpeercert()
            tls_version = ssock.version()
            cipher = ssock.cipher()
    except ssl.SSLCertVerificationError as exc:
        return json.dumps({"hostname": hostname, "error": f"Certificate verification failed: {exc}"})
    except (socket.timeout, OSError) as exc:
        return json.dumps({"hostname": hostname, "error": f"Connection failed: {exc}"})

    # Parse validity dates
    not_before = datetime.strptime(cert.get("notBefore", ""), "%b %d %H:%M:%S %Y %Z")
    not_after = datetime.strptime(cert.get("notAfter", ""), "%b %d %H:%M:%S %Y %Z")
    days_left = (not_after - datetime.utcnow()).days

    subject = {k: v for tup in cert.get("subject", []) for k, v in [tup[0]]}
    issuer = {k: v for tup in cert.get("issuer", []) for k, v in [tup[0]]}
    san_list: list[str] = [val for _, val in cert.get("subjectAltName", [])]

    security_notes: list[str] = []
    if days_left < 0:
        security_notes.append("CRITICAL: Certificate has expired!")
    elif days_left < 14:
        security_notes.append(f"WARNING: Certificate expires in {days_left} days.")
    elif days_left < 30:
        security_notes.append(f"Certificate expires soon ({days_left} days).")

    deprecated_tls = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
    if tls_version in deprecated_tls:
        security_notes.append(f"Deprecated TLS version in use: {tls_version}. Upgrade to TLS 1.2+.")

    if cipher and cipher[1] in deprecated_tls:
        security_notes.append(f"Weak cipher suite: {cipher[0]}.")

    wildcard = any(san.startswith("*.") for san in san_list)
    if wildcard:
        security_notes.append("Wildcard certificate detected – may increase scope of breach if compromised.")

    return json.dumps(
        {
            "hostname": hostname,
            "port": port,
            "subject": subject,
            "issuer": issuer,
            "valid_from": not_before.isoformat(),
            "valid_until": not_after.isoformat(),
            "days_until_expiry": days_left,
            "subject_alt_names": san_list,
            "tls_version": tls_version,
            "cipher_suite": cipher[0] if cipher else None,
            "wildcard": wildcard,
            "security_notes": security_notes,
        },
        indent=2,
    )


@_mcp.tool()
def whois_lookup(domain: str) -> str:
    """
    Return simulated WHOIS registration data for a domain.

    This tool demonstrates what WHOIS data looks like; in production you would
    query a real WHOIS server or RDAP API.

    Args:
        domain: Domain name to look up (e.g. "example.com").

    Returns:
        JSON with registration details and privacy/security observations.
    """
    if not _validate_hostname(domain):
        return json.dumps({"error": "Invalid domain format."})

    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else "unknown"
    now = datetime.utcnow()
    simulated_creation = now - timedelta(days=365 * 5)
    simulated_expiry = now + timedelta(days=180)

    days_to_expiry = (simulated_expiry - now).days
    notes: list[str] = []
    if days_to_expiry < 30:
        notes.append(f"Domain expires in {days_to_expiry} days – may be hijacked after expiry.")
    if tld in ("tk", "ml", "ga", "cf", "gq"):
        notes.append(f"TLD '.{tld}' is commonly abused for phishing and malware distribution.")

    return json.dumps(
        {
            "domain": domain,
            "registrar": "Example Registrar LLC (simulated)",
            "registration_date": simulated_creation.strftime("%Y-%m-%d"),
            "expiry_date": simulated_expiry.strftime("%Y-%m-%d"),
            "days_to_expiry": days_to_expiry,
            "registrant": "REDACTED FOR PRIVACY",
            "name_servers": [f"ns1.{domain}", f"ns2.{domain}"],
            "dnssec": "unsigned",
            "privacy_protected": True,
            "security_notes": notes,
            "note": "This is simulated WHOIS data for educational purposes.",
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Export list consumed by server.py
# ---------------------------------------------------------------------------
NETWORK_TOOLS = [dns_lookup, port_scan, analyze_http_headers, check_ssl_certificate, whois_lookup]
