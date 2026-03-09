"""
log_analysis_tools.py
----------------------
MCP tool functions for security log parsing and threat detection.

Tools:
  - parse_access_log          : Parse Common/Combined Log Format web access logs.
  - detect_brute_force        : Identify brute-force login attempts from auth logs.
  - extract_ips_from_log      : Extract, deduplicate, and classify IP addresses.
  - detect_sqli_in_log        : Find SQL injection attempts in URL request logs.
  - summarize_log_statistics  : Produce high-level statistics for any log text.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime

from mcp.server.fastmcp import FastMCP

_mcp = FastMCP("log-analysis-tools")

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Common Log Format:  IP - - [date] "METHOD /path HTTP/1.x" status bytes
_CLF_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+'          # Remote host
    r'\S+\s+'                  # Ident (-)
    r'\S+\s+'                  # Auth user (-)
    r'\[(?P<time>[^\]]+)\]\s+' # Timestamp
    r'"(?P<request>[^"]+)"\s+' # Request line
    r'(?P<status>\d{3})\s+'    # Status code
    r'(?P<bytes>\S+)'          # Response size
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?',  # Optional combined fields
)

# Auth log patterns  (syslog format)
_AUTH_FAILED_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd.*"
    r"(?:Failed password|authentication failure|Invalid user)\s+"
    r"(?:for\s+(?P<user>\S+)\s+)?from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)

# SQL injection indicator patterns in URL paths / query strings
_SQLI_PATTERNS: list[tuple[str, str]] = [
    (r"union\s+select",       "UNION SELECT injection"),
    (r"'\s*or\s+'1'\s*=\s*'1",   "OR 1=1 tautology"),
    (r";\s*drop\s+table",     "DROP TABLE statement"),
    (r"--\s*$",               "SQL comment terminator"),
    (r"xp_cmdshell",          "SQL Server command shell"),
    (r"information_schema",   "Schema enumeration"),
    (r"benchmark\s*\(",       "MySQL BENCHMARK timing attack"),
    (r"sleep\s*\(\s*\d+",     "Time-based blind SQLi"),
    (r"convert\s*\(\s*int",   "MSSQL type conversion probe"),
    (r"char\s*\(\s*\d+",      "Character encoding obfuscation"),
]


def _is_private_ip(ip: str) -> bool:
    try:
        parts = [int(p) for p in ip.split(".")]
        return (parts[0] == 10
                or (parts[0] == 172 and 16 <= parts[1] <= 31)
                or (parts[0] == 192 and parts[1] == 168)
                or parts[0] == 127)
    except (ValueError, IndexError):
        return False


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@_mcp.tool()
def parse_access_log(log_text: str, max_lines: int = 500) -> str:
    """
    Parse Apache/Nginx Common or Combined Log Format entries.

    Args:
        log_text:  Raw access log text (multi-line string).
        max_lines: Maximum number of lines to process (default 500).

    Returns:
        JSON with parsed requests, top IPs, status code distribution,
        and any suspicious 4xx/5xx spikes.
    """
    if len(log_text) > 500_000:
        return json.dumps({"error": "Log text too large. Maximum 500 000 characters."})

    lines = log_text.strip().splitlines()[:max_lines]
    parsed: list[dict] = []
    unparsed = 0

    for line in lines:
        m = _CLF_PATTERN.match(line.strip())
        if not m:
            unparsed += 1
            continue
        status = int(m.group("status"))
        method, path, *_ = (m.group("request") or "- -").split(" ", 2) + ["", ""]
        parsed.append({
            "ip": m.group("ip"),
            "time": m.group("time"),
            "method": method,
            "path": path,
            "status": status,
            "bytes": m.group("bytes"),
        })

    if not parsed:
        return json.dumps({"error": "No Common Log Format lines found.", "unparsed_lines": unparsed})

    ip_counter = Counter(e["ip"] for e in parsed)
    status_counter = Counter(e["status"] for e in parsed)
    method_counter = Counter(e["method"] for e in parsed)
    path_counter = Counter(e["path"] for e in parsed)

    errors_4xx = sum(v for k, v in status_counter.items() if 400 <= k < 500)
    errors_5xx = sum(v for k, v in status_counter.items() if 500 <= k < 600)

    anomalies: list[str] = []
    for ip, count in ip_counter.most_common(5):
        if count > max(10, len(parsed) * 0.2):
            anomalies.append(f"High request volume from {ip}: {count} requests ({count/len(parsed)*100:.1f}%)")

    if errors_5xx > len(parsed) * 0.1:
        anomalies.append(f"High 5xx error rate: {errors_5xx} server errors ({errors_5xx/len(parsed)*100:.1f}%)")

    return json.dumps(
        {
            "total_requests": len(parsed),
            "unparsed_lines": unparsed,
            "top_ips": ip_counter.most_common(10),
            "status_distribution": dict(sorted(status_counter.items())),
            "method_distribution": dict(method_counter),
            "top_paths": path_counter.most_common(10),
            "4xx_errors": errors_4xx,
            "5xx_errors": errors_5xx,
            "anomalies": anomalies,
        },
        indent=2,
    )


@_mcp.tool()
def detect_brute_force(
    log_text: str,
    threshold: int = 5,
    window_minutes: int = 10,
) -> str:
    """
    Detect brute-force login attempts in SSH / auth log output.

    Args:
        log_text:       Raw auth log or syslog text.
        threshold:      Minimum failed attempts per IP to flag as brute force.
        window_minutes: Time window in minutes for counting attempts (1–120).

    Returns:
        JSON with flagged IPs, attempt counts, targeted users, and recommendations.
    """
    if not 1 <= threshold <= 1000:
        return json.dumps({"error": "threshold must be between 1 and 1000."})
    if not 1 <= window_minutes <= 120:
        return json.dumps({"error": "window_minutes must be between 1 and 120."})

    ip_attempts: dict[str, list[dict]] = {}

    for line in log_text.splitlines():
        m = _AUTH_FAILED_PATTERN.search(line)
        if m:
            ip = m.group("ip")
            user = m.group("user") or "unknown"
            ts_str = m.group("timestamp")
            if ip not in ip_attempts:
                ip_attempts[ip] = []
            ip_attempts[ip].append({"user": user, "timestamp": ts_str, "line": line.strip()})

    flagged: list[dict] = []
    for ip, attempts in ip_attempts.items():
        if len(attempts) >= threshold:
            users_targeted = list({a["user"] for a in attempts})
            flagged.append({
                "ip": ip,
                "attempt_count": len(attempts),
                "users_targeted": users_targeted,
                "is_private": _is_private_ip(ip),
                "sample_lines": [a["line"] for a in attempts[:3]],
                "recommendation": f"Block {ip} with firewall rule; investigate intent.",
            })

    flagged.sort(key=lambda x: x["attempt_count"], reverse=True)

    return json.dumps(
        {
            "threshold": threshold,
            "total_failed_events": sum(len(v) for v in ip_attempts.values()),
            "unique_source_ips": len(ip_attempts),
            "flagged_ips": flagged,
            "recommendations": [
                "Enable fail2ban or equivalent automatic IP blocking.",
                "Disable password authentication; use SSH key pairs.",
                "Change default SSH port to reduce automated scanning.",
                "Implement geo-blocking for unexpected source countries.",
            ] if flagged else [],
        },
        indent=2,
    )


@_mcp.tool()
def extract_ips_from_log(log_text: str) -> str:
    """
    Extract all IPv4 addresses from log text, deduplicate, and classify them.

    Args:
        log_text: Any log text containing IP addresses.

    Returns:
        JSON with unique IPs, their frequency, and public/private classification.
    """
    if len(log_text) > 500_000:
        return json.dumps({"error": "Log text too large. Maximum 500 000 characters."})

    ip_pattern = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    all_ips = ip_pattern.findall(log_text)
    valid_ips = [ip for ip in all_ips if all(0 <= int(p) <= 255 for p in ip.split("."))]

    ip_counter = Counter(valid_ips)
    classified: list[dict] = []

    for ip, count in ip_counter.most_common():
        classified.append({
            "ip": ip,
            "count": count,
            "type": "private" if _is_private_ip(ip) else "public",
            "loopback": ip.startswith("127."),
        })

    public = [c for c in classified if c["type"] == "public"]
    private = [c for c in classified if c["type"] == "private"]

    return json.dumps(
        {
            "total_ip_occurrences": len(valid_ips),
            "unique_ips": len(ip_counter),
            "public_ips": len(public),
            "private_ips": len(private),
            "top_ips": classified[:20],
        },
        indent=2,
    )


@_mcp.tool()
def detect_sqli_in_log(log_text: str) -> str:
    """
    Scan web access log entries for SQL injection attempt patterns in URLs.

    Args:
        log_text: Raw web server access log (Common or Combined Log Format).

    Returns:
        JSON with detected attack lines, attack types, and source IPs.
    """
    if len(log_text) > 500_000:
        return json.dumps({"error": "Log text too large. Maximum 500 000 characters."})

    attacks: list[dict] = []

    for line_no, line in enumerate(log_text.splitlines(), 1):
        matched_types: list[str] = []
        for pattern, label in _SQLI_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                matched_types.append(label)

        if matched_types:
            ip_match = re.search(r"^(\S+)", line)
            ip = ip_match.group(1) if ip_match else "unknown"
            attacks.append({
                "line_number": line_no,
                "source_ip": ip,
                "attack_types": matched_types,
                "log_line": line.strip()[:300],
            })

    ip_attack_count = Counter(a["source_ip"] for a in attacks)
    attack_type_count = Counter(t for a in attacks for t in a["attack_types"])

    return json.dumps(
        {
            "total_sqli_attempts": len(attacks),
            "unique_attacker_ips": len(ip_attack_count),
            "attack_type_frequency": dict(attack_type_count.most_common()),
            "top_attacker_ips": ip_attack_count.most_common(10),
            "attack_details": attacks[:50],
            "recommendations": [
                "Use parameterised queries / prepared statements exclusively.",
                "Deploy a Web Application Firewall (WAF) with SQLi rules.",
                "Block attacking IPs at the load balancer / firewall.",
                "Enable detailed query logging and alerting for SQLi patterns.",
            ] if attacks else [],
        },
        indent=2,
    )


@_mcp.tool()
def summarize_log_statistics(log_text: str) -> str:
    """
    Generate high-level statistics from any plaintext log.

    Args:
        log_text: Arbitrary log text (access log, syslog, application log, etc.).

    Returns:
        JSON with line count, timestamp range, keyword frequencies, and
        common error indicators.
    """
    if len(log_text) > 500_000:
        return json.dumps({"error": "Log text too large. Maximum 500 000 characters."})

    lines = log_text.splitlines()
    word_counter: Counter = Counter()
    error_keywords = ["error", "fail", "critical", "alert", "warn", "denied", "attack", "invalid", "unauthorized", "exception"]
    keyword_counts: dict[str, int] = {kw: 0 for kw in error_keywords}

    for line in lines:
        lower = line.lower()
        for kw in error_keywords:
            if kw in lower:
                keyword_counts[kw] += 1

    ip_count = len(set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", log_text)))
    timestamp_patterns = re.findall(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", log_text)

    return json.dumps(
        {
            "total_lines": len(lines),
            "non_empty_lines": sum(1 for l in lines if l.strip()),
            "unique_ips_found": ip_count,
            "timestamp_samples": timestamp_patterns[:5] if timestamp_patterns else [],
            "keyword_frequencies": {k: v for k, v in sorted(keyword_counts.items(), key=lambda x: -x[1]) if v > 0},
            "top_keywords_total": sum(keyword_counts.values()),
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
LOG_ANALYSIS_TOOLS = [
    parse_access_log,
    detect_brute_force,
    extract_ips_from_log,
    detect_sqli_in_log,
    summarize_log_statistics,
]
