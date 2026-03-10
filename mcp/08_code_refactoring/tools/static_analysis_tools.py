"""
static_analysis_tools.py
--------------------------
MCP tools for static code analysis: quality scoring, smell detection, and
security pattern checking.

Tools:
  - analyze_code_quality    : Overall quality score and violation summary.
  - detect_code_smells      : Identify common code smells in source files.
  - find_dead_code          : Locate unused variables, imports, and unreachable code.
  - check_security_patterns : Scan for insecure coding patterns.
"""

from __future__ import annotations

import json
import re

from mcp.server.fastmcp import FastMCP

_mcp = FastMCP("static-analysis-tools")

# ---------------------------------------------------------------------------
# Pattern libraries
# ---------------------------------------------------------------------------

_SMELL_PATTERNS: dict[str, dict] = {
    "long_function": {
        "description": "Function/method body longer than 50 lines",
        "severity": "MEDIUM",
        "category": "maintainability",
    },
    "magic_numbers": {
        "pattern": r"(?<!\w)(?<!def\s)(?<!\.)(?<!\[)\b([2-9]\d{1,}|1[0-9]+)\b(?!\s*[=\[])",
        "description": "Numeric literals that are not 0 or 1 and not in constants",
        "severity": "LOW",
        "category": "readability",
    },
    "long_parameter_list": {
        "pattern": r"def\s+\w+\s*\(([^)]+)\)",
        "description": "Functions with more than 4 parameters",
        "severity": "MEDIUM",
        "category": "design",
    },
    "duplicate_code_indicator": {
        "pattern": r"(\b\w{6,}\b(?:\s+\w+){3,})\n.*\1",
        "description": "Potential duplicated code block",
        "severity": "HIGH",
        "category": "duplication",
    },
    "nested_ternary": {
        "pattern": r"\bif\b[^\n]*\belse\b[^\n]*\bif\b[^\n]*\belse\b",
        "description": "Nested ternary expressions reduce readability",
        "severity": "MEDIUM",
        "category": "readability",
    },
    "print_statement": {
        "pattern": r"^\s*print\s*\(",
        "description": "print() statement in production code (use logging)",
        "severity": "LOW",
        "category": "maintainability",
    },
    "commented_out_code": {
        "pattern": r"#\s*(if|for|while|def|class|return|import)\s+\w",
        "description": "Commented-out code should be removed",
        "severity": "LOW",
        "category": "cleanliness",
    },
    "bare_except": {
        "pattern": r"except\s*:",
        "description": "Bare except clause catches all exceptions including SystemExit",
        "severity": "HIGH",
        "category": "error_handling",
    },
    "mutable_default_argument": {
        "pattern": r"def\s+\w+\s*\([^)]*=\s*(\[\]|\{\}|list\(\)|dict\(\))",
        "description": "Mutable default argument – shared across all calls",
        "severity": "HIGH",
        "category": "bugs",
    },
    "hardcoded_password": {
        "pattern": r"(password|passwd|secret|token|key)\s*=\s*['\"][^'\"]{4,}['\"]",
        "description": "Hardcoded credential or secret",
        "severity": "CRITICAL",
        "category": "security",
    },
}

_SECURITY_PATTERNS: dict[str, dict] = {
    "sql_injection_risk": {
        "patterns": [
            r"f['\"].*SELECT.*\{",
            r"f['\"].*INSERT.*\{",
            r"f['\"].*UPDATE.*\{",
            r"['\"].*%s.*['\"].*%.*\(",
            r"\.format\(.*\).*WHERE",
        ],
        "description": "String-formatted SQL query – use parameterised queries",
        "severity": "CRITICAL",
        "cwe": "CWE-89",
    },
    "command_injection_risk": {
        "patterns": [
            r"os\.system\s*\(",
            r"subprocess\.call\s*\(.*shell\s*=\s*True",
            r"subprocess\.run\s*\(.*shell\s*=\s*True",
            r"eval\s*\(",
            r"exec\s*\(",
        ],
        "description": "Potentially unsafe command or code execution",
        "severity": "CRITICAL",
        "cwe": "CWE-78",
    },
    "path_traversal_risk": {
        "patterns": [
            r"open\s*\(\s*.*\+",
            r"open\s*\(\s*f['\"]",
        ],
        "description": "File path built from user input without validation",
        "severity": "HIGH",
        "cwe": "CWE-22",
    },
    "insecure_random": {
        "patterns": [
            r"\brandom\.random\s*\(",
            r"\brandom\.randint\s*\(",
            r"\brandom\.choice\s*\(",
        ],
        "description": "Non-cryptographic random used for security-sensitive context",
        "severity": "MEDIUM",
        "cwe": "CWE-330",
    },
    "weak_hash": {
        "patterns": [
            r"hashlib\.md5\s*\(",
            r"hashlib\.sha1\s*\(",
        ],
        "description": "Weak hashing algorithm (MD5/SHA-1)",
        "severity": "HIGH",
        "cwe": "CWE-327",
    },
    "xxe_risk": {
        "patterns": [
            r"xml\.etree\.ElementTree\.parse",
            r"lxml\.etree\.parse\s*\(",
        ],
        "description": "XML parsing without explicit XXE protection",
        "severity": "MEDIUM",
        "cwe": "CWE-611",
    },
    "pickle_deserialization": {
        "patterns": [
            r"pickle\.loads\s*\(",
            r"pickle\.load\s*\(",
        ],
        "description": "Pickle deserialization of untrusted data enables RCE",
        "severity": "CRITICAL",
        "cwe": "CWE-502",
    },
}


def _count_function_lines(code: str) -> list[dict]:
    """Return functions with their line counts."""
    functions: list[dict] = []
    lines = code.split("\n")
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)def\s+(\w+)\s*\(", lines[i])
        if m:
            indent = len(m.group(1))
            func_name = m.group(2)
            start = i
            j = i + 1
            while j < len(lines):
                stripped = lines[j].rstrip()
                if stripped and not stripped.startswith(" " * (indent + 1)) and not stripped.startswith("\t" * (indent // 4 + 1)):
                    break
                j += 1
            length = j - start
            functions.append({"name": func_name, "line": start + 1, "length": length})
            i = j
        else:
            i += 1
    return functions


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@_mcp.tool()
def analyze_code_quality(code: str, language: str = "python") -> str:
    """
    Compute an overall quality score and summarize violations.

    Args:
        code:     Source code text to analyze (max 100 000 characters).
        language: Programming language hint (python, javascript, java, generic).

    Returns:
        JSON with quality score (0–100), violation counts by category, and
        prioritised recommendations.
    """
    if len(code) > 100_000:
        return json.dumps({"error": "Code too large. Maximum 100 000 characters."})

    violations: list[dict] = []
    severity_weights = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2}

    # Run pattern-based smell checks
    for smell_name, info in _SMELL_PATTERNS.items():
        pattern = info.get("pattern")
        if not pattern:
            continue
        matches = re.findall(pattern, code, re.MULTILINE | re.IGNORECASE)
        if matches:
            violations.append({
                "rule": smell_name,
                "category": info["category"],
                "severity": info["severity"],
                "description": info["description"],
                "occurrences": len(matches),
            })

    # Long function check
    for fn in _count_function_lines(code):
        if fn["length"] > 50:
            violations.append({
                "rule": "long_function",
                "category": "maintainability",
                "severity": "MEDIUM",
                "description": f"Function '{fn['name']}' has {fn['length']} lines (limit: 50)",
                "occurrences": 1,
            })

    # Security pattern checks
    for sec_name, info in _SECURITY_PATTERNS.items():
        for pattern in info["patterns"]:
            if re.search(pattern, code, re.IGNORECASE):
                violations.append({
                    "rule": sec_name,
                    "category": "security",
                    "severity": info["severity"],
                    "description": info["description"],
                    "occurrences": 1,
                })
                break

    penalty = sum(
        severity_weights.get(v["severity"], 0) * min(v.get("occurrences", 1), 5)
        for v in violations
    )
    quality_score = max(0, 100 - penalty)

    grade = "A" if quality_score >= 90 else "B" if quality_score >= 75 else "C" if quality_score >= 60 else "D" if quality_score >= 45 else "F"

    categories: dict[str, int] = {}
    for v in violations:
        categories[v["category"]] = categories.get(v["category"], 0) + 1

    recommendations = []
    critical = [v for v in violations if v["severity"] == "CRITICAL"]
    if critical:
        recommendations.append(f"Fix {len(critical)} CRITICAL security issue(s) immediately.")
    high = [v for v in violations if v["severity"] == "HIGH"]
    if high:
        recommendations.append(f"Address {len(high)} HIGH severity issue(s) before deployment.")
    if categories.get("readability", 0) > 2:
        recommendations.append("Improve code readability: remove nested logic and magic numbers.")
    if categories.get("maintainability", 0) > 1:
        recommendations.append("Break long functions into smaller, focused units.")

    return json.dumps(
        {
            "language": language,
            "quality_score": quality_score,
            "grade": grade,
            "total_violations": len(violations),
            "violations_by_category": categories,
            "violations": sorted(violations, key=lambda v: severity_weights.get(v["severity"], 0), reverse=True),
            "recommendations": recommendations,
        },
        indent=2,
    )


@_mcp.tool()
def detect_code_smells(code: str) -> str:
    """
    Identify specific code smells with line-level context where possible.

    Args:
        code: Source code text to analyze (max 100 000 characters).

    Returns:
        JSON with detected smells, descriptions, and fix suggestions.
    """
    if len(code) > 100_000:
        return json.dumps({"error": "Code too large. Maximum 100 000 characters."})

    smells: list[dict] = []
    lines = code.split("\n")

    for line_no, line in enumerate(lines, 1):
        for smell_name, info in _SMELL_PATTERNS.items():
            pattern = info.get("pattern")
            if not pattern:
                continue
            if re.search(pattern, line, re.IGNORECASE):
                smells.append({
                    "smell": smell_name,
                    "line": line_no,
                    "severity": info["severity"],
                    "description": info["description"],
                    "code_snippet": line.strip()[:100],
                    "category": info["category"],
                })

    # Long function smell
    for fn in _count_function_lines(code):
        if fn["length"] > 50:
            smells.append({
                "smell": "long_function",
                "line": fn["line"],
                "severity": "MEDIUM",
                "description": f"Function '{fn['name']}' ({fn['length']} lines). Extract sub-functions.",
                "code_snippet": f"def {fn['name']}(...)",
                "category": "maintainability",
            })

    fix_suggestions: dict[str, str] = {
        "magic_numbers": "Extract to named constants (e.g. MAX_RETRIES = 3).",
        "long_parameter_list": "Introduce a parameter object or use *args/**kwargs.",
        "print_statement": "Replace with logging.info() / logging.debug().",
        "commented_out_code": "Delete commented-out code; use version control instead.",
        "bare_except": "Catch specific exceptions: except ValueError: or except (TypeError, KeyError):",
        "mutable_default_argument": "Use None as default; create fresh object inside function body.",
        "hardcoded_password": "Move to environment variables or a secrets manager.",
        "nested_ternary": "Use explicit if-else blocks for clarity.",
        "long_function": "Apply Extract Function refactoring; aim for < 20 lines per function.",
    }

    for smell in smells:
        smell["fix_suggestion"] = fix_suggestions.get(smell["smell"], "Review and simplify.")

    return json.dumps(
        {
            "total_smells": len(smells),
            "smells": smells,
        },
        indent=2,
    )


@_mcp.tool()
def find_dead_code(code: str) -> str:
    """
    Locate potentially unused variables, unreachable code, and redundant imports.

    Args:
        code: Python source code text to analyze.

    Returns:
        JSON with detected dead code patterns and removal suggestions.
    """
    if len(code) > 100_000:
        return json.dumps({"error": "Code too large. Maximum 100 000 characters."})

    findings: list[dict] = []
    lines = code.split("\n")

    imports: list[dict] = []
    for line_no, line in enumerate(lines, 1):
        m = re.match(r"^import\s+(\w+)", line.strip())
        if m:
            imports.append({"name": m.group(1), "line": line_no, "line_text": line.strip()})
        m2 = re.match(r"^from\s+\S+\s+import\s+(.+)", line.strip())
        if m2:
            for name in re.split(r",\s*", m2.group(1)):
                clean = name.strip().split(" as ")[-1].strip()
                imports.append({"name": clean, "line": line_no, "line_text": line.strip()})

    # Check each import is used elsewhere
    for imp in imports:
        uses = len(re.findall(r"\b" + re.escape(imp["name"]) + r"\b", code)) - 1
        if uses == 0:
            findings.append({
                "type": "unused_import",
                "line": imp["line"],
                "description": f"Import '{imp['name']}' is never used.",
                "code_snippet": imp["line_text"],
                "fix": f"Remove 'import {imp['name']}' or use autoflake to clean unused imports.",
            })

    # Unreachable code after return/raise
    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped in ("return", "raise", "break", "continue") or stripped.startswith(("return ", "raise ")):
            if line_no < len(lines):
                next_line = lines[line_no].strip()
                if next_line and not next_line.startswith(("#", "def ", "class ", "@", "else", "elif", "except", "finally")):
                    # Check same indent level
                    current_indent = len(line) - len(line.lstrip())
                    next_indent = len(lines[line_no]) - len(lines[line_no].lstrip())
                    if next_indent >= current_indent and lines[line_no].strip():
                        findings.append({
                            "type": "unreachable_code",
                            "line": line_no + 1,
                            "description": "Code after return/raise/break may be unreachable.",
                            "code_snippet": next_line[:80],
                            "fix": "Remove unreachable code or restructure control flow.",
                        })

    # Variables assigned but never read (heuristic: single assignment, no reads)
    assigned: dict[str, list[int]] = {}
    for line_no, line in enumerate(lines, 1):
        m = re.match(r"^\s+(\w+)\s*=\s*(?!\s*lambda)", line)
        if m and not line.strip().startswith(("#", "def ", "class ", "return ")):
            var = m.group(1)
            if var not in ("self", "cls") and not var.startswith("_"):
                if var not in assigned:
                    assigned[var] = []
                assigned[var].append(line_no)

    for var, assign_lines in assigned.items():
        uses = len(re.findall(r"\b" + re.escape(var) + r"\b", code)) - len(assign_lines)
        if uses == 0 and len(assign_lines) == 1:
            findings.append({
                "type": "unused_variable",
                "line": assign_lines[0],
                "description": f"Variable '{var}' is assigned but never read.",
                "code_snippet": lines[assign_lines[0] - 1].strip()[:80],
                "fix": f"Remove the assignment or prefix with '_' if intentionally unused.",
            })

    return json.dumps(
        {
            "total_findings": len(findings),
            "findings": findings,
            "tools_recommendation": "Run 'flake8 --select=F401,F841' or 'autoflake' for automated detection.",
        },
        indent=2,
    )


@_mcp.tool()
def check_security_patterns(code: str, language: str = "python") -> str:
    """
    Scan source code for insecure coding patterns mapped to CWE identifiers.

    Args:
        code:     Source code text (max 100 000 characters).
        language: Programming language hint (python, javascript, java, generic).

    Returns:
        JSON with security findings, CWE references, and remediation guidance.
    """
    if len(code) > 100_000:
        return json.dumps({"error": "Code too large. Maximum 100 000 characters."})

    findings: list[dict] = []

    for issue_name, info in _SECURITY_PATTERNS.items():
        for pattern in info["patterns"]:
            matches = list(re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE))
            if matches:
                finding = {
                    "issue": issue_name.replace("_", " ").title(),
                    "severity": info["severity"],
                    "cwe": info.get("cwe", "N/A"),
                    "description": info["description"],
                    "occurrences": len(matches),
                    "sample_location": f"Line ~{code[:matches[0].start()].count(chr(10)) + 1}",
                }
                findings.append(finding)
                break  # One finding per issue type

    severity_weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    risk_score = sum(severity_weights.get(f["severity"], 0) for f in findings)

    return json.dumps(
        {
            "language": language,
            "security_risk_score": risk_score,
            "risk_level": "CRITICAL" if risk_score >= 8 else "HIGH" if risk_score >= 5 else "MEDIUM" if risk_score >= 2 else "LOW",
            "total_findings": len(findings),
            "findings": sorted(findings, key=lambda f: severity_weights.get(f["severity"], 0), reverse=True),
            "remediation_summary": [
                "Replace string-formatted SQL with parameterised queries / ORM.",
                "Avoid os.system() and shell=True; use subprocess with argument lists.",
                "Validate and sanitise all file paths against an allowlist.",
                "Use secrets module instead of random for security contexts.",
                "Replace MD5/SHA-1 with SHA-256/SHA-3 or bcrypt/Argon2 for passwords.",
                "Enable defusedxml for XML parsing to prevent XXE.",
                "Never deserialise pickle data from untrusted sources.",
            ] if findings else ["No security issues detected."],
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
STATIC_ANALYSIS_TOOLS = [
    analyze_code_quality,
    detect_code_smells,
    find_dead_code,
    check_security_patterns,
]
