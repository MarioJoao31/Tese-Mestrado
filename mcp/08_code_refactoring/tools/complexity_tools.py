"""
complexity_tools.py
--------------------
MCP tools for measuring code complexity and size metrics.

Tools:
  - calculate_cyclomatic_complexity : Per-function McCabe complexity score.
  - measure_code_metrics            : LOC, comment ratio, blank lines, etc.
  - analyze_nesting_depth           : Detect deeply nested code.
  - evaluate_coupling               : Estimate coupling between functions/classes.
"""

from __future__ import annotations

import json
import re
import statistics
from collections import Counter

from mcp.server.fastmcp import FastMCP

_mcp = FastMCP("complexity-tools")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Decision-point keywords that increase cyclomatic complexity
_DECISION_KEYWORDS_PYTHON = re.compile(
    r"\b(if|elif|else|for|while|except|with|assert|and|or|case)\b"
)

_DECISION_KEYWORDS_JS = re.compile(
    r"\b(if|else\s+if|else|for|while|do|switch|case|catch|&&|\|\||try)\b"
)

_DECISION_KEYWORDS_JAVA = re.compile(
    r"\b(if|else\s+if|else|for|while|do|switch|case|catch|&&|\|\|)\b"
)

_FUNCTION_PATTERN_PYTHON = re.compile(r"^(\s*)def\s+(\w+)\s*\(", re.MULTILINE)
_FUNCTION_PATTERN_JS = re.compile(r"(?:function\s+(\w+)|(\w+)\s*=\s*(?:async\s+)?function|\b(\w+)\s*:\s*function)", re.MULTILINE)
_CLASS_PATTERN = re.compile(r"^(\s*)class\s+(\w+)\s*[\(:]", re.MULTILINE)


def _extract_python_functions(code: str) -> list[dict]:
    """Extract Python functions with their bodies."""
    functions = []
    lines = code.split("\n")
    matches = list(_FUNCTION_PATTERN_PYTHON.finditer(code))

    for idx, m in enumerate(matches):
        indent = len(m.group(1))
        name = m.group(2)
        start_line = code[:m.start()].count("\n") + 1

        # Find function end
        start_pos = m.end()
        if idx + 1 < len(matches):
            # Find next function at same or lower indent
            next_m = matches[idx + 1]
            next_indent = len(next_m.group(1))
            if next_indent <= indent:
                end_pos = next_m.start()
            else:
                end_pos = len(code)
        else:
            end_pos = len(code)

        body = code[start_pos:end_pos]
        end_line = start_line + body.count("\n")
        functions.append({
            "name": name,
            "start_line": start_line,
            "end_line": end_line,
            "body": body,
            "lines": end_line - start_line + 1,
        })

    return functions


def _cyclomatic_complexity(body: str, language: str = "python") -> int:
    """Compute McCabe cyclomatic complexity for a code body."""
    if language == "javascript":
        pattern = _DECISION_KEYWORDS_JS
    elif language == "java":
        pattern = _DECISION_KEYWORDS_JAVA
    else:
        pattern = _DECISION_KEYWORDS_PYTHON

    count = len(pattern.findall(body))
    return 1 + count  # Base complexity = 1


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@_mcp.tool()
def calculate_cyclomatic_complexity(code: str, language: str = "python") -> str:
    """
    Compute McCabe cyclomatic complexity for each function/method in the code.

    Complexity thresholds:
    - 1–5   : Simple, low risk
    - 6–10  : Moderate, some risk
    - 11–20 : Complex, high risk
    - > 20  : Very complex, very high risk – refactor required

    Args:
        code:     Source code text (max 100 000 characters).
        language: python, javascript, java, or generic.

    Returns:
        JSON with per-function complexity scores and an overall risk summary.
    """
    if len(code) > 100_000:
        return json.dumps({"error": "Code too large. Maximum 100 000 characters."})

    functions = _extract_python_functions(code) if language == "python" else []

    if not functions:
        # Fallback: treat whole code as one unit
        complexity = _cyclomatic_complexity(code, language)
        functions = [{"name": "<module>", "start_line": 1, "end_line": code.count("\n") + 1, "body": code, "lines": code.count("\n") + 1}]

    results: list[dict] = []
    for fn in functions:
        cc = _cyclomatic_complexity(fn["body"], language)
        risk = "LOW" if cc <= 5 else "MEDIUM" if cc <= 10 else "HIGH" if cc <= 20 else "VERY HIGH"
        results.append({
            "function": fn["name"],
            "start_line": fn["start_line"],
            "cyclomatic_complexity": cc,
            "risk": risk,
            "lines": fn["lines"],
        })

    results.sort(key=lambda x: x["cyclomatic_complexity"], reverse=True)
    avg_cc = statistics.mean(r["cyclomatic_complexity"] for r in results) if results else 0
    max_cc = max((r["cyclomatic_complexity"] for r in results), default=0)
    high_risk = [r for r in results if r["risk"] in ("HIGH", "VERY HIGH")]

    return json.dumps(
        {
            "language": language,
            "total_functions": len(results),
            "average_complexity": round(avg_cc, 2),
            "max_complexity": max_cc,
            "high_risk_functions": len(high_risk),
            "functions": results,
            "recommendations": [
                f"Refactor '{r['function']}' (CC={r['cyclomatic_complexity']}) – extract methods to reduce branching."
                for r in high_risk[:5]
            ],
        },
        indent=2,
    )


@_mcp.tool()
def measure_code_metrics(code: str, language: str = "python") -> str:
    """
    Measure standard code size and documentation metrics.

    Metrics: total lines, lines of code (LOC), blank lines, comment lines,
    comment ratio, average function length, class count, function count.

    Args:
        code:     Source code text (max 100 000 characters).
        language: python, javascript, java, or generic.

    Returns:
        JSON with all metrics and quality observations.
    """
    if len(code) > 100_000:
        return json.dumps({"error": "Code too large. Maximum 100 000 characters."})

    lines = code.split("\n")
    total_lines = len(lines)
    blank_lines = sum(1 for l in lines if not l.strip())

    # Comment detection varies by language
    if language in ("javascript", "java"):
        comment_pattern = re.compile(r"^\s*(//|/\*|\*)")
    else:  # python / generic
        comment_pattern = re.compile(r"^\s*#")

    comment_lines = sum(1 for l in lines if comment_pattern.match(l))
    loc = total_lines - blank_lines - comment_lines

    # Docstring lines (Python)
    docstring_lines = len(re.findall(r'"""[\s\S]*?"""', code)) + len(re.findall(r"'''[\s\S]*?'''", code))

    functions = _extract_python_functions(code)
    function_count = len(functions)
    function_lengths = [fn["lines"] for fn in functions]
    avg_fn_length = statistics.mean(function_lengths) if function_lengths else 0

    class_count = len(_CLASS_PATTERN.findall(code))

    comment_ratio = comment_lines / max(total_lines, 1)
    doc_coverage = function_count > 0 and sum(1 for fn in functions if '"""' in fn["body"] or "'''" in fn["body"]) / function_count

    observations: list[str] = []
    if comment_ratio < 0.1:
        observations.append("Low comment ratio (<10%) – consider adding inline explanations for complex logic.")
    if avg_fn_length > 50:
        observations.append(f"Average function length ({avg_fn_length:.0f} lines) is high – aim for < 20 lines.")
    if isinstance(doc_coverage, float) and doc_coverage < 0.5:
        observations.append("Less than 50% of functions have docstrings – improve API documentation.")
    if blank_lines / max(total_lines, 1) > 0.25:
        observations.append("More than 25% blank lines – consider condensing.")

    return json.dumps(
        {
            "language": language,
            "total_lines": total_lines,
            "lines_of_code": loc,
            "blank_lines": blank_lines,
            "comment_lines": comment_lines,
            "comment_ratio": round(comment_ratio, 3),
            "function_count": function_count,
            "class_count": class_count,
            "average_function_length": round(avg_fn_length, 1),
            "max_function_length": max(function_lengths, default=0),
            "docstring_blocks": docstring_lines,
            "observations": observations,
        },
        indent=2,
    )


@_mcp.tool()
def analyze_nesting_depth(code: str) -> str:
    """
    Detect deeply nested code blocks and flag functions that exceed depth thresholds.

    Args:
        code: Source code text (max 100 000 characters).

    Returns:
        JSON with per-function max nesting depth, overall depth distribution, and
        refactoring suggestions.
    """
    if len(code) > 100_000:
        return json.dumps({"error": "Code too large. Maximum 100 000 characters."})

    _INDENT_BLOCK_STARTERS = re.compile(r"^\s*(if|elif|else|for|while|with|try|except|finally|def|class)\b")

    lines = code.split("\n")
    depth_per_line: list[int] = []

    for line in lines:
        if not line.strip():
            depth_per_line.append(0)
            continue
        indent = len(line) - len(line.lstrip())
        depth_per_line.append(indent // 4)  # Assume 4-space indent

    max_depth = max(depth_per_line, default=0)
    avg_depth = statistics.mean(d for d in depth_per_line if d > 0) if any(d > 0 for d in depth_per_line) else 0

    deep_lines: list[dict] = [
        {"line": i + 1, "depth": d, "code": lines[i].strip()[:80]}
        for i, d in enumerate(depth_per_line)
        if d >= 4
    ]

    risk = "HIGH" if max_depth >= 6 else "MEDIUM" if max_depth >= 4 else "LOW"

    suggestions: list[str] = []
    if max_depth >= 4:
        suggestions.append("Apply Early Return pattern to flatten conditionals.")
        suggestions.append("Extract deeply nested blocks into separate helper functions.")
    if max_depth >= 6:
        suggestions.append("Consider using strategy or state pattern to replace deep nesting.")

    return json.dumps(
        {
            "max_nesting_depth": max_depth,
            "average_nesting_depth": round(avg_depth, 2),
            "risk": risk,
            "deep_lines_count": len(deep_lines),
            "deep_lines_sample": deep_lines[:10],
            "suggestions": suggestions,
        },
        indent=2,
    )


@_mcp.tool()
def evaluate_coupling(code: str) -> str:
    """
    Estimate the coupling level between functions and classes in the code.

    High coupling makes code hard to test, change, and reuse.

    Args:
        code: Source code text (max 100 000 characters).

    Returns:
        JSON with import count, cross-function call map, and coupling assessment.
    """
    if len(code) > 100_000:
        return json.dumps({"error": "Code too large. Maximum 100 000 characters."})

    # Count imports (external dependencies)
    import_lines = re.findall(r"^(?:import|from)\s+(\S+)", code, re.MULTILINE)
    unique_modules = list(set(m.split(".")[0] for m in import_lines))

    # Find function definitions
    function_names = re.findall(r"def\s+(\w+)\s*\(", code)

    # Count how many times each function calls others
    call_counts: dict[str, int] = {}
    for fn in function_names:
        callers = re.findall(r"\b" + re.escape(fn) + r"\s*\(", code)
        definitions = code.count(f"def {fn}(")
        calls = len(callers) - definitions
        if calls > 0:
            call_counts[fn] = calls

    total_calls = sum(call_counts.values())
    avg_calls = total_calls / max(len(function_names), 1)

    coupling_level = (
        "HIGH" if len(unique_modules) > 15 or avg_calls > 10
        else "MEDIUM" if len(unique_modules) > 8 or avg_calls > 5
        else "LOW"
    )

    recommendations: list[str] = []
    if len(unique_modules) > 10:
        recommendations.append("High number of imports – consider dependency injection or facade pattern.")
    if avg_calls > 8:
        recommendations.append("Highly inter-connected functions – decompose into cohesive modules.")
    if coupling_level == "LOW":
        recommendations.append("Low coupling – good modular design.")

    return json.dumps(
        {
            "import_count": len(import_lines),
            "unique_modules": len(unique_modules),
            "modules": unique_modules[:20],
            "function_count": len(function_names),
            "internal_call_count": total_calls,
            "average_calls_per_function": round(avg_calls, 2),
            "most_called_functions": sorted(call_counts.items(), key=lambda x: -x[1])[:10],
            "coupling_level": coupling_level,
            "recommendations": recommendations,
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
COMPLEXITY_TOOLS = [
    calculate_cyclomatic_complexity,
    measure_code_metrics,
    analyze_nesting_depth,
    evaluate_coupling,
]
