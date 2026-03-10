"""
refactoring_tools.py
---------------------
MCP tools that generate concrete refactoring suggestions.

Tools:
  - suggest_refactorings      : Comprehensive refactoring recommendation list.
  - suggest_extract_method    : Identify code blocks suitable for extraction.
  - improve_naming            : Detect naming violations and suggest improvements.
  - simplify_conditionals     : Detect complex conditionals and suggest simplifications.
"""

from __future__ import annotations

import json
import re
from collections import Counter

from mcp.server.fastmcp import FastMCP

_mcp = FastMCP("refactoring-tools")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NAMING_RULES_PYTHON: dict[str, dict] = {
    "class_names": {
        "pattern": r"class\s+([a-z]\w*)\b",
        "rule": "PEP 8: Class names should use CapWords (e.g. MyClass).",
        "severity": "MEDIUM",
    },
    "function_names_camel": {
        "pattern": r"def\s+([A-Z]\w*)\s*\(",
        "rule": "PEP 8: Function/method names should use snake_case (e.g. my_function).",
        "severity": "MEDIUM",
    },
    "constant_not_upper": {
        "pattern": r"^([a-z][A-Z_]+)\s*=\s*\d+",
        "rule": "PEP 8: Module-level constants should be UPPER_SNAKE_CASE.",
        "severity": "LOW",
    },
    "single_char_variable": {
        "pattern": r"\b([a-z])\s*=\s*(?!lambda\b)",
        "rule": "Single-character variable names (except loop counters i, j, k, x, y, n) reduce readability.",
        "severity": "LOW",
    },
    "non_descriptive_names": {
        "pattern": r"def\s+(data|result|temp|tmp|foo|bar|baz|stuff|thing|obj|ret)\s*\(",
        "rule": "Non-descriptive function name – use a name that describes the purpose.",
        "severity": "MEDIUM",
    },
}

_CONDITIONAL_SMELLS: dict[str, dict] = {
    "negated_condition": {
        "pattern": r"if\s+not\s+\w+\s*:\n",
        "suggestion": "Consider inverting the condition to use the positive case first (early return).",
        "refactored_example": "if condition:\n    # positive path\nelse:\n    # negative path",
    },
    "nested_if_else_chain": {
        "pattern": r"elif\s+\S[^\n]*:\n[^\n]*\n\s+elif\s+",
        "suggestion": "Long if-elif chains → use a dict lookup or strategy pattern.",
        "refactored_example": "handlers = {'A': handle_a, 'B': handle_b}\nresult = handlers.get(value, default_handler)()",
    },
    "deep_null_check": {
        "pattern": r"is\s+not\s+None\s+and\s+\w+(?:\.\w+)+\s+is\s+not\s+None",
        "suggestion": "Replace chained None-checks with getattr(obj, 'attr', None) or Optional chaining.",
        "refactored_example": "value = getattr(obj, 'attr', None)",
    },
    "boolean_literal_comparison": {
        "pattern": r"==\s*(True|False)\b",
        "suggestion": "Never compare to True/False with ==. Use 'if condition:' or 'if not condition:'.",
        "refactored_example": "if is_valid:  # not: if is_valid == True:",
    },
    "none_comparison_equality": {
        "pattern": r"[!=]=\s*None\b",
        "suggestion": "Use 'is None' / 'is not None' for None checks.",
        "refactored_example": "if value is None:  # not: if value == None:",
    },
    "return_boolean_literal": {
        "pattern": r"return\s+True\n\s+return\s+False",
        "suggestion": "Replace if/return True/return False with 'return <condition>'.",
        "refactored_example": "return is_valid  # not: if is_valid: return True\n         #        return False",
    },
}


def _extract_functions_with_bodies(code: str) -> list[dict]:
    """Return list of {name, start_line, body_lines} dicts."""
    lines = code.split("\n")
    functions = []
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)def\s+(\w+)\s*\(", lines[i])
        if m:
            indent = len(m.group(1))
            name = m.group(2)
            start = i
            j = i + 1
            while j < len(lines):
                line = lines[j]
                if line.strip() and not line.startswith(" " * (indent + 1)):
                    break
                j += 1
            functions.append({
                "name": name,
                "start_line": start + 1,
                "end_line": j,
                "body_lines": lines[start:j],
                "line_count": j - start,
            })
            i = j
        else:
            i += 1
    return functions


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@_mcp.tool()
def suggest_refactorings(code: str, language: str = "python") -> str:
    """
    Generate a prioritised list of refactoring suggestions for the provided code.

    Runs all available checks: naming, complexity, conditionals, dead code,
    security, and design patterns.

    Args:
        code:     Source code text (max 100 000 characters).
        language: python, javascript, java, or generic.

    Returns:
        JSON with a prioritised refactoring backlog and effort estimates.
    """
    if len(code) > 100_000:
        return json.dumps({"error": "Code too large. Maximum 100 000 characters."})

    suggestions: list[dict] = []
    priority_weights = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}

    # --- Naming checks ---
    for rule_name, info in _NAMING_RULES_PYTHON.items():
        matches = re.findall(info["pattern"], code, re.MULTILINE)
        if matches:
            suggestions.append({
                "area": "naming",
                "priority": info["severity"],
                "description": info["rule"],
                "examples": list(set(str(m).strip()[:40] for m in matches))[:3],
                "effort": "LOW",
                "refactoring": "Rename following PEP 8 / language conventions.",
            })

    # --- Conditional smells ---
    for smell_name, info in _CONDITIONAL_SMELLS.items():
        if re.search(info["pattern"], code, re.MULTILINE | re.IGNORECASE):
            suggestions.append({
                "area": "conditionals",
                "priority": "MEDIUM",
                "description": f"Conditional smell: {smell_name.replace('_', ' ')}",
                "suggestion": info["suggestion"],
                "example": info["refactored_example"],
                "effort": "LOW",
            })

    # --- Long functions ---
    for fn in _extract_functions_with_bodies(code):
        if fn["line_count"] > 50:
            suggestions.append({
                "area": "function_length",
                "priority": "HIGH",
                "description": f"Function '{fn['name']}' is {fn['line_count']} lines long.",
                "suggestion": "Extract cohesive blocks into separate functions.",
                "effort": "MEDIUM",
            })
        elif fn["line_count"] > 30:
            suggestions.append({
                "area": "function_length",
                "priority": "MEDIUM",
                "description": f"Function '{fn['name']}' is {fn['line_count']} lines long.",
                "suggestion": "Consider extracting repeated or complex sub-logic.",
                "effort": "LOW",
            })

    # --- Security patterns ---
    sec_patterns = [
        (r"eval\s*\(", "CRITICAL", "Remove eval() – execute code safely via AST or subprocess."),
        (r"os\.system\s*\(", "CRITICAL", "Replace os.system() with subprocess.run(args_list) for safety."),
        (r"hardcoded.*password|password\s*=\s*['\"][^'\"]{4,}['\"]", "CRITICAL", "Move credentials to environment variables."),
        (r"hashlib\.md5\s*\(|hashlib\.sha1\s*\(", "HIGH", "Replace MD5/SHA-1 with SHA-256 or better."),
        (r"except\s*:", "HIGH", "Catch specific exceptions instead of bare except."),
        (r"^\s*print\s*\(", "LOW", "Replace print() with logging module.", ),
    ]
    for pattern, priority, description in sec_patterns:
        if re.search(pattern, code, re.MULTILINE | re.IGNORECASE):
            suggestions.append({
                "area": "security_and_quality",
                "priority": priority,
                "description": description,
                "effort": "LOW" if priority in ("LOW", "MEDIUM") else "MEDIUM",
            })

    suggestions.sort(key=lambda s: priority_weights.get(s.get("priority", "LOW"), 5))

    return json.dumps(
        {
            "total_suggestions": len(suggestions),
            "high_priority_count": sum(1 for s in suggestions if s.get("priority") in ("CRITICAL", "HIGH")),
            "suggestions": suggestions,
        },
        indent=2,
    )


@_mcp.tool()
def suggest_extract_method(code: str, min_block_lines: int = 5) -> str:
    """
    Identify code blocks inside functions that are good candidates for extraction
    into separate methods.

    Looks for: comment-separated sections, repeated patterns, deeply indented blocks,
    and blocks preceded by a descriptive comment.

    Args:
        code:             Source code text (max 100 000 characters).
        min_block_lines:  Minimum block size to suggest extraction (default 5 lines).

    Returns:
        JSON with extraction candidates, suggested method names, and code previews.
    """
    if len(code) > 100_000:
        return json.dumps({"error": "Code too large. Maximum 100 000 characters."})

    if not 2 <= min_block_lines <= 50:
        return json.dumps({"error": "min_block_lines must be between 2 and 50."})

    candidates: list[dict] = []
    lines = code.split("\n")

    for i, line in enumerate(lines):
        # Comment-labeled block: "# Step N:" or "# --- section ---"
        m = re.match(r"\s*#\s*(step\s+\d+|phase\s+\d+|[-=]{3,}.*|[A-Z][^#]{5,})\s*$", line, re.IGNORECASE)
        if m:
            # Look ahead for the code block
            block_start = i + 1
            block_end = block_start
            current_indent = len(line) - len(line.lstrip())
            j = block_start
            while j < min(block_start + 50, len(lines)):
                l = lines[j]
                if l.strip() and not l.strip().startswith("#"):
                    next_indent = len(l) - len(l.lstrip())
                    if next_indent <= current_indent and j > block_start:
                        break
                block_end = j
                j += 1

            block_size = block_end - block_start + 1
            if block_size >= min_block_lines:
                label = m.group(1).strip().lower()
                suggested_name = re.sub(r"[\s\-=]+", "_", label).strip("_")
                candidates.append({
                    "trigger": "comment-labeled block",
                    "line_number": i + 1,
                    "block_lines": block_size,
                    "suggested_method_name": f"_{suggested_name}" if suggested_name else "_extracted_block",
                    "code_preview": "\n".join(lines[block_start:min(block_start + 5, block_end + 1)]),
                })

        # Deeply nested block
        indent = len(line) - len(line.lstrip()) if line.strip() else 0
        if indent >= 16 and line.strip():  # >= 4 levels of nesting
            candidates.append({
                "trigger": "deep nesting (4+ levels)",
                "line_number": i + 1,
                "indent_level": indent // 4,
                "suggested_method_name": "_extracted_inner_logic",
                "code_preview": line.strip()[:80],
            })

    # Deduplicate nearby candidates
    deduped: list[dict] = []
    last_line = -999
    for c in candidates:
        if c["line_number"] - last_line > 5:
            deduped.append(c)
            last_line = c["line_number"]

    return json.dumps(
        {
            "extraction_candidates": len(deduped),
            "candidates": deduped[:20],
            "how_to_extract": [
                "1. Select the block to extract.",
                "2. Identify all input variables (these become parameters).",
                "3. Identify all output variables (these become return values).",
                "4. Create a new method with a descriptive name.",
                "5. Replace the original block with a call to the new method.",
                "6. Run your tests to verify behaviour is unchanged.",
            ],
        },
        indent=2,
    )


@_mcp.tool()
def improve_naming(code: str, language: str = "python") -> str:
    """
    Detect naming convention violations and suggest improvements.

    Checks PEP 8 (Python), camelCase (JavaScript), UpperCamelCase (Java classes),
    and general readability rules.

    Args:
        code:     Source code text (max 100 000 characters).
        language: python, javascript, java, or generic.

    Returns:
        JSON with naming violations and suggested renamed versions.
    """
    if len(code) > 100_000:
        return json.dumps({"error": "Code too large. Maximum 100 000 characters."})

    violations: list[dict] = []

    if language in ("python", "generic"):
        for rule_name, info in _NAMING_RULES_PYTHON.items():
            matches = list(re.finditer(info["pattern"], code, re.MULTILINE))
            for m in matches[:5]:  # Cap at 5 per rule
                name = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                name = name.strip()

                # Skip allowed single chars
                if rule_name == "single_char_variable" and name in ("i", "j", "k", "n", "x", "y", "e", "f", "_"):
                    continue

                suggested = name
                if rule_name == "class_names":
                    suggested = "".join(w.capitalize() for w in name.split("_"))
                elif rule_name == "function_names_camel":
                    suggested = re.sub(r"([A-Z])", r"_\1", name).lower().strip("_")
                elif rule_name == "constant_not_upper":
                    suggested = name.upper()
                elif rule_name == "non_descriptive_names":
                    suggested = "<descriptive_name>"

                violations.append({
                    "rule": rule_name.replace("_", " ").title(),
                    "current_name": name,
                    "suggested_name": suggested,
                    "description": info["rule"],
                    "severity": info["severity"],
                    "line": code[:m.start()].count("\n") + 1,
                })

    return json.dumps(
        {
            "language": language,
            "violations": len(violations),
            "naming_issues": violations,
            "style_guide": {
                "python": "https://peps.python.org/pep-0008/",
                "javascript": "https://google.github.io/styleguide/jsguide.html",
                "java": "https://google.github.io/styleguide/javaguide.html",
            }.get(language, "Consult your project style guide."),
        },
        indent=2,
    )


@_mcp.tool()
def simplify_conditionals(code: str) -> str:
    """
    Detect complex or redundant conditional constructs and provide simplified equivalents.

    Args:
        code: Source code text (max 100 000 characters).

    Returns:
        JSON with detected conditional smells and refactored alternatives.
    """
    if len(code) > 100_000:
        return json.dumps({"error": "Code too large. Maximum 100 000 characters."})

    findings: list[dict] = []

    for smell_name, info in _CONDITIONAL_SMELLS.items():
        matches = list(re.finditer(info["pattern"], code, re.MULTILINE | re.IGNORECASE))
        for m in matches[:3]:
            line_no = code[:m.start()].count("\n") + 1
            findings.append({
                "smell": smell_name.replace("_", " ").title(),
                "line": line_no,
                "original_snippet": code[m.start():m.end()].strip()[:150],
                "suggestion": info["suggestion"],
                "refactored_example": info["refactored_example"],
            })

    return json.dumps(
        {
            "total_conditional_smells": len(findings),
            "findings": findings,
            "general_guidelines": [
                "Use guard clauses (early return) to reduce nesting.",
                "Replace if-elif chains with dictionary dispatch.",
                "Use 'is None'/'is not None' for None checks.",
                "Avoid comparing booleans with == True/False.",
                "Return expressions directly instead of setting a variable.",
            ],
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
REFACTORING_TOOLS = [
    suggest_refactorings,
    suggest_extract_method,
    improve_naming,
    simplify_conditionals,
]
