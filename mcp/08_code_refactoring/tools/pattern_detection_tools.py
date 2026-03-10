"""
pattern_detection_tools.py
---------------------------
MCP tools for detecting design patterns and anti-patterns in source code.

Tools:
  - detect_design_patterns  : Identify Gang of Four (GoF) design patterns.
  - find_antipatterns       : Detect known anti-patterns and bad practices.
  - analyze_solid_principles: Check adherence to SOLID principles.
  - detect_duplicate_logic  : Find repeated logic blocks (copy-paste detection).
"""

from __future__ import annotations

import json
import re
from collections import Counter

from mcp.server.fastmcp import FastMCP

_mcp = FastMCP("pattern-detection-tools")

# ---------------------------------------------------------------------------
# Pattern libraries
# ---------------------------------------------------------------------------

_DESIGN_PATTERN_INDICATORS: dict[str, dict] = {
    "singleton": {
        "patterns": [
            r"_instance\s*=\s*None",
            r"if\s+cls\._instance\s+is\s+None",
            r"__new__\s*\(cls\)",
        ],
        "description": "Singleton – ensures only one instance of a class exists.",
        "category": "creational",
    },
    "factory_method": {
        "patterns": [
            r"def\s+create_\w+\s*\(",
            r"def\s+make_\w+\s*\(",
            r"@classmethod.*def\s+\w+\s*\(",
        ],
        "description": "Factory Method – delegates object creation to subclasses.",
        "category": "creational",
    },
    "observer": {
        "patterns": [
            r"def\s+(subscribe|attach|register)\s*\(",
            r"def\s+(notify|publish|emit)\s*\(",
            r"self\._observers\b",
            r"self\._listeners\b",
            r"self\._subscribers\b",
        ],
        "description": "Observer – notifies dependents of state changes.",
        "category": "behavioral",
    },
    "strategy": {
        "patterns": [
            r"def\s+execute\s*\(self",
            r"self\._strategy\b",
            r"self\.strategy\b",
            r"def\s+set_strategy\s*\(",
        ],
        "description": "Strategy – encapsulates interchangeable algorithms.",
        "category": "behavioral",
    },
    "decorator": {
        "patterns": [
            r"@\w+",
            r"def\s+wrapper\s*\(",
            r"functools\.wraps",
            r"def\s+__call__\s*\(self",
        ],
        "description": "Decorator – adds behaviour to objects/functions dynamically.",
        "category": "structural",
    },
    "command": {
        "patterns": [
            r"def\s+execute\s*\(self",
            r"def\s+undo\s*\(self",
            r"self\._history\b",
        ],
        "description": "Command – encapsulates a request as an object.",
        "category": "behavioral",
    },
    "context_manager": {
        "patterns": [
            r"def\s+__enter__\s*\(self",
            r"def\s+__exit__\s*\(self",
            r"@contextmanager",
        ],
        "description": "Context Manager – manages resource lifecycle with 'with' statement.",
        "category": "structural",
    },
    "iterator": {
        "patterns": [
            r"def\s+__iter__\s*\(self",
            r"def\s+__next__\s*\(self",
        ],
        "description": "Iterator – provides sequential access to elements.",
        "category": "behavioral",
    },
}

_ANTI_PATTERN_INDICATORS: dict[str, dict] = {
    "god_class": {
        "description": "A class that knows or does too much",
        "severity": "HIGH",
        "indicators": "class with > 10 methods or > 300 lines",
    },
    "feature_envy": {
        "patterns": [
            r"self\.\w+\.\w+\.\w+\.\w+",  # Deep chaining: self.a.b.c.d
        ],
        "description": "Method uses another class's data more than its own",
        "severity": "MEDIUM",
    },
    "primitive_obsession": {
        "patterns": [
            r"def\s+\w+\s*\([^)]*\bstr\b[^)]*\bstr\b[^)]*\bstr\b",  # Too many strings
            r"def\s+\w+\s*\([^)]*\bint\b[^)]*\bint\b[^)]*\bint\b",  # Too many ints
        ],
        "description": "Using primitives instead of small objects for domain concepts",
        "severity": "LOW",
    },
    "global_state": {
        "patterns": [
            r"^global\s+\w+",
            r"^[A-Z_]{3,}\s*=",  # Module-level ALL_CAPS globals
        ],
        "description": "Excessive use of global variables couples code and hinders testing",
        "severity": "MEDIUM",
    },
    "anemic_domain_model": {
        "patterns": [
            r"class\s+\w+Model\b",
            r"class\s+\w+DTO\b",
            r"class\s+\w+Data\b",
        ],
        "description": "Domain objects with only data and no behaviour",
        "severity": "LOW",
    },
    "yo_yo_problem": {
        "patterns": [
            r"super\(\)\.\w+",
        ],
        "description": "Deep inheritance hierarchies requiring navigation up and down",
        "severity": "MEDIUM",
    },
    "lava_flow": {
        "patterns": [
            r"#\s*(TODO|FIXME|HACK|XXX|TEMP|REMOVEME)\b",
        ],
        "description": "Dead/legacy code kept out of fear to remove it",
        "severity": "LOW",
    },
}


def _count_class_methods(code: str, class_name: str) -> int:
    """Count methods in a class."""
    class_pattern = re.compile(rf"class\s+{re.escape(class_name)}\b.*?(?=\nclass\s|\Z)", re.DOTALL)
    m = class_pattern.search(code)
    if not m:
        return 0
    body = m.group(0)
    return len(re.findall(r"\n\s+def\s+\w+", body))


def _count_class_lines(code: str, class_name: str) -> int:
    """Count lines in a class body."""
    class_pattern = re.compile(rf"class\s+{re.escape(class_name)}\b.*?(?=\nclass\s|\Z)", re.DOTALL)
    m = class_pattern.search(code)
    if not m:
        return 0
    return m.group(0).count("\n")


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@_mcp.tool()
def detect_design_patterns(code: str) -> str:
    """
    Identify GoF (Gang of Four) and common Python design patterns in source code.

    Args:
        code: Source code text (max 100 000 characters).

    Returns:
        JSON with detected patterns, categories, and implementation notes.
    """
    if len(code) > 100_000:
        return json.dumps({"error": "Code too large. Maximum 100 000 characters."})

    detected: list[dict] = []

    for pattern_name, info in _DESIGN_PATTERN_INDICATORS.items():
        patterns = info.get("patterns", [])
        evidence: list[str] = []
        for p in patterns:
            if re.search(p, code, re.IGNORECASE | re.MULTILINE):
                evidence.append(p)

        if evidence:
            detected.append({
                "pattern": pattern_name.replace("_", " ").title(),
                "category": info["category"],
                "description": info["description"],
                "confidence": "HIGH" if len(evidence) >= 2 else "MEDIUM",
                "evidence_count": len(evidence),
            })

    categories = Counter(d["category"] for d in detected)

    return json.dumps(
        {
            "patterns_detected": len(detected),
            "by_category": dict(categories),
            "patterns": detected,
            "note": (
                "Pattern detection is heuristic; manual confirmation is recommended. "
                "Absence of a pattern does not mean it is not present."
            ),
        },
        indent=2,
    )


@_mcp.tool()
def find_antipatterns(code: str) -> str:
    """
    Detect common anti-patterns and bad programming practices.

    Args:
        code: Source code text (max 100 000 characters).

    Returns:
        JSON with detected anti-patterns, severity, and refactoring advice.
    """
    if len(code) > 100_000:
        return json.dumps({"error": "Code too large. Maximum 100 000 characters."})

    found: list[dict] = []

    for ap_name, info in _ANTI_PATTERN_INDICATORS.items():
        patterns = info.get("patterns", [])
        matched = False
        occurrences = 0

        for p in patterns:
            hits = re.findall(p, code, re.MULTILINE | re.IGNORECASE)
            if hits:
                matched = True
                occurrences += len(hits)

        # God class: check by class size
        if ap_name == "god_class":
            class_names = re.findall(r"class\s+(\w+)\b", code)
            for cn in class_names:
                methods = _count_class_methods(code, cn)
                lines = _count_class_lines(code, cn)
                if methods > 10 or lines > 300:
                    found.append({
                        "antipattern": "God Class",
                        "severity": "HIGH",
                        "description": f"Class '{cn}' has {methods} methods and ~{lines} lines.",
                        "refactoring": "Apply Single Responsibility Principle; decompose into smaller focused classes.",
                    })
            continue

        if matched:
            refactoring = {
                "feature_envy": "Move methods closer to the data they use; apply Tell-Don't-Ask principle.",
                "primitive_obsession": "Introduce Value Objects or small domain classes.",
                "global_state": "Pass state as parameters or inject as dependencies.",
                "anemic_domain_model": "Add behaviour methods to domain objects.",
                "yo_yo_problem": "Favour composition over deep inheritance.",
                "lava_flow": "Remove dead code; use version control for history.",
            }.get(ap_name, "Review and refactor.")

            found.append({
                "antipattern": ap_name.replace("_", " ").title(),
                "severity": info["severity"],
                "description": info["description"],
                "occurrences": occurrences,
                "refactoring": refactoring,
            })

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    found.sort(key=lambda x: severity_order.get(x.get("severity", "LOW"), 3))

    return json.dumps(
        {
            "total_antipatterns": len(found),
            "antipatterns": found,
        },
        indent=2,
    )


@_mcp.tool()
def analyze_solid_principles(code: str) -> str:
    """
    Analyze how well the code adheres to SOLID design principles.

    Args:
        code: Source code text (max 100 000 characters).

    Returns:
        JSON with a per-principle assessment and specific violation examples.
    """
    if len(code) > 100_000:
        return json.dumps({"error": "Code too large. Maximum 100 000 characters."})

    assessments: list[dict] = []

    # S – Single Responsibility
    class_names = re.findall(r"class\s+(\w+)\b", code)
    srp_violations: list[str] = []
    for cn in class_names:
        methods = _count_class_methods(code, cn)
        lines = _count_class_lines(code, cn)
        if methods > 10 or lines > 200:
            srp_violations.append(f"'{cn}' ({methods} methods, ~{lines} lines)")
    assessments.append({
        "principle": "S – Single Responsibility",
        "adherence": "POOR" if srp_violations else "GOOD",
        "violations": srp_violations[:5],
        "suggestion": "Decompose large classes into smaller, focused ones." if srp_violations else "Classes appear reasonably focused.",
    })

    # O – Open/Closed
    ocp_issues: list[str] = []
    if re.search(r"\bisinstance\s*\(.*\)", code) and not re.search(r"@\w+", code):
        ocp_issues.append("Heavy use of isinstance() without polymorphism may indicate closed-to-extension design.")
    assessments.append({
        "principle": "O – Open/Closed",
        "adherence": "REVIEW" if ocp_issues else "LIKELY GOOD",
        "violations": ocp_issues,
        "suggestion": "Prefer polymorphism and abstract base classes over type-checking conditionals.",
    })

    # L – Liskov Substitution
    # Check for methods that raise NotImplementedError (common in base classes)
    abstract_raises = re.findall(r"raise\s+NotImplementedError", code)
    lsp_note = (
        f"Found {len(abstract_raises)} raise NotImplementedError – ensure all subclasses properly implement these."
        if abstract_raises else None
    )
    assessments.append({
        "principle": "L – Liskov Substitution",
        "adherence": "REVIEW" if abstract_raises else "LIKELY GOOD",
        "violations": [lsp_note] if lsp_note else [],
        "suggestion": "Use abc.ABC and @abstractmethod instead of raise NotImplementedError.",
    })

    # I – Interface Segregation
    large_abstract = []
    abc_classes = re.findall(r"class\s+(\w+)\s*\(.*ABC.*\)", code)
    for cn in abc_classes:
        methods = _count_class_methods(code, cn)
        if methods > 5:
            large_abstract.append(f"Abstract class '{cn}' has {methods} abstract methods.")
    assessments.append({
        "principle": "I – Interface Segregation",
        "adherence": "REVIEW" if large_abstract else "LIKELY GOOD",
        "violations": large_abstract,
        "suggestion": "Split large interfaces/abstract classes into smaller, client-specific ones.",
    })

    # D – Dependency Inversion
    dip_issues: list[str] = []
    if re.search(r"\bimport\s+\w+\b", code):
        concrete_instantiations = re.findall(r"=\s+\w+\(\)", code)
        if len(concrete_instantiations) > 5:
            dip_issues.append(f"{len(concrete_instantiations)} direct class instantiations – consider dependency injection.")
    assessments.append({
        "principle": "D – Dependency Inversion",
        "adherence": "REVIEW" if dip_issues else "LIKELY GOOD",
        "violations": dip_issues,
        "suggestion": "Depend on abstractions; inject concrete implementations from the outside.",
    })

    overall = "GOOD" if all(a["adherence"] in ("GOOD", "LIKELY GOOD") for a in assessments) else "NEEDS IMPROVEMENT"

    return json.dumps(
        {
            "overall_solid_adherence": overall,
            "principles": assessments,
        },
        indent=2,
    )


@_mcp.tool()
def detect_duplicate_logic(code: str, min_line_length: int = 6, min_occurrences: int = 2) -> str:
    """
    Find repeated code blocks that may indicate copy-paste duplication.

    Args:
        code:              Source code text (max 100 000 characters).
        min_line_length:   Minimum significant line length to track (default 6 chars).
        min_occurrences:   Minimum times a line must repeat to be reported (default 2).

    Returns:
        JSON with duplicated lines, their locations, and refactoring advice.
    """
    if len(code) > 100_000:
        return json.dumps({"error": "Code too large. Maximum 100 000 characters."})

    if not 2 <= min_occurrences <= 20:
        return json.dumps({"error": "min_occurrences must be between 2 and 20."})

    lines = code.split("\n")
    # Normalise lines: strip whitespace, skip blanks/comments/imports
    normalised: list[tuple[int, str]] = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if (
            len(stripped) >= min_line_length
            and not stripped.startswith(("#", "//", "import", "from", "def ", "class ", "@"))
            and stripped not in ("pass", "return", "break", "continue", "...")
        ):
            normalised.append((i, stripped))

    # Count occurrences
    line_counter = Counter(text for _, text in normalised)
    duplicates: list[dict] = []

    for text, count in line_counter.most_common(20):
        if count < min_occurrences:
            break
        locations = [ln for ln, t in normalised if t == text]
        duplicates.append({
            "code": text[:120],
            "occurrences": count,
            "lines": locations,
        })

    return json.dumps(
        {
            "duplicates_found": len(duplicates),
            "duplicates": duplicates,
            "recommendations": [
                "Extract duplicated logic into shared functions or utility modules.",
                "Apply DRY (Don't Repeat Yourself) principle.",
                "Use inheritance or composition to share behaviour across classes.",
            ] if duplicates else ["No significant code duplication detected."],
            "tool_recommendation": "Run 'pylint --disable=all --enable=duplicate-code' for deeper analysis.",
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
PATTERN_DETECTION_TOOLS = [
    detect_design_patterns,
    find_antipatterns,
    analyze_solid_principles,
    detect_duplicate_logic,
]
