"""
server.py  –  08_code_refactoring
------------------------------------
MCP server exposing code refactoring and quality tools organised into four groups.

Tool groups (defined in tools/):
  static_analysis_tools  – Code quality, smells, dead code, security patterns
  complexity_tools        – Cyclomatic complexity, code metrics, nesting depth, coupling
  pattern_detection_tools – Design patterns, anti-patterns, SOLID, duplicate logic
  refactoring_tools       – Refactoring suggestions, extract method, naming, conditionals

Run with:
    python server.py
"""

from mcp.server.fastmcp import FastMCP

from tools.static_analysis_tools import (
    analyze_code_quality,
    detect_code_smells,
    find_dead_code,
    check_security_patterns,
)
from tools.complexity_tools import (
    calculate_cyclomatic_complexity,
    measure_code_metrics,
    analyze_nesting_depth,
    evaluate_coupling,
)
from tools.pattern_detection_tools import (
    detect_design_patterns,
    find_antipatterns,
    analyze_solid_principles,
    detect_duplicate_logic,
)
from tools.refactoring_tools import (
    suggest_refactorings,
    suggest_extract_method,
    improve_naming,
    simplify_conditionals,
)

# ---------------------------------------------------------------------------
# Main MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "Code Refactoring Tools",
    instructions=(
        "This server provides code analysis and refactoring tools organised into four groups:\n\n"
        "**Static Analysis** – analyze_code_quality, detect_code_smells, "
        "find_dead_code, check_security_patterns\n\n"
        "**Complexity** – calculate_cyclomatic_complexity, measure_code_metrics, "
        "analyze_nesting_depth, evaluate_coupling\n\n"
        "**Pattern Detection** – detect_design_patterns, find_antipatterns, "
        "analyze_solid_principles, detect_duplicate_logic\n\n"
        "**Refactoring** – suggest_refactorings, suggest_extract_method, "
        "improve_naming, simplify_conditionals"
    ),
)

# Register all tools
for _tool_fn in [
    # Static analysis
    analyze_code_quality, detect_code_smells, find_dead_code, check_security_patterns,
    # Complexity
    calculate_cyclomatic_complexity, measure_code_metrics, analyze_nesting_depth, evaluate_coupling,
    # Pattern detection
    detect_design_patterns, find_antipatterns, analyze_solid_principles, detect_duplicate_logic,
    # Refactoring
    suggest_refactorings, suggest_extract_method, improve_naming, simplify_conditionals,
]:
    mcp.add_tool(_tool_fn)

if __name__ == "__main__":
    mcp.run()
