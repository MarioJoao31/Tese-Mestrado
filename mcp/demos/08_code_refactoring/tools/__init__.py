"""
Code Refactoring MCP Tools Package
-------------------------------------
Organised into four modules:
  - static_analysis_tools  : Code quality, smells, security patterns
  - complexity_tools        : Cyclomatic complexity, code metrics
  - pattern_detection_tools : Design patterns, anti-patterns
  - refactoring_tools       : Refactoring suggestions, naming, simplification
"""

from .static_analysis_tools import STATIC_ANALYSIS_TOOLS
from .complexity_tools import COMPLEXITY_TOOLS
from .pattern_detection_tools import PATTERN_DETECTION_TOOLS
from .refactoring_tools import REFACTORING_TOOLS

ALL_TOOLS = (
    STATIC_ANALYSIS_TOOLS
    + COMPLEXITY_TOOLS
    + PATTERN_DETECTION_TOOLS
    + REFACTORING_TOOLS
)

__all__ = [
    "STATIC_ANALYSIS_TOOLS",
    "COMPLEXITY_TOOLS",
    "PATTERN_DETECTION_TOOLS",
    "REFACTORING_TOOLS",
    "ALL_TOOLS",
]
