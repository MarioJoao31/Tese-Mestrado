"""
Cybersecurity MCP Tools Package
---------------------------------
Organised into four modules:
  - network_tools      : DNS, port scanning, headers, SSL
  - vulnerability_tools: CVE lookup, dependency audit, CVSS scoring
  - crypto_tools       : Hash analysis, password checks, token generation
  - log_analysis_tools : Access log parsing, brute-force detection
"""

from .network_tools import NETWORK_TOOLS
from .vulnerability_tools import VULNERABILITY_TOOLS
from .crypto_tools import CRYPTO_TOOLS
from .log_analysis_tools import LOG_ANALYSIS_TOOLS

ALL_TOOLS = NETWORK_TOOLS + VULNERABILITY_TOOLS + CRYPTO_TOOLS + LOG_ANALYSIS_TOOLS

__all__ = [
    "NETWORK_TOOLS",
    "VULNERABILITY_TOOLS",
    "CRYPTO_TOOLS",
    "LOG_ANALYSIS_TOOLS",
    "ALL_TOOLS",
]
