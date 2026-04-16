# Tese de Mestrado – MCP + LLM Security & Tooling

Master's thesis research project exploring **Model Context Protocol (MCP)** security vulnerabilities and building practical tool suites for cybersecurity, LLM penetration testing, and code refactoring.

## Overview

This repository contains:

1. **Security attack demonstrations** – five MCP-based scenarios showing real LLM vulnerabilities
2. **Cybersecurity tools** – a comprehensive MCP server for security analysis
3. **LLM pen testing tools** – tools for red-teaming LLM applications
4. **Code refactoring tools** – static analysis and automated refactoring suggestions
5. **Testing framework** – GUI + CLI for side-by-side LLM security comparison

## Quick Start

```bash
# Install dependencies
cd mcp
pip install -r requirements.txt

# Launch the GUI test framework
**python interface.py**

# Or run any standalone demo (no LLM required)
python demos/06_cybersecurity_tools/demo.py
python demos/07_llm_pentest/demo.py
python demos/08_code_refactoring/demo.py
```

## Repository Structure

```text
.
├── README.md                    # Main project overview (this file)
├── LICENSE                      # Repository license
└── mcp/                         # Main application, demos, servers, UI, and assets
    ├── README.md                # MCP-specific usage and module documentation
    ├── requirements.txt         # Python dependencies
    ├── interface.py             # GUI entry point
    ├── attack_runner.py         # Attack test definitions and execution helpers
    ├── demos/                   # All MCP demos and tool-suite modules
    │   ├── 01_basic_mcp/        # Introductory MCP server + sample client
    │   ├── 02_prompt_injection/ # Direct and indirect prompt injection demos
    │   ├── 03_tool_misuse/      # Tool misuse and confused deputy scenarios
    │   ├── 04_memory_attacks/   # Persistent memory poisoning demonstrations
    │   ├── 05_supply_chain/     # Legitimate vs malicious MCP server scenarios
    │   ├── 06_cybersecurity_tools/ # Cybersecurity analysis tool suite
    │   ├── 07_llm_pentest/      # LLM red-teaming and pentest tool suite
    │   └── 08_code_refactoring/ # Static analysis and refactoring tools
    ├── ui/                      # Tkinter desktop interface
    ├── data/                    # Runtime data such as saved configs and test exports
    ├── assets/                  # Application icons and packaged UI assets
    ├── media/                   # Demo media used by the interface and thesis material
    ├── build_tools/             # Scripts and spec files for executable packaging
    ├── utils/                   # Helper scripts for intro video generation
    ├── build/                   # Generated build output
    ├── dist/                    # Packaged distributables
    └── .venv/                   # Local virtual environment (developer-specific)
```

### What each main folder contains

| Path | Purpose |
| --- | --- |
| `mcp/demos/01_basic_mcp` | Minimal MCP example used to introduce the protocol, with a simple server, client, and sample data. |
| `mcp/demos/02_prompt_injection` | Demonstrations of direct and indirect prompt injection attacks against tool-using LLM workflows. |
| `mcp/demos/03_tool_misuse` | Scenarios focused on confused deputy problems, unsafe tool execution, and workspace misuse. |
| `mcp/demos/04_memory_attacks` | Examples of memory poisoning and cross-session contamination in agent-style systems. |
| `mcp/demos/05_supply_chain` | Supply-chain attack demonstrations comparing trusted and malicious MCP servers. |
| `mcp/demos/06_cybersecurity_tools` | Security-oriented MCP server and demo scripts for network checks, vulnerability analysis, cryptography helpers, and log analysis. |
| `mcp/demos/07_llm_pentest` | LLM security testing tools for prompt fuzzing, adversarial testing, safety evaluation, model behaviour checks, and MCP exploit analysis. |
| `mcp/demos/08_code_refactoring` | Code quality and refactoring tools covering static analysis, complexity, design patterns, anti-patterns, and refactoring suggestions. |
| `mcp/ui` | Desktop GUI built with Tkinter. It contains the main app controller, page components, and supporting services. |
| `mcp/ui/pages` | Individual interface tabs such as configuration, test execution, results, MCP server inspection, and analyzer views. |
| `mcp/ui/services` | Backend helpers used by the GUI, including JSON persistence, Excel export, environment loading, MCP analysis, and test orchestration. |
| `mcp/data` | Persistent runtime data, including saved model configurations, stored test definitions, and exported `.xlsx` results. |
| `mcp/assets` | Static assets packaged with the application, such as icons. |
| `mcp/media` | Images, text snippets, and videos used by demos, the GUI, or thesis presentation material. |
| `mcp/utils` | Utility scripts for generating the intro animation and building macOS distributables. |
| `mcp/build` | Intermediate files created during packaging/build steps. |
| `mcp/dist` | Final packaged application artifacts, including the macOS app bundle. |
| `mcp/.venv` | Local Python virtual environment; useful for development but usually not part of the documented project logic. |

### Tool module breakdown

| Module | Internal structure |
| --- | --- |
| `mcp/demos/06_cybersecurity_tools/tools` | `network_tools.py`, `vulnerability_tools.py`, `crypto_tools.py`, `log_analysis_tools.py` |
| `mcp/demos/07_llm_pentest/tools` | `prompt_fuzzer.py`, `safety_evaluator.py`, `adversarial_tools.py`, `model_behavior_tools.py`, `mcp_exploit_tools.py` |
| `mcp/demos/08_code_refactoring/tools` | `static_analysis_tools.py`, `complexity_tools.py`, `pattern_detection_tools.py`, `refactoring_tools.py` |

## Key Features

### Security Scenarios (Modules 01–05)
- Prompt injection (direct + indirect)
- Tool misuse (confused deputy, privilege escalation)
- Memory poisoning and persistent instruction injection
- Supply chain attacks (malicious server substitution)
- Jailbreak resistance testing

### Cybersecurity Tools (Module 06)
- Real DNS resolution and SSL certificate checking
- HTTP security header grading (A–F)
- CVE lookup and dependency vulnerability audit
- CVSS v3 score interpretation with SLA guidance
- OWASP Top-10 pattern scanner
- Password strength analyser with entropy estimate
- Web access log parser with anomaly detection
- Brute-force and SQL injection detection in logs

### LLM Pen Testing Tools (Module 07)
- Adversarial prompt generation (7 injection techniques)
- Injection technique classifier
- PII detector (email, phone, SSN, API keys, Portuguese NIF)
- Harmful content classifier (7 categories)
- Attack surface analyser
- Multi-turn attack scenario simulator
- Model hallucination risk scorer
- Refusal consistency metrics (precision, recall, F1)

### Code Refactoring Tools (Module 08)
- Code quality score with grade (A–F)
- 10+ code smell detectors (including security smells)
- Cyclomatic complexity per function
- Design pattern detector (GoF + Python idioms)
- Anti-pattern detector (God Class, Lava Flow, etc.)
- SOLID principles analysis
- Copy-paste duplicate detection
- Naming convention checker with suggestions

## Testing Framework

The GUI (`python mcp/interface.py`) supports:
- Multiple LLM endpoint configurations for side-by-side comparison
- 20+ automated attack test cases across 9 categories
- Demo script runner (no LLM required)
- Results export to Excel (`.xlsx`)

## Tech Stack

- **Python 3.10+**
- **MCP (Model Context Protocol)** – tool server framework
- **LangChain + LangGraph** – LLM agent framework
- **Tkinter** – GUI
- **OpenAI-compatible API** – works with LM Studio, Ollama, and cloud APIs

## Disclaimer

All attack demonstrations and security testing tools are for **educational and research purposes only**. Only use scanning, pen testing, and analysis tools against systems you own or have explicit written authorisation to test.
