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
python interface.py

# Or run any standalone demo (no LLM required)
python 06_cybersecurity_tools/demo.py
python 07_llm_pentest/demo.py
python 08_code_refactoring/demo.py
```

## Repository Structure

```
mcp/
├── 01_basic_mcp/           # Basic MCP server with 5 security-aware tools
├── 02_prompt_injection/    # Direct and indirect prompt injection demos
├── 03_tool_misuse/         # Confused deputy, path traversal, SQL injection
├── 04_memory_attacks/      # Memory poisoning and cross-session contamination
├── 05_supply_chain/        # Malicious server substitution with backdoors
├── 06_cybersecurity_tools/ # 20 cybersecurity analysis tools (4 modules)
│   └── tools/
│       ├── network_tools.py         # DNS, port scan, headers, SSL, WHOIS
│       ├── vulnerability_tools.py   # CVE, CVSS, OWASP Top-10, dep audit
│       ├── crypto_tools.py          # Hash, password, tokens, encoding
│       └── log_analysis_tools.py    # Access log, brute force, SQLi
├── 07_llm_pentest/         # 16 LLM pen testing tools (4 modules)
│   └── tools/
│       ├── prompt_fuzzer.py         # Fuzz templates, injection classifier
│       ├── safety_evaluator.py      # PII, harmful content, output alignment
│       ├── adversarial_tools.py     # Attack surface, multi-turn simulation
│       └── model_behavior_tools.py  # Bias, hallucination, refusal metrics
├── 08_code_refactoring/    # 16 code quality tools (4 modules)
│   └── tools/
│       ├── static_analysis_tools.py # Quality score, smells, security
│       ├── complexity_tools.py      # Cyclomatic, metrics, nesting
│       ├── pattern_detection_tools.py # GoF, anti-patterns, SOLID
│       └── refactoring_tools.py     # Suggestions, naming, conditionals
├── ui/                     # Tkinter GUI (config, run, results tabs)
├── attack_runner.py        # 20+ LLM attack test cases + demo runner
├── interface.py            # GUI entry point
└── requirements.txt        # Python dependencies
```

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
