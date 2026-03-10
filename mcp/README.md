# MCP + LLM Security Examples

This project demonstrates **Model Context Protocol (MCP)** usage with a local LLM (LM Studio or Ollama) and explores security vulnerabilities in tool-using LLM agents.

---

## Project Structure

```text
mcp/
|-- requirements.txt
|-- README.md
|-- attack_runner.py                # Backend: test definitions + execution helpers
|-- interface.py                    # Thin GUI entrypoint (launches ui.app)
|
|-- ui/
|   |-- app.py                      # Main Tk controller (wires pages + services)
|   |-- pages/
|   |   |-- config_page.py          # "Configuration" tab
|   |   |-- run_page.py             # "Run Tests" tab
|   |   `-- results_page.py         # "Results" tab
|   `-- services/
|       |-- env_loader.py           # Loads defaults from .env
|       |-- test_runner.py          # Async orchestration for LLM + demo tests
|       |-- json_db.py              # JSON persistence (configs + test records)
|       `-- excel_export.py         # Export results to .xlsx
|
|-- data/                           # Created automatically at runtime
|   |-- configs_db.json             # Persisted UI/model configs (auto-loaded)
|   `-- tests_db.json               # Persisted test run history (write-only on startup)
|
|-- 01_basic_mcp/                   # Basic MCP server + LangChain client
|-- 02_prompt_injection/            # Direct and indirect prompt injection
|-- 03_tool_misuse/                 # Tool misuse and confused deputy
|-- 04_memory_attacks/              # Persistent memory poisoning
|-- 05_supply_chain/                # Malicious server substitution
|-- 06_cybersecurity_tools/         # Network, vulnerability, crypto, log analysis tools
|   `-- tools/
|       |-- network_tools.py        # DNS, port scan, HTTP headers, SSL, WHOIS
|       |-- vulnerability_tools.py  # CVE, dependencies, CVSS, OWASP Top-10
|       |-- crypto_tools.py         # Hash analysis, password check, token generation
|       `-- log_analysis_tools.py   # Access log, brute force, SQLi detection
|-- 07_llm_pentest/                 # LLM penetration testing tools
|   `-- tools/
|       |-- prompt_fuzzer.py        # Adversarial prompts, injection classifier, system prompt audit
|       |-- safety_evaluator.py     # Safety scoring, PII detection, harm classification
|       |-- adversarial_tools.py    # Adversarial variants, attack surface, multi-turn attacks
|       |-- model_behavior_tools.py # Response profiling, bias, hallucination, refusal consistency
|       `-- mcp_exploit_tools.py    # MCP tool weak-point audit, exploit tests, risky output checks
`-- 08_code_refactoring/            # Code analysis and refactoring tools
    `-- tools/
        |-- static_analysis_tools.py   # Quality score, smells, dead code, security patterns
        |-- complexity_tools.py        # Cyclomatic complexity, metrics, nesting, coupling
        |-- pattern_detection_tools.py # Design patterns, anti-patterns, SOLID, duplication
        `-- refactoring_tools.py       # Refactoring suggestions, naming, conditionals
```

---

## Prerequisites

1. Python 3.10+
2. Local LLM endpoint (LM Studio or Ollama)
3. Install dependencies (includes Manim for startup intro animation):

```bash
cd mcp
pip install -r requirements.txt
```

---

## LLM Setup

### Option A: LM Studio (recommended)

1. Install [LM Studio](https://lmstudio.ai)
2. Load a model (example: `llama-3.1-8b-instruct`)
3. Start the local server at `http://localhost:1234`

### Option B: Ollama

```bash
ollama pull llama3.1:8b
ollama serve
```

Default Ollama API endpoint is usually `http://localhost:11434`.

---

## Environment Variables (optional)

Create `mcp/.env`:

```env
# LM Studio defaults
LLM_BASE_URL=http://localhost:1234/v1
LLM_API_KEY=lm-studio
LLM_MODEL=llama-3.1-8b-instruct

# Ollama example
# LLM_BASE_URL=http://localhost:11434/v1
# LLM_API_KEY=ollama
# LLM_MODEL=llama3.1:8b
```

---

## How To Run

### 1. Launch the GUI (recommended)

From repository root:

```bash
python mcp/interface.py
```

Or inside `mcp/`:

```bash
python interface.py
```

The app now plays a Manim intro animation (`Mário Tese MCP Cyber`) before the Tkinter UI opens.
If you want to skip it, set `MCP_DISABLE_INTRO=1` before running.

### 2. Run backend tests from CLI

```bash
python mcp/attack_runner.py
```

### 3. Run standalone demo scenarios (no LLM required)

```bash
# Security attack demonstrations
python mcp/03_tool_misuse/demo.py
python mcp/04_memory_attacks/demo.py
python mcp/05_supply_chain/demo.py

# New tool modules
python mcp/06_cybersecurity_tools/demo.py
python mcp/07_llm_pentest/demo.py
python mcp/08_code_refactoring/demo.py
```

---

## Example Areas

### Security Scenarios (01–05)

| Folder                | Security Topic   | Description                                                           |
| --------------------- | ---------------- | --------------------------------------------------------------------- |
| `01_basic_mcp`        | Basics           | Intro MCP server + LangChain client with 5 security-aware tools       |
| `02_prompt_injection` | Prompt Injection | Direct and indirect prompt-injection demos                            |
| `03_tool_misuse`      | Tool Misuse      | Confused-deputy, path traversal, SQL injection, exfiltration patterns |
| `04_memory_attacks`   | Memory Attacks   | Persistent-memory poisoning and cross-session contamination           |
| `05_supply_chain`     | Supply Chain     | Legitimate vs malicious MCP server substitution with backdoors        |

### New Tool Modules (06–08)

| Folder                   | Category         | Tools                                                                             |
| ------------------------ | ---------------- | --------------------------------------------------------------------------------- |
| `06_cybersecurity_tools` | Cybersecurity    | 20 tools: network analysis, CVE/CVSS, cryptography, log analysis                  |
| `07_llm_pentest`         | LLM Pen Testing  | 19 tools: prompt fuzzing, safety evaluation, adversarial testing, model behaviour, MCP exploit analysis |
| `08_code_refactoring`    | Code Refactoring | 16 tools: static analysis, complexity, pattern detection, refactoring suggestions |

### LLM Attack Test Categories (attack_runner.py)

| Category                 | Tests | Description                                                |
| ------------------------ | ----- | ---------------------------------------------------------- |
| `01. Baseline`           | 2     | Normal queries that should succeed                         |
| `02. Direct Injection`   | 4     | Override, role-play, code-block, separator                 |
| `03. Indirect Injection` | 2     | Hidden document and invisible text                         |
| `04. Tool Misuse`        | 2     | Confused deputy, path traversal                            |
| `05. Memory Attack`      | 2     | Poisoned memory, cross-session contamination               |
| `06. Supply Chain`       | 1     | Malicious tool description                                 |
| `07. Cybersecurity`      | 3     | Social engineering, exploitation request, credential exfil |
| `08. LLM Pen Testing`    | 2     | Identity extraction, hypothetical framing                  |
| `09. Code Injection`     | 2     | Malicious code completion, backdoor via refactoring        |

---

## Module Details

### 06 · Cybersecurity Tools

Organised into four tool files:

- **`network_tools.py`** – `dns_lookup`, `port_scan`, `analyze_http_headers`, `check_ssl_certificate`, `whois_lookup`
- **`vulnerability_tools.py`** – `cve_lookup`, `check_dependency_vulnerabilities`, `assess_cvss_score`, `generate_security_report`, `check_owasp_top10`
- **`crypto_tools.py`** – `identify_hash_type`, `hash_text`, `analyze_password`, `generate_secure_token`, `check_encoding`
- **`log_analysis_tools.py`** – `parse_access_log`, `detect_brute_force`, `extract_ips_from_log`, `detect_sqli_in_log`, `summarize_log_statistics`

### 07 · LLM Penetration Testing

Organised into five tool files:

- **`prompt_fuzzer.py`** – `generate_fuzz_prompts`, `classify_injection_technique`, `build_indirect_injection`, `evaluate_system_prompt`
- **`safety_evaluator.py`** – `evaluate_prompt_safety`, `detect_pii`, `detect_harmful_content`, `check_output_alignment`
- **`adversarial_tools.py`** – `generate_adversarial_variants`, `analyze_attack_surface`, `test_prompt_boundaries`, `simulate_multi_turn_attack`
- **`model_behavior_tools.py`** – `profile_response_patterns`, `detect_response_bias`, `estimate_hallucination_risk`, `measure_refusal_consistency`
- **`mcp_exploit_tools.py`** – `audit_mcp_tool_design`, `generate_mcp_exploit_tests`, `evaluate_mcp_tool_output_risk`

### 08 · Code Refactoring

Organised into four tool files:

- **`static_analysis_tools.py`** – `analyze_code_quality`, `detect_code_smells`, `find_dead_code`, `check_security_patterns`
- **`complexity_tools.py`** – `calculate_cyclomatic_complexity`, `measure_code_metrics`, `analyze_nesting_depth`, `evaluate_coupling`
- **`pattern_detection_tools.py`** – `detect_design_patterns`, `find_antipatterns`, `analyze_solid_principles`, `detect_duplicate_logic`
- **`refactoring_tools.py`** – `suggest_refactorings`, `suggest_extract_method`, `improve_naming`, `simplify_conditionals`

---

## Notes

- The GUI supports multiple LLM endpoint configs for side-by-side comparison.
- Results can be exported from the GUI to Excel (`.xlsx`).
- Configs are auto-loaded from `mcp/data/configs_db.json` on each app start.
- Test runs are appended to `mcp/data/tests_db.json` after each run (not loaded on startup).
- New modules (06–08) use a `tools/` subdirectory to organise tools by function.
- All demo scripts run standalone without a live LLM or MCP server.

---

## Disclaimer

These examples are for **educational and research use only**. Do not apply attack techniques or security scanning tools to real systems without explicit authorisation.

## to run the video maker for the intro

to run manim exec to create the video 
```bash
manim -pqh utils/mario_video_intro.py MarioTeseMCP
```
