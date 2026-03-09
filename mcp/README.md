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
|-- 01_basic_mcp/
|-- 02_prompt_injection/
|-- 03_tool_misuse/
|-- 04_memory_attacks/
`-- 05_supply_chain/
```

---

## Prerequisites

1. Python 3.10+
2. Local LLM endpoint (LM Studio or Ollama)
3. Install dependencies:

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

### 2. Run backend tests from CLI

```bash
python mcp/attack_runner.py
```

### 3. Run demo scenarios directly

```bash
python mcp/03_tool_misuse/demo.py
python mcp/04_memory_attacks/demo.py
python mcp/05_supply_chain/demo.py
```

---

## Example Areas

| Folder | Security Topic | Description |
|---|---|---|
| `01_basic_mcp` | Basics | Intro MCP server + client |
| `02_prompt_injection` | Prompt Injection | Direct and indirect prompt-injection demos |
| `03_tool_misuse` | Tool Misuse | Confused-deputy and unsafe tool invocation patterns |
| `04_memory_attacks` | Memory | Persistent-memory poisoning scenarios |
| `05_supply_chain` | Supply Chain | Legitimate vs malicious MCP server substitution |

---

## Notes

- The GUI supports multiple LLM endpoint configs for side-by-side comparison.
- Results can be exported from the GUI to Excel (`.xlsx`).
- The refactor split page UI and business logic into dedicated files under `ui/`.
- Configs are auto-loaded from `mcp/data/configs_db.json` on each app start.
- Test runs are appended to `mcp/data/tests_db.json` after each run (not loaded on startup).

---

## Disclaimer

These examples are for **educational and research use only**. Do not apply these attack techniques to real systems without explicit authorization.
