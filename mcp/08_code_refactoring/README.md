# 08 · Code Refactoring Tools

A suite of MCP tools for static code analysis, complexity measurement, design pattern detection, and automated refactoring suggestions.

## Tool Groups

| Module | File | Tools |
|--------|------|-------|
| Static Analysis | `tools/static_analysis_tools.py` | `analyze_code_quality`, `detect_code_smells`, `find_dead_code`, `check_security_patterns` |
| Complexity | `tools/complexity_tools.py` | `calculate_cyclomatic_complexity`, `measure_code_metrics`, `analyze_nesting_depth`, `evaluate_coupling` |
| Pattern Detection | `tools/pattern_detection_tools.py` | `detect_design_patterns`, `find_antipatterns`, `analyze_solid_principles`, `detect_duplicate_logic` |
| Refactoring | `tools/refactoring_tools.py` | `suggest_refactorings`, `suggest_extract_method`, `improve_naming`, `simplify_conditionals` |

## Tool Reference

### Static Analysis (`tools/static_analysis_tools.py`)

| Tool | Description |
|------|-------------|
| `analyze_code_quality(code, language)` | Score code quality 0–100, list violations by severity |
| `detect_code_smells(code)` | Find magic numbers, bare except, mutable defaults, hardcoded secrets, etc. |
| `find_dead_code(code)` | Detect unused imports, unreachable code, assigned-but-never-read variables |
| `check_security_patterns(code, language)` | Scan for SQL injection, command injection, path traversal, weak hashes, pickle |

### Complexity (`tools/complexity_tools.py`)

| Tool | Description |
|------|-------------|
| `calculate_cyclomatic_complexity(code, language)` | Per-function McCabe complexity with risk levels |
| `measure_code_metrics(code, language)` | LOC, blank lines, comment ratio, avg function length, docstring coverage |
| `analyze_nesting_depth(code)` | Detect 4+ level deep nesting with early-return suggestions |
| `evaluate_coupling(code)` | Import count, cross-function call map, coupling level |

### Pattern Detection (`tools/pattern_detection_tools.py`)

| Tool | Description |
|------|-------------|
| `detect_design_patterns(code)` | Identify Singleton, Observer, Strategy, Decorator, Iterator, etc. |
| `find_antipatterns(code)` | Flag God Class, Feature Envy, Global State, Lava Flow, etc. |
| `analyze_solid_principles(code)` | Assess SRP, OCP, LSP, ISP, DIP adherence |
| `detect_duplicate_logic(code)` | Find copy-pasted code blocks (DRY violations) |

### Refactoring (`tools/refactoring_tools.py`)

| Tool | Description |
|------|-------------|
| `suggest_refactorings(code, language)` | Prioritised refactoring backlog with effort estimates |
| `suggest_extract_method(code, min_block_lines)` | Identify blocks suitable for Extract Method refactoring |
| `improve_naming(code, language)` | Detect PEP 8 naming violations with suggested renames |
| `simplify_conditionals(code)` | Detect boolean literal comparisons, None equality checks, nested if-else, etc. |

## Usage

**Start the MCP server:**

```bash
cd mcp/08_code_refactoring
python server.py
```

**Run the standalone demo (no LLM required):**

```bash
cd mcp/08_code_refactoring
python demo.py
```

## Project Structure

```
08_code_refactoring/
├── server.py          # MCP server entry point
├── demo.py            # Standalone demonstration script
├── README.md          # This file
└── tools/
    ├── __init__.py                # Package exports
    ├── static_analysis_tools.py   # Quality scoring, smells, dead code, security
    ├── complexity_tools.py        # Cyclomatic complexity, metrics, nesting, coupling
    ├── pattern_detection_tools.py # GoF patterns, anti-patterns, SOLID, duplication
    └── refactoring_tools.py       # Suggestions, extract method, naming, conditionals
```

## Code Smells Detected

| Smell | Severity |
|-------|----------|
| Magic numbers | LOW |
| Long function (>50 lines) | MEDIUM |
| Long parameter list (>4 params) | MEDIUM |
| Print statements in production code | LOW |
| Commented-out code | LOW |
| Bare `except:` clause | HIGH |
| Mutable default argument | HIGH |
| Hardcoded password / secret | CRITICAL |
| Nested ternary | MEDIUM |

## Security Patterns Checked

| Pattern | CWE | Severity |
|---------|-----|----------|
| String-formatted SQL query | CWE-89 | CRITICAL |
| `os.system()` / `shell=True` | CWE-78 | CRITICAL |
| Path built from user input | CWE-22 | HIGH |
| `random` for security context | CWE-330 | MEDIUM |
| MD5 / SHA-1 hashing | CWE-327 | HIGH |
| XML parsing without XXE protection | CWE-611 | MEDIUM |
| `pickle.loads()` on untrusted data | CWE-502 | CRITICAL |
