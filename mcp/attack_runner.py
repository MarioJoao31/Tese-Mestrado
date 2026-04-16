"""
attack_runner.py
----------------
Execution layer for LLM attack tests and real MCP tool test suites.

Test definitions live in `attack_definitions.py` so the catalog is isolated from
the runtime logic.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from attack_definitions import (
    LLM_ATTACK_TESTS,
    get_llm_categories,
)


@dataclass
class LLMConfig:
    """Configuration for an OpenAI-compatible LLM endpoint."""

    name: str = "LLM"
    base_url: str = "http://localhost:11434/v1"
    api_key: str = "ollama"
    model: str = "llama3.1:8b"

    def __str__(self) -> str:
        return f"{self.name} ({self.model})"


@dataclass
class AttackResult:
    """Result of a single attack test for one LLM."""

    llm_name: str
    attack_category: str
    test_name: str
    prompt: str
    response: str
    verdict: str
    details: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


def _check_markers(text: str, markers: list[str]) -> bool:
    """Return True if any marker appears in the text (case-insensitive)."""
    if not markers:
        return False
    lower = text.lower()
    return any(str(marker).lower() in lower for marker in markers if str(marker).strip())


def _resolve_path(path: str) -> str:
    """Resolve relative paths against the current working directory."""
    return path if os.path.isabs(path) else os.path.abspath(path)


def _load_mcp_test_cases(tests_file: str) -> tuple[list[dict], str | None]:
    """Load declarative MCP tool test cases from a JSON file."""
    resolved = _resolve_path(tests_file)
    if not os.path.exists(resolved):
        return [], f"Test file not found: {resolved}"
    try:
        with open(resolved, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return [], f"Invalid tests file: {exc}"

    tests_obj = payload.get("tests") if isinstance(payload, dict) else payload
    if not isinstance(tests_obj, list):
        return [], "Tests file must contain a 'tests' array (or be a top-level array)."

    tests: list[dict] = []
    for idx, test in enumerate(tests_obj, start=1):
        if not isinstance(test, dict):
            return [], f"Invalid test at index {idx}: expected object."

        name = str(test.get("name", f"test_{idx}")).strip() or f"test_{idx}"
        tool = str(test.get("tool", "")).strip()
        params = test.get("params", {})
        if not tool:
            return [], f"Invalid test '{name}': missing 'tool'."
        if not isinstance(params, dict):
            return [], f"Invalid test '{name}': 'params' must be an object."

        normalized = dict(test)
        normalized["name"] = name
        normalized["tool"] = tool
        normalized["params"] = params
        tests.append(normalized)

    if not tests:
        return [], "No tests found in tests file."
    return tests, None


def _parse_server_command(entry: dict) -> tuple[str | None, list[str], str | None]:
    """Resolve command + args for launching an MCP server over stdio."""
    command = str(entry.get("command", "")).strip()
    args_raw = str(entry.get("args", "")).strip()

    # Backward compatibility for older saved entries that used "script".
    script = str(entry.get("script", "")).strip()
    if not command and script:
        resolved_script = _resolve_path(script)
        return "python", [resolved_script], None

    if not command:
        return None, [], "Missing server command."

    args = shlex.split(args_raw, posix=False) if args_raw else []
    return command, args, None


def count_custom_entry_steps(entry: dict) -> int:
    """Return the number of result rows expected for a custom MCP entry."""
    tests_file = str(entry.get("tests_file", "")).strip()
    if not tests_file:
        return 0
    tests, error = _load_mcp_test_cases(tests_file)
    return len(tests) if not error else 0


async def run_llm_test(
    llm_config: LLMConfig,
    test: dict,
    timeout: float = 60.0,
) -> AttackResult:
    """
    Run a single LLM test case against the given LLM configuration.
    Returns an AttackResult with verdict SAFE, VULNERABLE, or ERROR.
    """
    try:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(
            base_url=llm_config.base_url,
            api_key=llm_config.api_key,
        )

        response = await asyncio.wait_for(
            client.chat.completions.create(
                model=llm_config.model,
                messages=[
                    {"role": "system", "content": test["system"]},
                    {"role": "user", "content": test["prompt"]},
                ],
                max_tokens=400,
                temperature=0,
            ),
            timeout=timeout,
        )

        resp_text = response.choices[0].message.content or ""
        compromised: bool = test["compromised_fn"](resp_text)

        if test["is_attack"]:
            verdict = "VULNERABLE" if compromised else "SAFE"
        else:
            verdict = "ERROR" if compromised else "SAFE"

        return AttackResult(
            llm_name=llm_config.name,
            attack_category=test["category"],
            test_name=test["name"],
            prompt=test["prompt"],
            response=resp_text,
            verdict=verdict,
            details=test.get("note", ""),
        )

    except asyncio.TimeoutError:
        return AttackResult(
            llm_name=llm_config.name,
            attack_category=test["category"],
            test_name=test["name"],
            prompt=test["prompt"],
            response="",
            verdict="ERROR",
            details=f"Timeout after {timeout}s - LLM did not respond in time.",
        )
    except Exception as exc:
        return AttackResult(
            llm_name=llm_config.name,
            attack_category=test["category"],
            test_name=test["name"],
            prompt=test["prompt"],
            response="",
            verdict="ERROR",
            details=str(exc),
        )


def _extract_tool_result_text(result: object) -> str:
    """Best-effort conversion of an MCP tool result to plain text."""
    content = getattr(result, "content", None)
    if isinstance(content, list) and content:
        first = content[0]
        text = getattr(first, "text", None)
        if isinstance(text, str):
            return text
    return str(result)


def _evaluate_mcp_test_response(test: dict, response: str) -> tuple[str, str]:
    """Evaluate a declarative MCP test response and return verdict + explanation."""
    is_attack = bool(test.get("is_attack", True))
    fail_markers = [str(x) for x in test.get("fail_if_any", test.get("compromised_if_any", []))]
    pass_markers = [str(x) for x in test.get("pass_if_any", test.get("safe_if_any", []))]

    failed = _check_markers(response, fail_markers)
    passed = _check_markers(response, pass_markers) if pass_markers else False

    if failed:
        return ("VULNERABLE" if is_attack else "ERROR"), f"Matched fail markers: {fail_markers}"
    if pass_markers:
        if passed:
            return "SAFE", f"Matched pass markers: {pass_markers}"
        return ("VULNERABLE" if is_attack else "ERROR"), f"Missing pass markers: {pass_markers}"
    if is_attack:
        return "ERROR", "Attack test has no pass/fail markers to evaluate."
    return "SAFE", "No explicit markers provided; non-attack test treated as informational success."


async def run_llm_tests(
    llm_config: LLMConfig,
    selected_categories: list[str],
    progress_cb: Callable[[int, int], None] | None = None,
) -> list[AttackResult]:
    """
    Run all LLM tests for the selected categories against one LLM.
    progress_cb(done, total) is called after each test.
    """
    category_keys = {category.split(".")[0].strip() for category in selected_categories}
    tests_to_run = [
        test for test in LLM_ATTACK_TESTS
        if test["category"].split(".")[0].strip() in category_keys
    ]

    results: list[AttackResult] = []
    for index, test in enumerate(tests_to_run, start=1):
        result = await run_llm_test(llm_config, test)
        results.append(result)
        if progress_cb:
            progress_cb(index, len(tests_to_run))

    return results


async def run_mcp_test_suite(entry: dict) -> list[AttackResult]:
    """
    Run a declarative MCP test suite against a real MCP server command.
    Each test case calls one tool and evaluates the response with substring markers.
    """
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    tests_file = str(entry.get("tests_file", "")).strip()
    category = str(entry.get("category", "MCP Tool Tests")).strip() or "MCP Tool Tests"
    suite_name = str(entry.get("name", "MCP Suite")).strip() or "MCP Suite"
    timeout = int(entry.get("timeout", 60))

    command, args, command_error = _parse_server_command(entry)
    if command_error or not command:
        return [
            AttackResult(
                llm_name="N/A",
                attack_category=category,
                test_name=suite_name,
                prompt="",
                response="",
                verdict="ERROR",
                details=command_error or "Invalid server command.",
            )
        ]

    if not tests_file:
        return [
            AttackResult(
                llm_name="N/A",
                attack_category=category,
                test_name=suite_name,
                prompt=command,
                response="",
                verdict="ERROR",
                details="Missing tests JSON file.",
            )
        ]

    tests, error = _load_mcp_test_cases(tests_file)
    if error:
        return [
            AttackResult(
                llm_name="N/A",
                attack_category=category,
                test_name=suite_name,
                prompt=tests_file,
                response="",
                verdict="ERROR",
                details=error,
            )
        ]

    results: list[AttackResult] = []
    server_params = StdioServerParameters(
        command=command,
        args=args,
    )

    try:
        async with asyncio.timeout(timeout):
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()

                    for test in tests:
                        prompt = f"{test['tool']}({json.dumps(test['params'], ensure_ascii=False)})"
                        try:
                            raw_result = await session.call_tool(test["tool"], test["params"])
                            response = _extract_tool_result_text(raw_result)
                            verdict, explanation = _evaluate_mcp_test_response(test, response)
                            note = str(test.get("note", "")).strip()
                            details = explanation if not note else f"{note}\n{explanation}"
                            results.append(
                                AttackResult(
                                    llm_name="N/A",
                                    attack_category=category,
                                    test_name=f"{suite_name} :: {test['name']}",
                                    prompt=prompt,
                                    response=response,
                                    verdict=verdict,
                                    details=details,
                                )
                            )
                        except Exception as exc:
                            results.append(
                                AttackResult(
                                    llm_name="N/A",
                                    attack_category=category,
                                    test_name=f"{suite_name} :: {test['name']}",
                                    prompt=prompt,
                                    response="",
                                    verdict="ERROR",
                                    details=f"Tool call failed: {exc}",
                                )
                            )
    except TimeoutError:
        return [
            AttackResult(
                llm_name="N/A",
                attack_category=category,
                test_name=suite_name,
                prompt=f"{command} {' '.join(args)}".strip(),
                response="",
                verdict="ERROR",
                details=f"Suite timed out after {timeout}s.",
            )
        ]
    except Exception as exc:
        return [
            AttackResult(
                llm_name="N/A",
                attack_category=category,
                test_name=suite_name,
                prompt=f"{command} {' '.join(args)}".strip(),
                response="",
                verdict="ERROR",
                details=str(exc),
            )
        ]

    return results


async def _cli_demo() -> None:
    config = LLMConfig(
        name="Test LLM",
        base_url=os.getenv("LLM_BASE_URL", "http://localhost:1234/v1"),
        api_key=os.getenv("LLM_API_KEY", "lm-studio"),
        model=os.getenv("LLM_MODEL", "llama-3.1-8b-instruct"),
    )

    print(f"Testing LLM: {config}")
    categories = get_llm_categories()
    results = await run_llm_tests(
        config,
        categories,
        progress_cb=lambda done, total: print(f"  {done}/{total} tests done"),
    )

    print("\n--- Results ---")
    for result in results:
        marker = "VULN" if result.verdict == "VULNERABLE" else ("OK" if result.verdict == "SAFE" else "ERR")
        print(f"{marker} [{result.attack_category}] {result.test_name}: {result.verdict}")
        if result.response:
            print(f"   Response: {result.response[:100]}")


if __name__ == "__main__":
    asyncio.run(_cli_demo())
