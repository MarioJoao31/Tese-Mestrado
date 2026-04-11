"""
attack_runner.py
----------------
Execution layer for LLM attack tests and demo scripts.

Test definitions live in `attack_definitions.py` so the catalog is isolated from
the runtime logic.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from attack_definitions import (
    DEMO_SCRIPTS,
    LLM_ATTACK_TESTS,
    get_demo_categories,
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


def run_demo_script(demo: dict) -> AttackResult:
    """
    Run an existing demo script as a subprocess and capture its output.
    Returns a single AttackResult with verdict DEMO and the full output.
    """
    script = demo["script"]
    if not os.path.exists(script):
        return AttackResult(
            llm_name="N/A",
            attack_category=demo["category"],
            test_name=demo["name"],
            prompt=f"python {script}",
            response="",
            verdict="ERROR",
            details=f"Script not found: {script}",
        )

    try:
        proc = subprocess.run(
            [sys.executable, script],
            capture_output=True,
            text=True,
            timeout=demo.get("timeout", 60),
            cwd=os.path.dirname(script),
        )
        output = proc.stdout + ("\n[STDERR]\n" + proc.stderr if proc.stderr.strip() else "")
        verdict = "DEMO"
        if proc.returncode != 0:
            verdict = "ERROR"
            output += f"\n[Exit code: {proc.returncode}]"

        return AttackResult(
            llm_name="N/A",
            attack_category=demo["category"],
            test_name=demo["name"],
            prompt=f"python {os.path.basename(script)}",
            response=output,
            verdict=verdict,
            details="Demo script output captured from subprocess.",
        )
    except subprocess.TimeoutExpired:
        return AttackResult(
            llm_name="N/A",
            attack_category=demo["category"],
            test_name=demo["name"],
            prompt=f"python {os.path.basename(script)}",
            response="",
            verdict="ERROR",
            details=f"Script timed out after {demo.get('timeout', 60)}s.",
        )
    except Exception as exc:
        return AttackResult(
            llm_name="N/A",
            attack_category=demo["category"],
            test_name=demo["name"],
            prompt=f"python {os.path.basename(script)}",
            response="",
            verdict="ERROR",
            details=str(exc),
        )


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

    print("\n--- Demo Scripts ---")
    for demo in DEMO_SCRIPTS:
        print(f"\nRunning: {demo['name']}")
        result = run_demo_script(demo)
        print(f"  Verdict: {result.verdict}")
        print(f"  Output (first 200 chars): {result.response[:200]}")


if __name__ == "__main__":
    asyncio.run(_cli_demo())
