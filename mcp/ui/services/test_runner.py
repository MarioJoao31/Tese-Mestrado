from __future__ import annotations

import asyncio

from attack_runner import (
    LLM_ATTACK_TESTS,
    LLMConfig,
    count_custom_entry_steps,
    run_llm_test,
    run_mcp_test_suite,
)


class TestRunnerService:
    @staticmethod
    async def run_all(
        llm_configs: list[LLMConfig],
        selected_llm_cats: list[str],
        selected_mcp_entries: list[dict],
        stop_requested: callable,
        on_llm_header: callable,
        on_llm_test_start: callable,
        on_llm_test_done: callable,
        on_demo_start: callable,
        on_demo_done: callable,
        on_progress: callable,
    ) -> None:
        category_keys = {c.split(".")[0].strip() for c in selected_llm_cats}
        tests_per_llm = [
            t for t in LLM_ATTACK_TESTS if t["category"].split(".")[0].strip() in category_keys
        ]
        total_steps = len(llm_configs) * len(tests_per_llm) + sum(
            count_custom_entry_steps(entry) for entry in selected_mcp_entries
        )
        if total_steps == 0:
            return

        completed = 0
        for llm in llm_configs:
            if stop_requested():
                break
            on_llm_header(llm)
            for test in tests_per_llm:
                if stop_requested():
                    break
                on_llm_test_start(llm, test)
                result = await run_llm_test(llm, test)
                on_llm_test_done(result, test)
                completed += 1
                on_progress(completed / total_steps * 100)

        for entry in selected_mcp_entries:
            if stop_requested():
                break
            on_demo_start(entry)
            results = await run_mcp_test_suite(entry)
            for result in results:
                on_demo_done(result, entry)
                completed += 1
                on_progress(completed / total_steps * 100)
