from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from attack_runner import AttackResult, LLMConfig


class JsonDbService:
    """File-based JSON storage for UI configuration and test run records."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.config_path = data_dir / "configs_db.json"
        self.tests_path = data_dir / "tests_db.json"

    def load_configs(self) -> dict:
        if not self.config_path.exists():
            return {}
        try:
            with open(self.config_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def save_configs(
        self,
        llm_configs: list[LLMConfig],
        selected_attack_categories: list[str],
        selected_demo_categories: list[str],
        custom_prompt: str,
        custom_mcp_servers: list[dict],
    ) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "llm_configs": [asdict(cfg) for cfg in llm_configs],
            "selected_attack_categories": selected_attack_categories,
            "selected_demo_categories": selected_demo_categories,
            "custom_prompt": custom_prompt,
            "custom_mcp_servers": custom_mcp_servers,
        }
        with open(self.config_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)

    def append_test_run(
        self,
        run_started_at: str,
        llm_configs: list[LLMConfig],
        selected_attack_categories: list[str],
        selected_demo_categories: list[str],
        results: list[AttackResult],
    ) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)

        if self.tests_path.exists():
            try:
                with open(self.tests_path, "r", encoding="utf-8") as fh:
                    db = json.load(fh)
                if not isinstance(db, dict):
                    db = {}
            except (OSError, json.JSONDecodeError):
                db = {}
        else:
            db = {}

        runs = db.get("runs")
        if not isinstance(runs, list):
            runs = []

        run_record = {
            "run_started_at": run_started_at,
            "run_finished_at": datetime.now().isoformat(),
            "llm_configs": [asdict(cfg) for cfg in llm_configs],
            "selected_attack_categories": selected_attack_categories,
            "selected_demo_categories": selected_demo_categories,
            "results": [asdict(result) for result in results],
        }
        runs.append(run_record)
        db["runs"] = runs

        with open(self.tests_path, "w", encoding="utf-8") as fh:
            json.dump(db, fh, indent=2, ensure_ascii=False)
