from __future__ import annotations

from pathlib import Path


def load_env_defaults(base_dir: Path) -> dict[str, str]:
    defaults = {
        "base_url": "http://localhost:1234/v1",
        "api_key": "lm-studio",
        "model": "llama-3.1-8b-instruct",
    }
    env_path = base_dir / ".env"
    if env_path.exists():
        with open(env_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("LLM_BASE_URL="):
                    defaults["base_url"] = line.split("=", 1)[1]
                elif line.startswith("LLM_API_KEY="):
                    defaults["api_key"] = line.split("=", 1)[1]
                elif line.startswith("LLM_MODEL="):
                    defaults["model"] = line.split("=", 1)[1]
    return defaults

