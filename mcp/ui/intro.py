from __future__ import annotations

import os
import subprocess
import tkinter as tk
from pathlib import Path


def play_startup_intro(root: tk.Tk, base_dir: Path) -> None:
    """Play a pre-rendered MP4 intro before showing the main UI."""
    if os.getenv("MCP_DISABLE_INTRO", "").strip().lower() in {"1", "true", "yes"}:
        return

    video_path = base_dir / "utils" / "media" / "MarioTeseMCP.mp4"
    if not video_path.exists():
        return

    root.withdraw()
    try:
        subprocess.run(
            [
                "ffplay",
                "-autoexit",
                "-loglevel",
                "quiet",
                "-nostats",
                str(video_path),
            ],
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        pass
    finally:
        root.deiconify()
