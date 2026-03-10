from __future__ import annotations

import os
import subprocess
import sys
import tkinter as tk
from pathlib import Path


def play_startup_intro(root: tk.Tk, base_dir: Path) -> None:
    """Render (if needed) and play the Manim intro before showing the main UI."""
    if os.getenv("MCP_DISABLE_INTRO", "").strip().lower() in {"1", "true", "yes"}:
        return

    gif_path = _resolve_intro_gif(base_dir)
    if gif_path is None:
        return

    _play_gif_splash(root, gif_path)


def _resolve_intro_gif(base_dir: Path) -> Path | None:
    media_dir = base_dir / "media"
    cached = _find_intro_gif(media_dir)
    if cached is not None:
        return cached

    scene_file = base_dir / "ui" / "intro_scene.py"
    if not scene_file.exists():
        return None

    cmd = [
        sys.executable,
        "-m",
        "manim",
        "-q",
        "l",
        "--format=gif",
        "--progress_bar",
        "none",
        str(scene_file),
        "MCPIntroScene",
        "-o",
        "intro.gif",
        "--media_dir",
        str(media_dir),
    ]

    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError):
        return None

    return _find_intro_gif(media_dir)


def _find_intro_gif(media_dir: Path) -> Path | None:
    candidates = sorted(media_dir.rglob("intro.gif"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def _play_gif_splash(root: tk.Tk, gif_path: Path) -> None:
    frames: list[tk.PhotoImage] = []
    idx = 0
    while True:
        try:
            frames.append(tk.PhotoImage(file=str(gif_path), format=f"gif -index {idx}"))
            idx += 1
        except tk.TclError:
            break

    if not frames:
        return

    root.withdraw()

    splash = tk.Toplevel(root)
    splash.overrideredirect(True)
    splash.configure(bg="black")

    width = frames[0].width()
    height = frames[0].height()
    x = (splash.winfo_screenwidth() - width) // 2
    y = (splash.winfo_screenheight() - height) // 2
    splash.geometry(f"{width}x{height}+{x}+{y}")

    label = tk.Label(splash, image=frames[0], bd=0, bg="black")
    label.pack()
    label._frames = frames  # type: ignore[attr-defined]

    frame_delay_ms = 67
    state = {"frame": 0}

    def advance_frame() -> None:
        frame_idx = state["frame"]
        if frame_idx >= len(frames):
            splash.destroy()
            return
        label.configure(image=frames[frame_idx])
        state["frame"] = frame_idx + 1
        splash.after(frame_delay_ms, advance_frame)

    splash.after(0, advance_frame)
    root.wait_window(splash)
    root.deiconify()
