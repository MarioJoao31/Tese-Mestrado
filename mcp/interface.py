"""
interface.py
------------
Thin entry point for the refactored Tkinter GUI.
"""

from __future__ import annotations

import os
import sys

# Ensure mcp/ is on sys.path when running this file directly.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui.app import main


if __name__ == "__main__":
    main()

