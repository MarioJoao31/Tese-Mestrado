from __future__ import annotations

import tkinter as tk
from tkinter import scrolledtext, ttk


class RunPage:
    def __init__(
        self,
        parent: ttk.Frame,
        on_run: callable,
        on_stop: callable,
        on_clear_log: callable,
    ) -> None:
        self._parent = parent
        self._on_run = on_run
        self._on_stop = on_stop
        self._on_clear_log = on_clear_log

        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar(value="Ready - add LLM tests and/or MCP suites, then press Run.")
        self.run_btn: ttk.Button
        self.stop_btn: ttk.Button
        self.log_text: scrolledtext.ScrolledText

        self.build()

    def build(self) -> None:
        prog_lf = ttk.LabelFrame(self._parent, text="Progress", padding=8)
        prog_lf.pack(fill=tk.X, padx=6, pady=6)

        ttk.Progressbar(prog_lf, variable=self.progress_var, maximum=100).pack(fill=tk.X, pady=(0, 4))
        ttk.Label(prog_lf, textvariable=self.status_var).pack(anchor="w")

        btn_row = ttk.Frame(self._parent)
        btn_row.pack(fill=tk.X, padx=6, pady=2)

        self.run_btn = ttk.Button(btn_row, text="Run All Tests", command=self._on_run)
        self.run_btn.pack(side=tk.LEFT, padx=4)

        self.stop_btn = ttk.Button(btn_row, text="Stop", command=self._on_stop, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=4)

        ttk.Button(btn_row, text="Clear Log", command=self._on_clear_log).pack(side=tk.LEFT, padx=4)

        log_lf = ttk.LabelFrame(self._parent, text="Live Test Log", padding=4)
        log_lf.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        self.log_text = scrolledtext.ScrolledText(log_lf, font=("Courier", 11), state=tk.DISABLED, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        for tag, cfg in (
            ("safe", {"foreground": "#1a7d00"}),
            ("vulnerable", {"foreground": "#cc0000", "font": ("Courier", 11, "bold")}),
            ("error", {"foreground": "#e07800"}),
            ("info", {"foreground": "#005fa3"}),
            ("header", {"font": ("Courier", 11, "bold")}),
            ("demo", {"foreground": "#6a0dad"}),
        ):
            self.log_text.tag_configure(tag, **cfg)

