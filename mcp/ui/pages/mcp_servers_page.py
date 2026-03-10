from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, ttk

from ui.services.tooltip import attach_tooltip


class McpServersPage:
    def __init__(
        self,
        parent: ttk.Frame,
        on_select: callable,
        on_add: callable,
        on_update: callable,
        on_remove: callable,
    ) -> None:
        self._parent = parent
        self._on_select = on_select
        self._on_add = on_add
        self._on_update = on_update
        self._on_remove = on_remove

        self.server_vars: dict[str, tk.StringVar] = {
            "server_name": tk.StringVar(value="Custom MCP Server"),
            "tool_name": tk.StringVar(value="custom_tool"),
            "script": tk.StringVar(value=""),
            "timeout": tk.StringVar(value="60"),
            "enabled": tk.StringVar(value="true"),
        }
        self.server_listbox: tk.Listbox

        self.build()

    def build(self) -> None:
        container = ttk.Frame(self._parent, padding=8)
        container.pack(fill=tk.BOTH, expand=True)
        container.columnconfigure(0, weight=1)

        list_frame = ttk.LabelFrame(container, text="Configured MCP Servers / Tools", padding=6)
        list_frame.grid(row=0, column=0, sticky="nsew")
        container.rowconfigure(0, weight=1)

        self.server_listbox = tk.Listbox(list_frame, height=9, selectmode=tk.SINGLE, exportselection=False)
        self.server_listbox.pack(fill=tk.BOTH, expand=True)
        self.server_listbox.bind("<<ListboxSelect>>", self._on_select)

        form_frame = ttk.LabelFrame(container, text="Add or Edit MCP Tool", padding=6)
        form_frame.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        form_frame.columnconfigure(1, weight=1)

        ttk.Label(form_frame, text="Server name:").grid(row=0, column=0, sticky="w", padx=(0, 6), pady=2)
        server_entry = ttk.Entry(form_frame, textvariable=self.server_vars["server_name"])
        server_entry.grid(row=0, column=1, sticky="ew", pady=2)
        attach_tooltip(server_entry, "Display name for this MCP server grouping in the UI.")

        ttk.Label(form_frame, text="Tool name:").grid(row=1, column=0, sticky="w", padx=(0, 6), pady=2)
        tool_entry = ttk.Entry(form_frame, textvariable=self.server_vars["tool_name"])
        tool_entry.grid(row=1, column=1, sticky="ew", pady=2)
        attach_tooltip(tool_entry, "Tool identifier to show/run for this script entry.")

        ttk.Label(form_frame, text="Demo script path:").grid(row=2, column=0, sticky="w", padx=(0, 6), pady=2)
        script_entry = ttk.Entry(form_frame, textvariable=self.server_vars["script"])
        script_entry.grid(row=2, column=1, sticky="ew", pady=2)
        attach_tooltip(script_entry, "Absolute or relative path to a Python demo script (.py) to execute.")
        ttk.Button(form_frame, text="Browse", command=self._browse_script).grid(row=2, column=2, padx=(6, 0), pady=2)

        ttk.Label(form_frame, text="Timeout (sec):").grid(row=3, column=0, sticky="w", padx=(0, 6), pady=2)
        timeout_entry = ttk.Entry(form_frame, textvariable=self.server_vars["timeout"])
        timeout_entry.grid(row=3, column=1, sticky="ew", pady=2)
        attach_tooltip(timeout_entry, "Maximum run time in seconds before the demo script is stopped.")

        ttk.Label(form_frame, text="Enabled (true/false):").grid(row=4, column=0, sticky="w", padx=(0, 6), pady=2)
        enabled_entry = ttk.Entry(form_frame, textvariable=self.server_vars["enabled"])
        enabled_entry.grid(row=4, column=1, sticky="ew", pady=2)
        attach_tooltip(enabled_entry, "Set true/false (also accepts 1/0, yes/no, on/off) to include or skip this tool.")

        btn_row = ttk.Frame(container)
        btn_row.grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Button(btn_row, text="Add", command=self._on_add).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="Update", command=self._on_update).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="Remove", command=self._on_remove).pack(side=tk.LEFT, padx=2)

        ttk.Label(
            container,
            text=(
                "Each entry represents one external MCP demo tool script.\n"
                "When enabled, it will run together with other demos."
            ),
            foreground="gray",
            justify=tk.LEFT,
        ).grid(row=3, column=0, sticky="w", pady=(8, 0))

    def _browse_script(self) -> None:
        path = filedialog.askopenfilename(
            title="Select demo script",
            filetypes=[("Python files", "*.py"), ("All files", "*.*")],
        )
        if path:
            self.server_vars["script"].set(path)
