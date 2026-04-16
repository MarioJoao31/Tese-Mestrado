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
            "tool_name": tk.StringVar(value="tool_suite"),
            "command": tk.StringVar(value="python"),
            "args": tk.StringVar(value=""),
            "tests_file": tk.StringVar(value=""),
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

        ttk.Label(form_frame, text="Suite name:").grid(row=1, column=0, sticky="w", padx=(0, 6), pady=2)
        tool_entry = ttk.Entry(form_frame, textvariable=self.server_vars["tool_name"])
        tool_entry.grid(row=1, column=1, sticky="ew", pady=2)
        attach_tooltip(tool_entry, "Display name for this MCP test suite entry.")

        ttk.Label(form_frame, text="Server command:").grid(row=2, column=0, sticky="w", padx=(0, 6), pady=2)
        command_entry = ttk.Entry(form_frame, textvariable=self.server_vars["command"])
        command_entry.grid(row=2, column=1, sticky="ew", pady=2)
        attach_tooltip(command_entry, "Command used to launch the MCP server (examples: python, node, uvx).")
        ttk.Button(form_frame, text="Browse", command=self._browse_command).grid(row=2, column=2, padx=(6, 0), pady=2)

        ttk.Label(form_frame, text="Command args:").grid(row=3, column=0, sticky="w", padx=(0, 6), pady=2)
        args_entry = ttk.Entry(form_frame, textvariable=self.server_vars["args"])
        args_entry.grid(row=3, column=1, sticky="ew", pady=2)
        attach_tooltip(args_entry, "Arguments passed to the command (example: demos/06_cybersecurity_tools/server.py).")

        ttk.Label(form_frame, text="Tests JSON path:").grid(row=4, column=0, sticky="w", padx=(0, 6), pady=2)
        tests_entry = ttk.Entry(form_frame, textvariable=self.server_vars["tests_file"])
        tests_entry.grid(row=4, column=1, sticky="ew", pady=2)
        attach_tooltip(
            tests_entry,
            "JSON file with declarative MCP tool tests.",
        )
        ttk.Button(form_frame, text="Browse", command=self._browse_tests_file).grid(row=4, column=2, padx=(6, 0), pady=2)

        ttk.Label(form_frame, text="Timeout (sec):").grid(row=5, column=0, sticky="w", padx=(0, 6), pady=2)
        timeout_entry = ttk.Entry(form_frame, textvariable=self.server_vars["timeout"])
        timeout_entry.grid(row=5, column=1, sticky="ew", pady=2)
        attach_tooltip(timeout_entry, "Maximum run time in seconds before this MCP suite is stopped.")

        ttk.Label(form_frame, text="Enabled (true/false):").grid(row=6, column=0, sticky="w", padx=(0, 6), pady=2)
        enabled_entry = ttk.Entry(form_frame, textvariable=self.server_vars["enabled"])
        enabled_entry.grid(row=6, column=1, sticky="ew", pady=2)
        attach_tooltip(enabled_entry, "Set true/false (also accepts 1/0, yes/no, on/off) to include or skip this tool.")

        btn_row = ttk.Frame(container)
        btn_row.grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Button(btn_row, text="Add", command=self._on_add).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="Update", command=self._on_update).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="Remove", command=self._on_remove).pack(side=tk.LEFT, padx=2)

        ttk.Label(
            container,
            text=(
                "Each entry connects to a real MCP server launched by command + args.\n"
                "Provide a tests JSON file to score tool calls as SAFE/VULNERABLE/ERROR."
            ),
            foreground="gray",
            justify=tk.LEFT,
        ).grid(row=3, column=0, sticky="w", pady=(8, 0))

    def _browse_command(self) -> None:
        path = filedialog.askopenfilename(
            title="Select server command executable",
            filetypes=[("All files", "*.*")],
        )
        if path:
            self.server_vars["command"].set(path)

    def _browse_tests_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Select MCP tests JSON",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if path:
            self.server_vars["tests_file"].set(path)
