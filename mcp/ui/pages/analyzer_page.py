from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk

from ui.services.tooltip import attach_tooltip


class AnalyzerPage:
    def __init__(
        self,
        parent: ttk.Frame,
        on_scan: callable,
        on_export_json: callable,
        on_select_finding: callable,
        on_sort_findings: callable,
    ) -> None:
        self._parent = parent
        self._on_scan = on_scan
        self._on_export_json = on_export_json
        self._on_select_finding = on_select_finding
        self._on_sort_findings = on_sort_findings

        self.target_var = tk.StringVar()
        self.include_ext_var = tk.StringVar(value=".py,.json,.yaml,.yml,.md")
        self.exclude_var = tk.StringVar(value="__pycache__,.venv,.git,node_modules")
        self.selected_llm_var = tk.StringVar(value="None (rules only)")
        self.status_var = tk.StringVar(value="Ready to scan MCP implementation folders.")
        self.progress_var = tk.DoubleVar(value=0)

        self.llm_combo: ttk.Combobox
        self.scan_btn: ttk.Button
        self.export_btn: ttk.Button
        self.tree: ttk.Treeview
        self.detail_text: scrolledtext.ScrolledText
        self.summary_text: scrolledtext.ScrolledText

        self.build()

    def build(self) -> None:
        top = ttk.LabelFrame(self._parent, text="MCP Analyzer Agent", padding=8)
        top.pack(fill=tk.X, padx=6, pady=6)
        top.columnconfigure(1, weight=1)

        ttk.Label(top, text="Target folder:").grid(row=0, column=0, sticky="w", padx=(0, 6), pady=3)
        target_entry = ttk.Entry(top, textvariable=self.target_var)
        target_entry.grid(row=0, column=1, sticky="ew", pady=3)
        attach_tooltip(target_entry, "Root folder to scan recursively for MCP implementation files.")
        ttk.Button(top, text="Browse", command=self._browse_folder).grid(row=0, column=2, padx=(6, 0), pady=3)

        ttk.Label(top, text="Include extensions:").grid(row=1, column=0, sticky="w", padx=(0, 6), pady=3)
        include_entry = ttk.Entry(top, textvariable=self.include_ext_var)
        include_entry.grid(row=1, column=1, sticky="ew", pady=3)
        attach_tooltip(include_entry, "Comma-separated list of file extensions (example: .py,.json,.yaml).")

        ttk.Label(top, text="Exclude patterns:").grid(row=2, column=0, sticky="w", padx=(0, 6), pady=3)
        exclude_entry = ttk.Entry(top, textvariable=self.exclude_var)
        exclude_entry.grid(row=2, column=1, sticky="ew", pady=3)
        attach_tooltip(exclude_entry, "Comma-separated path tokens to skip while scanning.")

        ttk.Label(top, text="LLM for summary:").grid(row=3, column=0, sticky="w", padx=(0, 6), pady=3)
        self.llm_combo = ttk.Combobox(top, textvariable=self.selected_llm_var, values=["None (rules only)"], state="readonly")
        self.llm_combo.grid(row=3, column=1, sticky="ew", pady=3)
        attach_tooltip(self.llm_combo, "Optional LLM used to summarize rule findings and suggest priorities.")

        btn_row = ttk.Frame(top)
        btn_row.grid(row=4, column=1, sticky="w", pady=(8, 2))
        self.scan_btn = ttk.Button(btn_row, text="Scan Folder", command=self._on_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=2)
        self.export_btn = ttk.Button(btn_row, text="Export JSON", command=self._on_export_json)
        self.export_btn.pack(side=tk.LEFT, padx=2)

        ttk.Progressbar(top, variable=self.progress_var, maximum=100).grid(row=5, column=0, columnspan=3, sticky="ew", pady=(8, 2))
        ttk.Label(top, textvariable=self.status_var).grid(row=6, column=0, columnspan=3, sticky="w", pady=(0, 2))

        findings_lf = ttk.LabelFrame(self._parent, text="Findings", padding=6)
        findings_lf.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0, 6))
        findings_lf.rowconfigure(0, weight=1)
        findings_lf.columnconfigure(0, weight=1)

        cols = ("ID", "Severity", "Category", "File", "Line", "Evidence")
        self.tree = ttk.Treeview(findings_lf, columns=cols, show="headings", selectmode="browse")
        widths = (70, 90, 180, 300, 70, 460)
        for col, width in zip(cols, widths):
            self.tree.heading(col, text=col, command=lambda c=col: self._on_sort_findings(c))
            self.tree.column(col, width=width, minwidth=50)

        self.tree.tag_configure("HIGH", background="#f8d7da")
        self.tree.tag_configure("MEDIUM", background="#fff3cd")
        self.tree.tag_configure("LOW", background="#d4edda")

        vsb = ttk.Scrollbar(findings_lf, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(findings_lf, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        self.tree.bind("<<TreeviewSelect>>", self._on_select_finding)

        bottom = ttk.Frame(self._parent)
        bottom.pack(fill=tk.BOTH, expand=False, padx=6, pady=(0, 6))
        bottom.columnconfigure(0, weight=1)
        bottom.columnconfigure(1, weight=1)

        detail_lf = ttk.LabelFrame(bottom, text="Finding Detail", padding=4)
        detail_lf.grid(row=0, column=0, sticky="nsew", padx=(0, 3))
        self.detail_text = scrolledtext.ScrolledText(detail_lf, height=10, font=("Courier", 11), state=tk.DISABLED, wrap=tk.WORD)
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        summary_lf = ttk.LabelFrame(bottom, text="LLM Summary", padding=4)
        summary_lf.grid(row=0, column=1, sticky="nsew", padx=(3, 0))
        self.summary_text = scrolledtext.ScrolledText(summary_lf, height=10, font=("Courier", 11), state=tk.DISABLED, wrap=tk.WORD)
        self.summary_text.pack(fill=tk.BOTH, expand=True)

    def _browse_folder(self) -> None:
        path = filedialog.askdirectory(title="Select folder to scan")
        if path:
            self.target_var.set(path)

    def set_llm_options(self, llm_options: list[str]) -> None:
        values = ["None (rules only)"] + llm_options
        self.llm_combo.configure(values=values)
        if self.selected_llm_var.get() not in values:
            self.selected_llm_var.set(values[0])

    def set_busy(self, is_busy: bool) -> None:
        self.scan_btn.configure(state=tk.DISABLED if is_busy else tk.NORMAL)
        self.export_btn.configure(state=tk.DISABLED if is_busy else tk.NORMAL)

