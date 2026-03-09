from __future__ import annotations

import tkinter as tk
from tkinter import scrolledtext, ttk


class ResultsPage:
    def __init__(
        self,
        parent: ttk.Frame,
        on_sort: callable,
        on_select: callable,
    ) -> None:
        self._parent = parent
        self._on_sort = on_sort
        self._on_select = on_select
        self.tree: ttk.Treeview
        self.detail_text: scrolledtext.ScrolledText
        self.build()

    def build(self) -> None:
        cols = ("LLM", "Category", "Test", "Verdict", "Response Preview")
        self.tree = ttk.Treeview(self._parent, columns=cols, show="headings", selectmode="browse")

        widths = (130, 180, 200, 90, 450)
        for col, width in zip(cols, widths):
            self.tree.heading(col, text=col, command=lambda c=col: self._on_sort(c))
            self.tree.column(col, width=width, minwidth=60)

        vsb = ttk.Scrollbar(self._parent, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self._parent, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        self._parent.rowconfigure(0, weight=1)
        self._parent.columnconfigure(0, weight=1)

        self.tree.tag_configure("safe", background="#d4edda")
        self.tree.tag_configure("vulnerable", background="#f8d7da")
        self.tree.tag_configure("error", background="#fff3cd")
        self.tree.tag_configure("demo", background="#e2d9f3")

        detail_lf = ttk.LabelFrame(self._parent, text="Detail", padding=4)
        detail_lf.grid(row=2, column=0, columnspan=2, sticky="ew", padx=2, pady=4)

        self.detail_text = scrolledtext.ScrolledText(detail_lf, height=8, font=("Courier", 9), state=tk.DISABLED, wrap=tk.WORD)
        self.detail_text.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

