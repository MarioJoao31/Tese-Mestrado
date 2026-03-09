from __future__ import annotations

import asyncio
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from attack_runner import AttackResult, DEMO_SCRIPTS, LLMConfig
from ui.pages.config_page import ConfigPage
from ui.pages.results_page import ResultsPage
from ui.pages.run_page import RunPage
from ui.services.env_loader import load_env_defaults
from ui.services.excel_export import export_results_to_excel
from ui.services.test_runner import TestRunnerService


class SecurityTestApp:
    """Main Tkinter application controller."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("LLM Security Attack Testing Interface")
        self.root.geometry("1280x820")
        self.root.minsize(900, 620)

        self.llm_configs: list[LLMConfig] = []
        self.results: list[AttackResult] = []
        self.is_running = False
        self._stop_flag = threading.Event()
        self._sort_col = ""
        self._sort_reverse = False

        self._defaults = load_env_defaults(Path(__file__).resolve().parents[1])
        self._build_ui()

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self.root, padding=(8, 4))
        toolbar.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(toolbar, text="LLM Security Attack Interface", font=("TkDefaultFont", 13, "bold")).pack(side=tk.LEFT)
        self._export_btn = ttk.Button(toolbar, text="Export to Excel", command=self._export_to_excel)
        self._export_btn.pack(side=tk.RIGHT, padx=4)

        self._nb = ttk.Notebook(self.root)
        self._nb.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        cfg_tab = ttk.Frame(self._nb)
        run_tab = ttk.Frame(self._nb)
        res_tab = ttk.Frame(self._nb)

        self._nb.add(cfg_tab, text="Configuration")
        self._nb.add(run_tab, text="Run Tests")
        self._nb.add(res_tab, text="Results")

        self.config_page = ConfigPage(
            cfg_tab,
            defaults=self._defaults,
            on_llm_select=self._on_llm_select,
            on_add_llm=self._add_llm,
            on_update_llm=self._update_llm,
            on_remove_llm=self._remove_llm,
        )
        self.run_page = RunPage(
            run_tab,
            on_run=self._start_tests,
            on_stop=self._stop_tests,
            on_clear_log=self._clear_log,
        )
        self.results_page = ResultsPage(
            res_tab,
            on_sort=self._sort_tree,
            on_select=self._on_result_select,
        )

    def _add_llm(self) -> None:
        name = self.config_page.llm_vars["name"].get().strip()
        base_url = self.config_page.llm_vars["base_url"].get().strip()
        api_key = self.config_page.llm_vars["api_key"].get().strip()
        model = self.config_page.llm_vars["model"].get().strip()

        if not name or not base_url or not model:
            messagebox.showwarning("Validation Error", "Name, Base URL and Model are required.")
            return

        cfg = LLMConfig(name=name, base_url=base_url, api_key=api_key, model=model)
        self.llm_configs.append(cfg)
        self.config_page.llm_listbox.insert(tk.END, f"{name}  [{model}]")
        self.config_page.llm_vars["name"].set("")

    def _update_llm(self) -> None:
        sel = self.config_page.llm_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        cfg = self.llm_configs[idx]
        cfg.name = self.config_page.llm_vars["name"].get().strip()
        cfg.base_url = self.config_page.llm_vars["base_url"].get().strip()
        cfg.api_key = self.config_page.llm_vars["api_key"].get().strip()
        cfg.model = self.config_page.llm_vars["model"].get().strip()
        self.config_page.llm_listbox.delete(idx)
        self.config_page.llm_listbox.insert(idx, f"{cfg.name}  [{cfg.model}]")
        self.config_page.llm_listbox.selection_set(idx)

    def _remove_llm(self) -> None:
        sel = self.config_page.llm_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        self.llm_configs.pop(idx)
        self.config_page.llm_listbox.delete(idx)

    def _on_llm_select(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        sel = self.config_page.llm_listbox.curselection()
        if not sel:
            return
        cfg = self.llm_configs[sel[0]]
        self.config_page.llm_vars["name"].set(cfg.name)
        self.config_page.llm_vars["base_url"].set(cfg.base_url)
        self.config_page.llm_vars["api_key"].set(cfg.api_key)
        self.config_page.llm_vars["model"].set(cfg.model)

    def _start_tests(self) -> None:
        if not self.llm_configs and not any(v.get() for v in self.config_page.demo_vars.values()):
            messagebox.showwarning("Nothing to run", "Add at least one LLM endpoint or enable a demo script.")
            return

        selected_llm_cats = [c for c, v in self.config_page.atk_vars.items() if v.get()]
        selected_demos = [d for d in DEMO_SCRIPTS if self.config_page.demo_vars.get(d["category"], tk.BooleanVar()).get()]

        if self.llm_configs and not selected_llm_cats and not selected_demos:
            messagebox.showwarning("Nothing selected", "Select at least one attack category to run.")
            return

        self.is_running = True
        self._stop_flag.clear()
        self.results = []
        self.run_page.progress_var.set(0)
        self.run_page.run_btn.config(state=tk.DISABLED)
        self.run_page.stop_btn.config(state=tk.NORMAL)
        self.run_page.status_var.set("Running tests...")

        thread = threading.Thread(
            target=self._run_tests_thread,
            args=(list(self.llm_configs), selected_llm_cats, selected_demos),
            daemon=True,
        )
        thread.start()

    def _stop_tests(self) -> None:
        self._stop_flag.set()
        self.is_running = False
        self.run_page.status_var.set("Stopping - waiting for current test to finish...")

    def _run_tests_thread(
        self,
        llm_configs: list[LLMConfig],
        selected_llm_cats: list[str],
        selected_demos: list[dict],
    ) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._async_run_all(llm_configs, selected_llm_cats, selected_demos))
        finally:
            loop.close()
            self.root.after(0, self._on_tests_complete)

    async def _async_run_all(
        self,
        llm_configs: list[LLMConfig],
        selected_llm_cats: list[str],
        selected_demos: list[dict],
    ) -> None:
        await TestRunnerService.run_all(
            llm_configs=llm_configs,
            selected_llm_cats=selected_llm_cats,
            selected_demos=selected_demos,
            stop_requested=self._stop_flag.is_set,
            on_llm_header=self._on_llm_header,
            on_llm_test_start=self._on_llm_test_start,
            on_llm_test_done=self._on_llm_test_done,
            on_demo_start=self._on_demo_start,
            on_demo_done=self._on_demo_done,
            on_progress=self._update_progress,
        )

    def _on_llm_header(self, llm: LLMConfig) -> None:
        self._log_ui(f"\n{'=' * 60}\n  LLM: {llm}\n{'=' * 60}\n", "header")

    def _on_llm_test_start(self, llm: LLMConfig, test: dict) -> None:
        self._update_status(f"Testing [{test['category']}] {test['name']} on {llm.name}...")

    def _on_llm_test_done(self, result: AttackResult, test: dict) -> None:
        self.results.append(result)
        tag = result.verdict.lower() if result.verdict in ("SAFE", "VULNERABLE", "ERROR") else "info"
        preview = result.response[:120].replace("\n", " ") if result.response else result.details[:120]
        self._log_ui(f"  [{result.verdict:>10}]  {test['name']}\n             {preview}\n", tag)

    def _on_demo_start(self, demo: dict) -> None:
        self._log_ui(f"\n{'-' * 60}\n  Demo: {demo['category']}\n{'-' * 60}\n", "demo")
        self._update_status(f"Running demo: {demo['name']}...")

    def _on_demo_done(self, result: AttackResult, demo: dict) -> None:
        self.results.append(result)
        tag = "error" if result.verdict == "ERROR" else "demo"
        preview = result.response[:200].replace("\n", " ")
        self._log_ui(f"  [{result.verdict:>10}]  {demo['name']}\n             {preview}\n", tag)

    def _log_ui(self, msg: str, tag: str = "") -> None:
        self.root.after(0, lambda m=msg, t=tag: self._append_log(m, t))

    def _append_log(self, msg: str, tag: str) -> None:
        self.run_page.log_text.config(state=tk.NORMAL)
        self.run_page.log_text.insert(tk.END, msg, tag or "")
        self.run_page.log_text.see(tk.END)
        self.run_page.log_text.config(state=tk.DISABLED)

    def _update_status(self, text: str) -> None:
        self.root.after(0, lambda t=text: self.run_page.status_var.set(t))

    def _update_progress(self, pct: float) -> None:
        self.root.after(0, lambda p=pct: self.run_page.progress_var.set(p))

    def _clear_log(self) -> None:
        self.run_page.log_text.config(state=tk.NORMAL)
        self.run_page.log_text.delete("1.0", tk.END)
        self.run_page.log_text.config(state=tk.DISABLED)

    def _on_tests_complete(self) -> None:
        self.is_running = False
        self.run_page.run_btn.config(state=tk.NORMAL)
        self.run_page.stop_btn.config(state=tk.DISABLED)
        total = len(self.results)
        vuln = sum(1 for r in self.results if r.verdict == "VULNERABLE")
        safe = sum(1 for r in self.results if r.verdict == "SAFE")
        err = sum(1 for r in self.results if r.verdict == "ERROR")
        msg = f"Tests complete - {total} results  (safe: {safe}  vulnerable: {vuln}  errors: {err})"
        self.run_page.status_var.set(msg)
        self.run_page.progress_var.set(100)
        self._log_ui(f"\n{msg}\n", "header")
        self._update_results_view()
        self._nb.select(2)

    def _update_results_view(self) -> None:
        for item in self.results_page.tree.get_children():
            self.results_page.tree.delete(item)

        for result in self.results:
            tag = result.verdict.lower() if result.verdict in ("SAFE", "VULNERABLE", "ERROR", "DEMO") else ""
            preview = result.response[:120].replace("\n", " ") if result.response else result.details[:120]
            self.results_page.tree.insert(
                "",
                tk.END,
                values=(result.llm_name, result.attack_category, result.test_name, result.verdict, preview),
                tags=(tag,),
            )

    def _on_result_select(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        sel = self.results_page.tree.selection()
        if not sel:
            return
        values = self.results_page.tree.item(sel[0])["values"]
        if not values:
            return

        for result in self.results:
            if (
                str(result.llm_name) == str(values[0])
                and str(result.attack_category) == str(values[1])
                and str(result.test_name) == str(values[2])
            ):
                text = (
                    f"LLM:      {result.llm_name}\n"
                    f"Category: {result.attack_category}\n"
                    f"Test:     {result.test_name}\n"
                    f"Verdict:  {result.verdict}\n"
                    f"Time:     {result.timestamp}\n"
                )
                if result.details:
                    text += f"\nNOTE:\n{result.details}\n"
                text += f"\nPROMPT:\n{result.prompt}\n"
                text += f"\nRESPONSE:\n{result.response}\n"

                self.results_page.detail_text.config(state=tk.NORMAL)
                self.results_page.detail_text.delete("1.0", tk.END)
                self.results_page.detail_text.insert(tk.END, text)
                self.results_page.detail_text.config(state=tk.DISABLED)
                break

    def _sort_tree(self, col: str) -> None:
        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col = col
            self._sort_reverse = False

        items = [(self.results_page.tree.set(k, col), k) for k in self.results_page.tree.get_children("")]
        items.sort(reverse=self._sort_reverse)
        for idx, (_, key) in enumerate(items):
            self.results_page.tree.move(key, "", idx)

    def _export_to_excel(self) -> None:
        if not self.results:
            messagebox.showinfo("No Results", "Run tests first to generate results.")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel workbook", "*.xlsx"), ("All files", "*.*")],
            initialfile=f"llm_security_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
        )
        if not filepath:
            return

        try:
            export_results_to_excel(self.results, filepath)
            messagebox.showinfo("Exported", f"Results saved to:\n{filepath}")
        except Exception as exc:
            messagebox.showerror("Export Error", str(exc))


def main() -> None:
    root = tk.Tk()
    style = ttk.Style(root)
    available = style.theme_names()
    for preferred in ("clam", "alt", "default"):
        if preferred in available:
            style.theme_use(preferred)
            break

    SecurityTestApp(root)
    root.mainloop()

