from __future__ import annotations

import asyncio
import subprocess
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import httpx

from attack_runner import AttackResult, DEMO_SCRIPTS, LLMConfig
from ui.intro import play_startup_intro
from ui.pages.analyzer_page import AnalyzerPage
from ui.pages.config_page import ConfigPage
from ui.pages.mcp_servers_page import McpServersPage
from ui.pages.results_page import ResultsPage
from ui.pages.run_page import RunPage
from ui.services.mcp_analyzer import AnalyzerFinding, AnalyzerReport, McpAnalyzerService
from ui.services.env_loader import load_env_defaults
from ui.services.excel_export import export_results_to_excel
from ui.services.json_db import JsonDbService
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
        self.custom_mcp_servers: list[dict[str, str | int | bool]] = []
        self.is_running = False
        self._stop_flag = threading.Event()
        self._sort_col = ""
        self._sort_reverse = False
        self._run_started_at = ""
        self._analyzer_sort_col = ""
        self._analyzer_sort_reverse = False
        self._analyzer_report: AnalyzerReport | None = None
        self._analyzer_finding_index: dict[str, AnalyzerFinding] = {}

        self._base_dir = Path(__file__).resolve().parents[1]
        self._defaults = load_env_defaults(self._base_dir)
        self._db = JsonDbService(self._base_dir / "data")
        self._build_ui()
        self.analyzer_page.target_var.set(str(self._base_dir))
        self._load_persisted_configs()
        self._refresh_analyzer_llm_options()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

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
        mcp_tab = ttk.Frame(self._nb)
        analyzer_tab = ttk.Frame(self._nb)

        self._nb.add(cfg_tab, text="Configuration")
        self._nb.add(run_tab, text="Run Tests")
        self._nb.add(res_tab, text="Results")
        self._nb.add(mcp_tab, text="MCP Servers")
        self._nb.add(analyzer_tab, text="MCP Analyzer")

        self.config_page = ConfigPage(
            cfg_tab,
            defaults=self._defaults,
            on_llm_select=self._on_llm_select,
            on_add_llm=self._add_llm,
            on_update_llm=self._update_llm,
            on_remove_llm=self._remove_llm,
            on_import_ollama_models=self._import_ollama_models,
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
        self.mcp_servers_page = McpServersPage(
            mcp_tab,
            on_select=self._on_mcp_server_select,
            on_add=self._add_mcp_server,
            on_update=self._update_mcp_server,
            on_remove=self._remove_mcp_server,
        )
        self.analyzer_page = AnalyzerPage(
            analyzer_tab,
            on_scan=self._start_analyzer_scan,
            on_export_json=self._export_analyzer_json,
            on_select_finding=self._on_analyzer_select,
            on_sort_findings=self._sort_analyzer_tree,
        )

    def _active_demo_scripts(self) -> list[dict]:
        selected_categories = {c for c, v in self.config_page.demo_vars.items() if v.get()}
        selected_default_demos = [d for d in DEMO_SCRIPTS if d["category"] in selected_categories]

        custom_demos: list[dict] = []
        for entry in self.custom_mcp_servers:
            if not bool(entry.get("enabled", True)):
                continue
            category = str(entry.get("server_name", "Custom MCP")).strip()
            tool_name = str(entry.get("tool_name", "security_suite")).strip()
            script = str(entry.get("script", "")).strip()
            tests_file = str(entry.get("tests_file", "")).strip()
            timeout = int(entry.get("timeout", 60))
            if not script:
                continue
            custom_demos.append(
                {
                    "category": f"{category} (custom)",
                    "name": tool_name,
                    "script": script,
                    "tests_file": tests_file,
                    "timeout": timeout,
                }
            )

        return selected_default_demos + custom_demos

    def _add_mcp_server(self) -> None:
        server_name = self.mcp_servers_page.server_vars["server_name"].get().strip()
        tool_name = self.mcp_servers_page.server_vars["tool_name"].get().strip()
        script = self.mcp_servers_page.server_vars["script"].get().strip()
        tests_file = self.mcp_servers_page.server_vars["tests_file"].get().strip()
        timeout_raw = self.mcp_servers_page.server_vars["timeout"].get().strip()
        enabled_raw = self.mcp_servers_page.server_vars["enabled"].get().strip().lower()

        if not server_name or not tool_name or not script:
            messagebox.showwarning("Validation Error", "Server name, suite name and script path are required.")
            return

        try:
            timeout = max(1, int(timeout_raw))
        except ValueError:
            messagebox.showwarning("Validation Error", "Timeout must be an integer number of seconds.")
            return

        enabled = enabled_raw not in {"false", "0", "no", "off"}
        entry: dict[str, str | int | bool] = {
            "server_name": server_name,
            "tool_name": tool_name,
            "script": script,
            "tests_file": tests_file,
            "timeout": timeout,
            "enabled": enabled,
        }
        self.custom_mcp_servers.append(entry)
        status = "enabled" if enabled else "disabled"
        mode = "tests" if tests_file else "demo"
        self.mcp_servers_page.server_listbox.insert(tk.END, f"{server_name} :: {tool_name} [{mode}, {status}]")
        self._save_configs()

    def _update_mcp_server(self) -> None:
        sel = self.mcp_servers_page.server_listbox.curselection()
        if not sel:
            return
        idx = sel[0]

        server_name = self.mcp_servers_page.server_vars["server_name"].get().strip()
        tool_name = self.mcp_servers_page.server_vars["tool_name"].get().strip()
        script = self.mcp_servers_page.server_vars["script"].get().strip()
        tests_file = self.mcp_servers_page.server_vars["tests_file"].get().strip()
        timeout_raw = self.mcp_servers_page.server_vars["timeout"].get().strip()
        enabled_raw = self.mcp_servers_page.server_vars["enabled"].get().strip().lower()

        if not server_name or not tool_name or not script:
            messagebox.showwarning("Validation Error", "Server name, suite name and script path are required.")
            return
        try:
            timeout = max(1, int(timeout_raw))
        except ValueError:
            messagebox.showwarning("Validation Error", "Timeout must be an integer number of seconds.")
            return

        enabled = enabled_raw not in {"false", "0", "no", "off"}
        entry: dict[str, str | int | bool] = {
            "server_name": server_name,
            "tool_name": tool_name,
            "script": script,
            "tests_file": tests_file,
            "timeout": timeout,
            "enabled": enabled,
        }
        self.custom_mcp_servers[idx] = entry

        status = "enabled" if enabled else "disabled"
        mode = "tests" if tests_file else "demo"
        self.mcp_servers_page.server_listbox.delete(idx)
        self.mcp_servers_page.server_listbox.insert(idx, f"{server_name} :: {tool_name} [{mode}, {status}]")
        self.mcp_servers_page.server_listbox.selection_set(idx)
        self._save_configs()

    def _remove_mcp_server(self) -> None:
        sel = self.mcp_servers_page.server_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        self.custom_mcp_servers.pop(idx)
        self.mcp_servers_page.server_listbox.delete(idx)
        self._save_configs()

    def _on_mcp_server_select(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        sel = self.mcp_servers_page.server_listbox.curselection()
        if not sel:
            return
        entry = self.custom_mcp_servers[sel[0]]
        self.mcp_servers_page.server_vars["server_name"].set(str(entry.get("server_name", "")))
        self.mcp_servers_page.server_vars["tool_name"].set(str(entry.get("tool_name", "")))
        self.mcp_servers_page.server_vars["script"].set(str(entry.get("script", "")))
        self.mcp_servers_page.server_vars["tests_file"].set(str(entry.get("tests_file", "")))
        self.mcp_servers_page.server_vars["timeout"].set(str(entry.get("timeout", 60)))
        self.mcp_servers_page.server_vars["enabled"].set("true" if bool(entry.get("enabled", True)) else "false")

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
        self._refresh_analyzer_llm_options()
        self._save_configs()

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
        self._refresh_analyzer_llm_options()
        self._save_configs()

    def _remove_llm(self) -> None:
        sel = self.config_page.llm_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        self.llm_configs.pop(idx)
        self.config_page.llm_listbox.delete(idx)
        self._refresh_analyzer_llm_options()
        self._save_configs()

    def _import_ollama_models(self) -> None:
        models: list[str] = []

        # Preferred: Ollama HTTP API (works even when binary is not in PATH).
        try:
            response = httpx.get("http://localhost:11434/api/tags", timeout=5.0)
            response.raise_for_status()
            data = response.json()
            raw_models = data.get("models", [])
            if isinstance(raw_models, list):
                models = [
                    str(item.get("name", "")).strip()
                    for item in raw_models
                    if isinstance(item, dict) and str(item.get("name", "")).strip()
                ]
        except (httpx.HTTPError, ValueError):
            models = []

        # Fallback: CLI output parser.
        if not models:
            try:
                proc = subprocess.run(
                    ["ollama", "list"],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
                for line in lines[1:]:
                    name = line.split()[0].strip()
                    if name:
                        models.append(name)
            except (OSError, subprocess.SubprocessError):
                models = []

        unique_models = sorted(set(models))
        if not unique_models:
            messagebox.showwarning(
                "Ollama Models",
                "No installed models were found. Make sure Ollama is running and has pulled models.",
            )
            return

        self.config_page.set_model_options(unique_models)
        current_base_url = self.config_page.llm_vars["base_url"].get().strip()
        current_api_key = self.config_page.llm_vars["api_key"].get().strip()
        if not current_base_url or current_base_url == "http://localhost:1234/v1":
            self.config_page.llm_vars["base_url"].set("http://localhost:11434/v1")
        if not current_api_key or current_api_key == "lm-studio":
            self.config_page.llm_vars["api_key"].set("ollama")
        messagebox.showinfo("Ollama Models", f"Imported {len(unique_models)} model(s) from Ollama.")

    def _on_llm_select(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        sel = self.config_page.llm_listbox.curselection()
        if not sel:
            return
        cfg = self.llm_configs[sel[0]]
        self.config_page.llm_vars["name"].set(cfg.name)
        self.config_page.llm_vars["base_url"].set(cfg.base_url)
        self.config_page.llm_vars["api_key"].set(cfg.api_key)
        self.config_page.llm_vars["model"].set(cfg.model)

    def _refresh_analyzer_llm_options(self) -> None:
        labels = [f"{cfg.name} [{cfg.model}]" for cfg in self.llm_configs]
        self.analyzer_page.set_llm_options(labels)

    def _start_tests(self) -> None:
        if not self.llm_configs and not any(v.get() for v in self.config_page.demo_vars.values()):
            messagebox.showwarning("Nothing to run", "Add at least one LLM endpoint or enable a demo script.")
            return

        selected_llm_cats = [c for c, v in self.config_page.atk_vars.items() if v.get()]
        selected_demos = self._active_demo_scripts()

        if self.llm_configs and not selected_llm_cats and not selected_demos:
            messagebox.showwarning("Nothing selected", "Select at least one attack category to run.")
            return

        self.is_running = True
        self._stop_flag.clear()
        self.results = []
        self._run_started_at = datetime.now().isoformat()
        self.run_page.progress_var.set(0)
        self.run_page.run_btn.config(state=tk.DISABLED)
        self.run_page.stop_btn.config(state=tk.NORMAL)
        self.run_page.status_var.set("Running tests...")
        self._save_configs()

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
        label = "MCP Test Suite" if str(demo.get("tests_file", "")).strip() else "Demo"
        self._log_ui(f"\n{'-' * 60}\n  {label}: {demo['category']}\n{'-' * 60}\n", "demo")
        self._update_status(f"Running {label.lower()}: {demo['name']}...")

    def _on_demo_done(self, result: AttackResult, demo: dict) -> None:
        self.results.append(result)
        tag = "error" if result.verdict == "ERROR" else "demo"
        preview = result.response[:200].replace("\n", " ")
        self._log_ui(f"  [{result.verdict:>10}]  {result.test_name}\n             {preview}\n", tag)

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
        self._save_test_run_record()

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

    def _selected_analyzer_llm_config(self) -> LLMConfig | None:
        selected = self.analyzer_page.selected_llm_var.get().strip()
        if not selected or selected == "None (rules only)":
            return None
        for cfg in self.llm_configs:
            label = f"{cfg.name} [{cfg.model}]"
            if label == selected:
                return cfg
        return None

    def _start_analyzer_scan(self) -> None:
        target = self.analyzer_page.target_var.get().strip()
        include_extensions = self.analyzer_page.include_ext_var.get().strip()
        exclude_patterns = self.analyzer_page.exclude_var.get().strip()

        if not target:
            messagebox.showwarning("Analyzer", "Select a target folder to scan.")
            return
        target_path = Path(target).expanduser()
        if not target_path.exists() or not target_path.is_dir():
            messagebox.showwarning("Analyzer", "Target folder does not exist or is not a directory.")
            return

        llm_cfg = self._selected_analyzer_llm_config()
        self._analyzer_report = None
        self._analyzer_finding_index = {}
        self.analyzer_page.progress_var.set(0)
        self.analyzer_page.status_var.set("Scanning files...")
        self.analyzer_page.set_busy(True)
        self._clear_analyzer_view()

        thread = threading.Thread(
            target=self._run_analyzer_thread,
            args=(str(target_path), include_extensions, exclude_patterns, llm_cfg),
            daemon=True,
        )
        thread.start()

    def _run_analyzer_thread(
        self,
        target_path: str,
        include_extensions: str,
        exclude_patterns: str,
        llm_cfg: LLMConfig | None,
    ) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            report = loop.run_until_complete(
                McpAnalyzerService.analyze_mcp_folder(
                    target_path=target_path,
                    include_extensions_raw=include_extensions,
                    exclude_patterns_raw=exclude_patterns,
                    llm_config=llm_cfg,
                    on_progress=self._on_analyzer_progress,
                )
            )
        except Exception as exc:
            report = AnalyzerReport(
                scan_time=datetime.now().isoformat(),
                target_path=target_path,
                files_scanned=0,
                llm_used=str(llm_cfg) if llm_cfg else "None",
                errors=[f"Analyzer failed: {exc}"],
            )
        finally:
            loop.close()
            self.root.after(0, lambda r=report: self._on_analyzer_scan_complete(r))

    def _on_analyzer_progress(self, done: int, total: int) -> None:
        def _update() -> None:
            if total <= 0:
                self.analyzer_page.progress_var.set(0)
                self.analyzer_page.status_var.set("No files matched the filters.")
                return
            pct = done / total * 100
            self.analyzer_page.progress_var.set(pct)
            self.analyzer_page.status_var.set(f"Scanning files... {done}/{total}")

        self.root.after(0, _update)

    def _on_analyzer_scan_complete(self, report: AnalyzerReport) -> None:
        self._analyzer_report = report
        self._analyzer_finding_index = {finding.id: finding for finding in report.findings}
        self._update_analyzer_view(report)
        self.analyzer_page.set_busy(False)

        if report.errors:
            self.analyzer_page.status_var.set(
                f"Scan finished with warnings - findings: {len(report.findings)}; errors: {len(report.errors)}."
            )
        else:
            self.analyzer_page.status_var.set(
                f"Scan complete - scanned {report.files_scanned} files; findings: {len(report.findings)}."
            )
        self.analyzer_page.progress_var.set(100)

    def _clear_analyzer_view(self) -> None:
        for item in self.analyzer_page.tree.get_children():
            self.analyzer_page.tree.delete(item)
        self.analyzer_page.detail_text.config(state=tk.NORMAL)
        self.analyzer_page.detail_text.delete("1.0", tk.END)
        self.analyzer_page.detail_text.config(state=tk.DISABLED)
        self.analyzer_page.summary_text.config(state=tk.NORMAL)
        self.analyzer_page.summary_text.delete("1.0", tk.END)
        self.analyzer_page.summary_text.config(state=tk.DISABLED)

    def _update_analyzer_view(self, report: AnalyzerReport) -> None:
        for item in self.analyzer_page.tree.get_children():
            self.analyzer_page.tree.delete(item)

        for finding in report.findings:
            self.analyzer_page.tree.insert(
                "",
                tk.END,
                values=(finding.id, finding.severity, finding.category, finding.file, finding.line, finding.evidence),
                tags=(finding.severity,),
            )

        summary_parts: list[str] = []
        if report.llm_summary.strip():
            summary_parts.append(report.llm_summary.strip())
        if report.errors:
            summary_parts.append("Warnings:\n" + "\n".join(f"- {err}" for err in report.errors))
        if not summary_parts:
            summary_parts.append("No LLM summary available. Run with a selected LLM to enrich the report.")

        self.analyzer_page.summary_text.config(state=tk.NORMAL)
        self.analyzer_page.summary_text.delete("1.0", tk.END)
        self.analyzer_page.summary_text.insert(tk.END, "\n\n".join(summary_parts))
        self.analyzer_page.summary_text.config(state=tk.DISABLED)

    def _on_analyzer_select(self, _event: tk.Event) -> None:  # type: ignore[type-arg]
        sel = self.analyzer_page.tree.selection()
        if not sel:
            return
        values = self.analyzer_page.tree.item(sel[0]).get("values", [])
        if not values:
            return
        finding_id = str(values[0])
        finding = self._analyzer_finding_index.get(finding_id)
        if not finding:
            return

        text = (
            f"ID:            {finding.id}\n"
            f"Severity:      {finding.severity}\n"
            f"Category:      {finding.category}\n"
            f"File:          {finding.file}\n"
            f"Line:          {finding.line}\n"
            f"Evidence:      {finding.evidence}\n\n"
            f"Recommendation:\n{finding.recommendation}\n"
        )
        self.analyzer_page.detail_text.config(state=tk.NORMAL)
        self.analyzer_page.detail_text.delete("1.0", tk.END)
        self.analyzer_page.detail_text.insert(tk.END, text)
        self.analyzer_page.detail_text.config(state=tk.DISABLED)

    def _sort_analyzer_tree(self, col: str) -> None:
        if self._analyzer_sort_col == col:
            self._analyzer_sort_reverse = not self._analyzer_sort_reverse
        else:
            self._analyzer_sort_col = col
            self._analyzer_sort_reverse = False

        rows = [(self.analyzer_page.tree.set(k, col), k) for k in self.analyzer_page.tree.get_children("")]
        rows.sort(reverse=self._analyzer_sort_reverse)
        for idx, (_, key) in enumerate(rows):
            self.analyzer_page.tree.move(key, "", idx)

    def _export_analyzer_json(self) -> None:
        if not self._analyzer_report:
            messagebox.showinfo("Analyzer", "Run a scan first to export a report.")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON file", "*.json"), ("All files", "*.*")],
            initialfile=f"mcp_analyzer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )
        if not filepath:
            return
        try:
            McpAnalyzerService.export_report_json(self._analyzer_report, filepath)
            messagebox.showinfo("Analyzer", f"Report exported to:\n{filepath}")
        except Exception as exc:
            messagebox.showerror("Analyzer Export Error", str(exc))

    def _load_persisted_configs(self) -> None:
        persisted = self._db.load_configs()
        llm_entries = persisted.get("llm_configs", [])
        if isinstance(llm_entries, list):
            for item in llm_entries:
                if not isinstance(item, dict):
                    continue
                try:
                    cfg = LLMConfig(
                        name=str(item.get("name", "")).strip(),
                        base_url=str(item.get("base_url", "")).strip(),
                        api_key=str(item.get("api_key", "")).strip(),
                        model=str(item.get("model", "")).strip(),
                    )
                except Exception:
                    continue
                if not cfg.name or not cfg.base_url or not cfg.model:
                    continue
                self.llm_configs.append(cfg)
                self.config_page.llm_listbox.insert(tk.END, f"{cfg.name}  [{cfg.model}]")

        selected_atk = persisted.get("selected_attack_categories")
        if isinstance(selected_atk, list):
            selected_set = {str(x) for x in selected_atk}
            for category, var in self.config_page.atk_vars.items():
                var.set(category in selected_set)

        selected_demos = persisted.get("selected_demo_categories")
        if isinstance(selected_demos, list):
            selected_set = {str(x) for x in selected_demos}
            for category, var in self.config_page.demo_vars.items():
                var.set(category in selected_set)

        custom_prompt = persisted.get("custom_prompt")
        if isinstance(custom_prompt, str) and custom_prompt.strip():
            self.config_page.custom_prompt_var.set(custom_prompt)

        custom_servers = persisted.get("custom_mcp_servers")
        if isinstance(custom_servers, list):
            for item in custom_servers:
                if not isinstance(item, dict):
                    continue
                script = str(item.get("script", "")).strip()
                if not script:
                    continue
                entry: dict[str, str | int | bool] = {
                    "server_name": str(item.get("server_name", "Custom MCP Server")).strip() or "Custom MCP Server",
                    "tool_name": str(item.get("tool_name", "security_suite")).strip() or "security_suite",
                    "script": script,
                    "tests_file": str(item.get("tests_file", "")).strip(),
                    "timeout": int(item.get("timeout", 60)),
                    "enabled": bool(item.get("enabled", True)),
                }
                self.custom_mcp_servers.append(entry)
                status = "enabled" if bool(entry["enabled"]) else "disabled"
                mode = "tests" if str(entry.get("tests_file", "")).strip() else "demo"
                self.mcp_servers_page.server_listbox.insert(
                    tk.END,
                    f"{entry['server_name']} :: {entry['tool_name']} [{mode}, {status}]",
                )
        self._refresh_analyzer_llm_options()

    def _save_configs(self) -> None:
        selected_llm_cats = [c for c, v in self.config_page.atk_vars.items() if v.get()]
        selected_demo_cats = [c for c, v in self.config_page.demo_vars.items() if v.get()]
        try:
            self._db.save_configs(
                llm_configs=self.llm_configs,
                selected_attack_categories=selected_llm_cats,
                selected_demo_categories=selected_demo_cats,
                custom_prompt=self.config_page.custom_prompt_var.get().strip(),
                custom_mcp_servers=self.custom_mcp_servers,
            )
        except OSError:
            pass

    def _save_test_run_record(self) -> None:
        selected_llm_cats = [c for c, v in self.config_page.atk_vars.items() if v.get()]
        selected_demo_cats = [c for c, v in self.config_page.demo_vars.items() if v.get()]
        try:
            self._db.append_test_run(
                run_started_at=self._run_started_at or datetime.now().isoformat(),
                llm_configs=self.llm_configs,
                selected_attack_categories=selected_llm_cats,
                selected_demo_categories=selected_demo_cats,
                results=self.results,
            )
        except OSError:
            pass

    def _on_close(self) -> None:
        self._save_configs()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    play_startup_intro(root, Path(__file__).resolve().parents[1])

    style = ttk.Style(root)
    available = style.theme_names()
    for preferred in ("clam", "alt", "default"):
        if preferred in available:
            style.theme_use(preferred)
            break

    SecurityTestApp(root)
    root.mainloop()
