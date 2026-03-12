from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from attack_runner import LLMConfig


@dataclass
class AnalyzerFinding:
    id: str
    severity: str
    category: str
    file: str
    line: int
    evidence: str
    recommendation: str


@dataclass
class AnalyzerReport:
    scan_time: str
    target_path: str
    files_scanned: int
    llm_used: str
    findings: list[AnalyzerFinding] = field(default_factory=list)
    llm_summary: str = ""
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["findings_count"] = len(self.findings)
        return payload


@dataclass(frozen=True)
class _Rule:
    code: str
    severity: str
    category: str
    pattern: re.Pattern[str]
    recommendation: str


_RULES: list[_Rule] = [
    _Rule(
        code="CMD_SHELL_TRUE",
        severity="HIGH",
        category="Command Execution",
        pattern=re.compile(r"subprocess\.(?:run|Popen|call|check_call|check_output)\(.*?shell\s*=\s*True", re.DOTALL),
        recommendation="Avoid shell=True; pass argv as a list and validate user-controlled inputs.",
    ),
    _Rule(
        code="OS_SYSTEM_CALL",
        severity="HIGH",
        category="Command Execution",
        pattern=re.compile(r"\bos\.system\("),
        recommendation="Replace os.system with subprocess.run(list_args, shell=False) and strict input validation.",
    ),
    _Rule(
        code="DYNAMIC_EXEC",
        severity="HIGH",
        category="Code Injection",
        pattern=re.compile(r"\b(?:eval|exec)\("),
        recommendation="Avoid eval/exec on dynamic content; use safe parsing and allowlists.",
    ),
    _Rule(
        code="PICKLE_LOAD",
        severity="HIGH",
        category="Unsafe Deserialization",
        pattern=re.compile(r"\bpickle\.(?:load|loads)\("),
        recommendation="Do not deserialize untrusted pickle data; use safer formats like JSON.",
    ),
    _Rule(
        code="YAML_LOAD",
        severity="HIGH",
        category="Unsafe Deserialization",
        pattern=re.compile(r"\byaml\.load\("),
        recommendation="Use yaml.safe_load for untrusted YAML inputs.",
    ),
    _Rule(
        code="REQUESTS_VERIFY_FALSE",
        severity="MEDIUM",
        category="Transport Security",
        pattern=re.compile(r"\brequests\.[a-z_]+\([^)]*verify\s*=\s*False", re.DOTALL),
        recommendation="Keep TLS verification enabled (verify=True) and pin certs where appropriate.",
    ),
    _Rule(
        code="HARDCODED_SECRET",
        severity="MEDIUM",
        category="Secrets Exposure",
        pattern=re.compile(
            r"(?im)\b(?:api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*[\"'][^\"'\n]{8,}[\"']"
        ),
        recommendation="Move secrets to environment variables or a secure secret manager.",
    ),
    _Rule(
        code="PATH_TRAVERSAL_RISK",
        severity="MEDIUM",
        category="Path Traversal",
        pattern=re.compile(r"os\.path\.join\([^)]*(?:user|input|filename|filepath|path)", re.IGNORECASE),
        recommendation="Normalize and validate paths against an allowed base directory before file access.",
    ),
    _Rule(
        code="BIND_ALL_INTERFACES",
        severity="LOW",
        category="Network Exposure",
        pattern=re.compile(r"[\"']0\.0\.0\.0[\"']"),
        recommendation="Bind to localhost unless remote exposure is explicitly required and protected.",
    ),
]


def _parse_csv_tokens(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]


def _is_likely_binary(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:2048]
    except OSError:
        return True
    return b"\x00" in sample


def _line_number_for(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def _line_evidence(content: str, line: int) -> str:
    lines = content.splitlines()
    if line < 1 or line > len(lines):
        return ""
    return lines[line - 1].strip()[:220]


def _collect_files(target: Path, include_exts: list[str], excludes: list[str]) -> list[Path]:
    include_set = {ext if ext.startswith(".") else f".{ext}" for ext in include_exts}
    files: list[Path] = []
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        if include_set and path.suffix.lower() not in include_set:
            continue
        as_posix = path.as_posix()
        if any(token in as_posix for token in excludes):
            continue
        files.append(path)
    return files


async def _llm_summarize(report: AnalyzerReport, llm_config: LLMConfig) -> str:
    from openai import AsyncOpenAI

    findings_preview = "\n".join(
        f"- [{f.severity}] {f.category} | {f.file}:{f.line} | {f.evidence}"
        for f in report.findings[:40]
    )
    if not findings_preview:
        findings_preview = "- No findings detected by current rule set."

    system = (
        "You are a security analyst specializing in MCP implementations. "
        "Provide concise, defensive guidance only. "
        "Do not provide offensive exploitation steps."
    )
    user = (
        f"Target path: {report.target_path}\n"
        f"Files scanned: {report.files_scanned}\n"
        f"Findings: {len(report.findings)}\n\n"
        "Findings preview:\n"
        f"{findings_preview}\n\n"
        "Respond with:\n"
        "1) Overall risk level (LOW/MEDIUM/HIGH)\n"
        "2) Top 5 remediation priorities\n"
        "3) Quick hardening checklist for MCP tool implementations\n"
    )

    client = AsyncOpenAI(base_url=llm_config.base_url, api_key=llm_config.api_key)
    response = await client.chat.completions.create(
        model=llm_config.model,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        temperature=0,
        max_tokens=500,
    )
    return (response.choices[0].message.content or "").strip()


class McpAnalyzerService:
    @staticmethod
    async def analyze_mcp_folder(
        target_path: str,
        include_extensions_raw: str,
        exclude_patterns_raw: str,
        llm_config: LLMConfig | None = None,
        on_progress: Callable[[int, int], None] | None = None,
    ) -> AnalyzerReport:
        target = Path(target_path).expanduser().resolve()
        include_exts = _parse_csv_tokens(include_extensions_raw) or [".py", ".json", ".yaml", ".yml", ".md"]
        excludes = _parse_csv_tokens(exclude_patterns_raw)

        report = AnalyzerReport(
            scan_time=datetime.now().isoformat(),
            target_path=str(target),
            files_scanned=0,
            llm_used=str(llm_config) if llm_config else "None",
        )

        if not target.exists() or not target.is_dir():
            report.errors.append(f"Target folder does not exist or is not a directory: {target}")
            return report

        files = _collect_files(target, include_exts, excludes)
        total = len(files)
        finding_idx = 1

        for done, file_path in enumerate(files, start=1):
            if on_progress:
                on_progress(done, total)

            if _is_likely_binary(file_path):
                continue

            try:
                content = file_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                except OSError as exc:
                    report.errors.append(f"Could not read {file_path}: {exc}")
                    continue

            report.files_scanned += 1
            rel_path = str(file_path.relative_to(target))
            for rule in _RULES:
                for match in rule.pattern.finditer(content):
                    line = _line_number_for(content, match.start())
                    report.findings.append(
                        AnalyzerFinding(
                            id=f"F{finding_idx:04d}",
                            severity=rule.severity,
                            category=rule.category,
                            file=rel_path,
                            line=line,
                            evidence=_line_evidence(content, line),
                            recommendation=rule.recommendation,
                        )
                    )
                    finding_idx += 1

        if on_progress:
            on_progress(total, total)

        if llm_config:
            try:
                report.llm_summary = await _llm_summarize(report, llm_config)
            except Exception as exc:
                report.errors.append(f"LLM summary unavailable: {exc}")

        return report

    @staticmethod
    def export_report_json(report: AnalyzerReport, filepath: str) -> None:
        output = Path(filepath).expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(report.to_dict(), fh, indent=2, ensure_ascii=False)
