"""报告模型、去重、JSON 落盘与终端摘要。

报告顶层固定包含 ``scan`` / ``findings`` / ``stats`` 三部分，
顺序稳定，便于后续做快照对比。
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .plugin import Finding

DEFAULT_REPORT_DIR = Path("reports")


class ScanMeta(BaseModel):
    """扫描元信息。"""

    model_config = ConfigDict(extra="forbid")

    target: str
    started_at: str
    finished_at: str
    config: dict[str, Any]


class ScanStats(BaseModel):
    """扫描统计。"""

    model_config = ConfigDict(extra="forbid")

    requests: int = 0
    skipped: int = 0
    duration_ms: int = 0
    findings_total: int = 0
    by_plugin: dict[str, int] = Field(default_factory=dict)


class Report(BaseModel):
    """一次扫描的完整报告。"""

    model_config = ConfigDict(extra="forbid")

    scan: ScanMeta
    findings: list[Finding] = Field(default_factory=list)
    stats: ScanStats = Field(default_factory=ScanStats)


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """按 (plugin, url, parameter) 去重，保留第一次出现的记录。"""

    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.plugin, finding.url, finding.parameter)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def default_report_path() -> Path:
    """默认报告路径：reports/scan-{YYYYmmdd-HHMMSS}.json。"""

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return DEFAULT_REPORT_DIR / f"scan-{stamp}.json"


def write_report(report: Report, out: Path | None = None) -> Path:
    """把报告写入 JSON 文件，返回最终路径。"""

    path = Path(out) if out is not None else default_report_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = report.model_dump(mode="json")
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def print_summary(report: Report) -> None:
    """打印终端摘要：统计信息 + 一行一个 finding。"""

    stats = report.stats
    print("=" * 72)
    print(f"扫描目标: {report.scan.target}")
    print(f"起止时间: {report.scan.started_at} -> {report.scan.finished_at}")
    print(
        f"请求数: {stats.requests}  跳过: {stats.skipped}  "
        f"耗时: {stats.duration_ms} ms  发现: {stats.findings_total}"
    )
    if stats.by_plugin:
        detail = ", ".join(f"{name}={count}" for name, count in stats.by_plugin.items())
        print(f"插件命中: {detail}")
    if not report.findings:
        print("未发现漏洞。")
    for finding in report.findings:
        print(
            f"[{finding.severity}] {finding.plugin}  {finding.url}  "
            f"param={finding.parameter}  payload={finding.payload}"
        )
    print("=" * 72)
