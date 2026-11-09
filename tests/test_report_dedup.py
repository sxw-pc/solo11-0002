"""报告与去重测试：字段完整性、去重键、两次扫描结果一致。"""

from __future__ import annotations

import json
from pathlib import Path

from scan_lab.config import ScanSettings
from scan_lab.plugin import Finding
from scan_lab.report import dedupe_findings, write_report
from scan_lab.scanner import run_scan


def _finding(url: str = "http://127.0.0.1:8000/search?q=1", payload: str = "p1") -> Finding:
    return Finding(
        plugin="xss_reflect",
        severity="high",
        url=url,
        parameter="q",
        payload=payload,
        evidence="请求: GET / -> HTTP 200\n响应片段: ...",
        repro_curl="curl -sS -i 'http://127.0.0.1:8000/search?q=1'",
        confidence="high",
    )


def test_dedupe_keeps_first_finding_per_key() -> None:
    first = _finding(payload="p1")
    duplicate = _finding(payload="p2")
    other_param = Finding(
        plugin="xss_reflect",
        severity="high",
        url=first.url,
        parameter="id",
        payload="p3",
        evidence="e",
        repro_curl="curl",
    )

    unique = dedupe_findings([first, duplicate, other_param])

    assert len(unique) == 2
    assert unique[0].payload == "p1"
    assert {item.parameter for item in unique} == {"q", "id"}


def test_scan_twice_yields_same_findings(
    target_base_url: str,
    settings: ScanSettings,
) -> None:
    first = run_scan(target_base_url, settings, ["xss_reflect", "path_traversal"])
    second = run_scan(target_base_url, settings, ["xss_reflect", "path_traversal"])

    assert first.stats.findings_total == len(first.findings)
    assert len(first.findings) == len(second.findings)
    assert {finding.plugin for finding in first.findings} == {
        "xss_reflect",
        "path_traversal",
    }

    keys = [(item.plugin, item.url, item.parameter) for item in first.findings]
    assert len(keys) == len(set(keys))
    assert first.stats.by_plugin["xss_reflect"] >= 1
    assert first.stats.by_plugin["path_traversal"] >= 1
    assert first.stats.requests > 0


def test_report_json_has_complete_fields(
    tmp_path: Path,
    target_base_url: str,
    settings: ScanSettings,
) -> None:
    report = run_scan(target_base_url, settings, ["xss_reflect", "path_traversal"])
    out = write_report(report, tmp_path / "nested" / "scan.json")

    data = json.loads(out.read_text(encoding="utf-8"))

    assert set(data) == {"scan", "findings", "stats"}
    assert set(data["scan"]) == {"target", "started_at", "finished_at", "config"}
    assert set(data["stats"]) == {
        "requests",
        "skipped",
        "duration_ms",
        "findings_total",
        "by_plugin",
    }
    assert data["scan"]["target"] == target_base_url
    assert data["stats"]["findings_total"] == len(data["findings"])
    assert data["stats"]["duration_ms"] >= 0

    finding_fields = {
        "plugin",
        "severity",
        "url",
        "parameter",
        "payload",
        "evidence",
        "repro_curl",
        "confidence",
    }
    for finding in data["findings"]:
        assert set(finding) == finding_fields


def test_default_report_path_shape() -> None:
    from scan_lab.report import default_report_path

    path = default_report_path()
    assert path.parent.name == "reports"
    assert path.name.startswith("scan-")
    assert path.suffix == ".json"
