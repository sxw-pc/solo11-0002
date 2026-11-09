"""CLI 冒烟测试：插件列表、端到端扫描、错误退出码。"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from scan_lab.cli import app

runner = CliRunner()


def _combined_output(result: object) -> str:
    stdout = getattr(result, "stdout", "") or ""
    stderr = getattr(result, "stderr", "") or ""
    output = getattr(result, "output", "") or ""
    return f"{output}\n{stdout}\n{stderr}"


def test_plugins_list_shows_two_builtins() -> None:
    result = runner.invoke(app, ["plugins", "list"])

    assert result.exit_code == 0
    assert "xss_reflect" in result.output
    assert "path_traversal" in result.output


def test_scan_end_to_end_writes_report(target_base_url: str, tmp_path: Path) -> None:
    out = tmp_path / "scan.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            target_base_url,
            "--plugins",
            "xss_reflect,path_traversal",
            "--out",
            str(out),
            "--rate-limit",
            "100",
        ],
    )

    assert result.exit_code == 0, _combined_output(result)
    assert out.is_file()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["stats"]["findings_total"] >= 2
    assert "报告已写入" in result.output
    assert "[high]" in result.output


def test_unknown_plugin_exits_with_code_2(target_base_url: str, tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            target_base_url,
            "--plugins",
            "not_exists",
            "--out",
            str(tmp_path / "r.json"),
        ],
    )

    assert result.exit_code == 2
    assert "未知插件" in _combined_output(result)


def test_unreachable_target_exits_with_code_2(closed_port: int, tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            f"http://127.0.0.1:{closed_port}",
            "--out",
            str(tmp_path / "r.json"),
            "--timeout",
            "0.5",
        ],
    )

    combined = _combined_output(result)
    assert result.exit_code == 2
    assert "Traceback" not in combined
    assert "不可达" in combined


def test_non_local_target_is_rejected(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "http://192.0.2.10:8080",
            "--out",
            str(tmp_path / "r.json"),
        ],
    )

    combined = _combined_output(result)
    assert result.exit_code == 2
    assert "本地" in combined
