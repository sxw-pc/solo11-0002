"""命令行入口（console_scripts: scan-lab）。

子命令：
    scan-lab serve-target --port 5001
    scan-lab scan --target http://127.0.0.1:5001 [--plugins ...] [--out ...]
    scan-lab plugins list

退出码约定：0 成功；2 配置/目标/插件错误或目标不可达；1 报告写入失败。
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Sequence

import typer

from .config import apply_overrides, ensure_local_target, load_settings
from .errors import ConfigError, FetchError, ParseError, PluginError
from .plugin import available_plugins
from .report import print_summary, write_report
from .scanner import run_scan

app = typer.Typer(
    help="scan-lab：本地 Web 漏洞扫描器（仅限自有/授权环境）",
    no_args_is_help=True,
    add_completion=False,
)
plugins_app = typer.Typer(help="插件管理", no_args_is_help=True)
app.add_typer(plugins_app, name="plugins")


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def _create_target_app(db_path: Path | None) -> Any:
    """加载 target 包并创建 Flask 应用。

    源码/editable 安装时把仓库根目录加入 sys.path，便于 ``target`` 包被导入。
    """

    root = Path(__file__).resolve().parents[2]
    if (root / "target" / "app.py").is_file() and str(root) not in sys.path:
        sys.path.insert(0, str(root))
    try:
        from target.app import create_app
    except ModuleNotFoundError as exc:
        raise ConfigError(
            "未找到 target 靶场包；请在仓库根目录执行 `pip install -e .` 后重试"
        ) from exc
    return create_app(db_path)


def _resolve_plugin_names(raw: str | None, defaults: Sequence[str]) -> list[str]:
    if raw is None or not raw.strip():
        return list(dict.fromkeys(defaults))
    names = [item.strip() for item in raw.split(",") if item.strip()]
    if not names:
        raise ConfigError("--plugins 不能为空")
    return list(dict.fromkeys(names))


@app.command("serve-target")
def serve_target(
    port: int = typer.Option(5001, "--port", "-p", min=1, max=65535, help="监听端口"),
    host: str = typer.Option("127.0.0.1", "--host", help="监听地址（只允许本机）"),
    db: Path | None = typer.Option(None, "--db", help="sqlite 数据库路径"),
) -> None:
    """启动内置的故意有漏洞靶场。"""

    _setup_logging(False)
    if host not in {"127.0.0.1", "localhost"}:
        typer.secho(f"拒绝启动：靶场只能监听本机，收到 {host}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)

    try:
        flask_app = _create_target_app(db)
    except ConfigError as exc:
        typer.secho(f"启动失败: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc

    typer.echo(f"靶场已启动: http://{host}:{port} （Ctrl+C 停止）")
    try:
        flask_app.run(host=host, port=port, debug=False, use_reloader=False)
    except OSError as exc:
        typer.secho(f"端口启动失败: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc


@app.command("scan")
def scan_command(
    target: str = typer.Option(..., "--target", "-t", help="靶场地址（仅 127.0.0.1）"),
    plugins: str | None = typer.Option(None, "--plugins", help="逗号分隔的插件名"),
    out: Path | None = typer.Option(None, "--out", help="报告输出路径"),
    config_path: Path | None = typer.Option(None, "--config", help="配置文件路径"),
    timeout: float | None = typer.Option(None, "--timeout", min=0.1, max=60.0),
    rate_limit: float | None = typer.Option(None, "--rate-limit", min=0.1, max=100.0),
    max_depth: int | None = typer.Option(None, "--max-depth", min=0, max=5),
    max_urls: int | None = typer.Option(None, "--max-urls", min=1, max=500),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="输出每个请求的 debug 日志"),
) -> None:
    """对本地靶场执行一次扫描并输出 JSON 报告。"""

    _setup_logging(verbose)
    try:
        settings = load_settings(config_path)
        settings = apply_overrides(
            settings,
            timeout=timeout,
            rate_limit=rate_limit,
            max_depth=max_depth,
            max_urls=max_urls,
        )
        ensure_local_target(target)
        plugin_names = _resolve_plugin_names(plugins, settings.plugins)
        report = run_scan(target, settings, plugin_names)
        report_path = write_report(report, out)
    except ConfigError as exc:
        typer.secho(f"配置错误: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc
    except PluginError as exc:
        typer.secho(f"插件错误: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc
    except (FetchError, ParseError) as exc:
        reason = getattr(exc, "reason", str(exc))
        url = getattr(exc, "url", target)
        typer.secho(f"目标不可达: {reason}（{url}）", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc
    except OSError as exc:
        typer.secho(f"报告写入失败: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc

    print_summary(report)
    typer.echo(f"报告已写入: {report_path}")


@plugins_app.command("list")
def list_plugins() -> None:
    """列出已注册插件。"""

    registry = available_plugins()
    typer.echo(f"{'NAME':<16}{'SEVERITY':<10}DESCRIPTION")
    for name in registry:
        plugin_cls = registry[name]
        typer.echo(f"{name:<16}{plugin_cls.severity:<10}{plugin_cls.description}")


if __name__ == "__main__":
    app()
