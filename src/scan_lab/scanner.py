"""扫描编排：爬取 → 插件匹配 → 探测 → 去重 → 生成报告。

这里是 CLI 与各模块之间的粘合层，不包含任何具体检测逻辑。
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Sequence

from .config import ScanSettings, ensure_local_target
from .crawl import CrawlResult, Crawler
from .errors import FetchError, PluginError
from .http import HttpClient
from .plugin import Finding, available_plugins, get_plugin
from .report import Report, ScanMeta, ScanStats, dedupe_findings

logger = logging.getLogger(__name__)


def run_scan(
    target: str,
    settings: ScanSettings,
    plugin_names: Sequence[str],
) -> Report:
    """对本地靶场执行一次完整扫描，返回内存中的 Report。

    起始页不可达时抛出 FetchError；插件名未知时抛出 PluginError。
    单个后续页面或单次插件探测失败只计入 skipped，不中断扫描。
    """

    base_url = ensure_local_target(target)
    registry = available_plugins()
    unknown = [name for name in plugin_names if name not in registry]
    if unknown:
        raise PluginError(
            unknown[0],
            f"未知插件，可用插件: {', '.join(registry)}",
        )

    started_at = datetime.now(timezone.utc)
    clock = time.perf_counter()
    raw_findings: list[Finding] = []

    with HttpClient(settings.http) as client:
        plugins = [get_plugin(name, client) for name in plugin_names]
        crawler = Crawler(client, settings.crawl)
        # 起点失败会向上抛出，由 CLI 输出原因并以退出码 2 结束
        crawl_result: CrawlResult = crawler.crawl(base_url)
        skipped = len(crawl_result.skipped)

        for plugin in plugins:
            for page in crawl_result.pages:
                if not plugin.match(page):
                    continue
                try:
                    raw_findings.extend(plugin.run(page))
                except FetchError as exc:
                    logger.warning(
                        "插件 %s 探测 %s 失败，记入 skipped: %s",
                        plugin.name,
                        page.url,
                        exc.reason,
                    )
                    skipped += 1
                except PluginError as exc:
                    logger.warning(
                        "插件 %s 在 %s 执行失败，记入 skipped: %s",
                        plugin.name,
                        page.url,
                        exc.reason,
                    )
                    skipped += 1

        request_count = client.request_count

    findings = dedupe_findings(raw_findings)
    by_plugin: dict[str, int] = {name: 0 for name in plugin_names}
    for finding in findings:
        by_plugin[finding.plugin] = by_plugin.get(finding.plugin, 0) + 1

    finished_at = datetime.now(timezone.utc)
    duration_ms = int((time.perf_counter() - clock) * 1000)

    return Report(
        scan=ScanMeta(
            target=base_url,
            started_at=started_at.isoformat(timespec="seconds"),
            finished_at=finished_at.isoformat(timespec="seconds"),
            config=settings.model_dump(mode="json"),
        ),
        findings=findings,
        stats=ScanStats(
            requests=request_count,
            skipped=skipped,
            duration_ms=duration_ms,
            findings_total=len(findings),
            by_plugin=by_plugin,
        ),
    )
