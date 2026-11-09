"""xss_reflect 插件测试：/search 命中、/files 不误报、无参数页面不匹配。"""

from __future__ import annotations

import pytest

from scan_lab.crawl import Page
from scan_lab.http import HttpClient
from scan_lab.plugin import get_plugin


def test_plugin_is_registered() -> None:
    from scan_lab.plugin import available_plugins

    assert "xss_reflect" in available_plugins()


def test_xss_hits_search_page(target_base_url: str, client: HttpClient) -> None:
    plugin = get_plugin("xss_reflect", client)
    page = Page(url=f"{target_base_url}/search?q=hello", params=["q"])

    assert plugin.match(page) is True
    findings = plugin.run(page)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.plugin == "xss_reflect"
    assert finding.severity == "high"
    assert finding.parameter == "q"
    assert finding.payload.startswith("<sl") and finding.payload.endswith(">")
    assert finding.payload in finding.evidence
    assert finding.repro_curl.startswith("curl")
    assert finding.confidence == "high"


def test_xss_does_not_false_positive_on_files_page(
    target_base_url: str,
    client: HttpClient,
) -> None:
    plugin = get_plugin("xss_reflect", client)
    page = Page(url=f"{target_base_url}/files?path=readme.txt", params=["path"])

    assert plugin.match(page) is True
    assert plugin.run(page) == []


def test_xss_skips_pages_without_params(target_base_url: str, client: HttpClient) -> None:
    plugin = get_plugin("xss_reflect", client)
    page = Page(url=f"{target_base_url}/login")

    assert plugin.match(page) is False
    assert plugin.run(page) == []


@pytest.mark.parametrize("parameter", ["q", "path", "id"])
def test_xss_matches_any_get_parameter(parameter: str, client: HttpClient) -> None:
    plugin = get_plugin("xss_reflect", client)
    page = Page(url=f"http://127.0.0.1:8000/probe?{parameter}=1", params=[parameter])
    assert plugin.match(page) is True
