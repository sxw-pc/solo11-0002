"""path_traversal 插件测试：/files 命中、非文件参数不匹配、编码变体存在。"""

from __future__ import annotations

from scan_lab.crawl import Page
from scan_lab.http import HttpClient
from scan_lab.plugin import get_plugin
from scan_lab.plugins.path_traversal import PAYLOADS


def test_payloads_cover_plain_and_encoded_forms() -> None:
    assert "../../etc/passwd" in PAYLOADS
    assert any("%2f" in payload for payload in PAYLOADS)
    assert any("....//" in payload for payload in PAYLOADS)


def test_traversal_hits_files_page(target_base_url: str, client: HttpClient) -> None:
    plugin = get_plugin("path_traversal", client)
    page = Page(url=f"{target_base_url}/files?path=readme.txt", params=["path"])

    assert plugin.match(page) is True
    findings = plugin.run(page)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.plugin == "path_traversal"
    assert finding.severity == "high"
    assert finding.parameter == "path"
    assert finding.payload in PAYLOADS
    assert "root:" in finding.evidence
    assert finding.payload in finding.evidence or "%2f" in finding.evidence
    assert finding.repro_curl.startswith("curl")


def test_traversal_skips_non_file_parameters(client: HttpClient) -> None:
    plugin = get_plugin("path_traversal", client)
    page = Page(url="http://127.0.0.1:8000/search?q=hello", params=["q"])

    assert plugin.match(page) is False
    assert plugin.run(page) == []


def test_traversal_handles_upload_style_parameter(client: HttpClient) -> None:
    plugin = get_plugin("path_traversal", client)
    page = Page(url="http://127.0.0.1:8000/download?file=x", params=["file"])
    assert plugin.match(page) is True
