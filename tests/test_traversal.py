"""path_traversal 插件测试：/files 命中、非文件参数不匹配、编码变体存在。"""

from __future__ import annotations

import pytest

from scan_lab.crawl import Page
from scan_lab.http import HttpClient
from scan_lab.plugin import get_plugin
from scan_lab.plugins.path_traversal import (
    ENCODING_VARIANTS,
    PAYLOADS,
    PathTraversalPlugin,
)


def test_payloads_cover_plain_and_encoded_forms() -> None:
    assert "../../etc/passwd" in PAYLOADS
    # 单次编码：只编码斜杠（..%2f）与点斜杠全编码（%2e%2e%2f）
    assert any("%2f" in payload for payload in PAYLOADS)
    assert any("%2e%2e%2f" in payload for payload in PAYLOADS)
    # 双重编码：%252f（二次解码后才变成 %2f）与全双重编码 %252e%252e%252f
    assert any("%252f" in payload for payload in PAYLOADS)
    assert any("%252e%252e%252f" in payload for payload in PAYLOADS)
    # 双写绕过前缀仍被保留
    assert any("....//" in payload for payload in PAYLOADS)
    # 编码变体是可组合部件，明文 / 单编码 / 双重编码三档都在
    assert {name for name, _ in ENCODING_VARIANTS} >= {
        "plain",
        "slash_encoded",
        "full_encoded",
        "double_encoded_slash",
        "double_encoded_full",
    }
    assert len(PAYLOADS) == len(set(PAYLOADS))


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


def test_traversal_detects_double_encoded_payload(
    target_base_url: str,
    client: HttpClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """双重编码（..%252f / %252e%252e%252f）必须能命中二次解码的注入点。

    把 payload 列表收窄为双重编码变体，确保命中不是靠明文/单编码变体
    提前 break 得到的。
    """

    double_only = tuple(
        payload for payload in PAYLOADS if "%252f" in payload or "%252e" in payload
    )
    assert double_only  # 至少要有一条双重编码 payload 可验证
    monkeypatch.setattr(
        "scan_lab.plugins.path_traversal.PAYLOADS", double_only, raising=True
    )

    plugin = get_plugin("path_traversal", client)
    page = Page(url=f"{target_base_url}/files?path=readme.txt", params=["path"])
    findings = plugin.run(page)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "high"
    assert finding.parameter == "path"
    assert "%252f" in finding.payload or "%252e" in finding.payload
    assert "root:" in finding.evidence


def test_traversal_skips_non_file_parameters(client: HttpClient) -> None:
    plugin = get_plugin("path_traversal", client)
    page = Page(url="http://127.0.0.1:8000/search?q=hello", params=["q"])

    assert plugin.match(page) is False
    assert plugin.run(page) == []


def test_traversal_zero_requests_without_path_parameter(
    target_base_url: str,
    client: HttpClient,
) -> None:
    """不带 path/file 参数的页面必须零请求、零发现（不产生误报）。"""

    plugin = get_plugin("path_traversal", client)
    page = Page(url=f"{target_base_url}/profile?id=1", params=["id"])

    assert plugin.match(page) is False
    before = client.request_count
    assert plugin.run(page) == []
    assert client.request_count == before


def test_detect_requires_target_file_markers() -> None:
    """只有响应包含目标文件特征（root: 或 passwd 条目格式）才判定命中。"""

    assert PathTraversalPlugin._detect("<html>root:x:0:0:decoy:/root:/bin/sh</html>")
    assert PathTraversalPlugin._detect("daemon:x:1:1::/usr/sbin:/usr/sbin/nologin")
    assert PathTraversalPlugin._detect("alice:x:1000:1000::/home/alice:/bin/bash")
    # 普通 404 页面、提示文本、不含 passwd 条目的正文都不算命中
    assert PathTraversalPlugin._detect("<p>文件不存在。</p>") is None
    assert PathTraversalPlugin._detect("root directory listing is empty") is None
    assert PathTraversalPlugin._detect("") is None


def test_traversal_handles_upload_style_parameter(client: HttpClient) -> None:
    plugin = get_plugin("path_traversal", client)
    page = Page(url="http://127.0.0.1:8000/download?file=x", params=["file"])
    assert plugin.match(page) is True
