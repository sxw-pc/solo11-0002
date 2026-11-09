"""爬虫测试：同源、去重、深度/数量上限、表单与参数提取、URL 规范化。"""

from __future__ import annotations

from scan_lab.config import CrawlSettings
from scan_lab.crawl import (
    Crawler,
    is_dangerous,
    normalize_url,
    query_params,
    same_origin,
    set_query_param,
)
from scan_lab.http import HttpClient


def test_normalize_url_removes_fragment_and_sorts_query() -> None:
    assert (
        normalize_url("HTTP://Example.test:80/a?b=2&a=1#frag")
        == "http://example.test:80/a?a=1&b=2"
    )
    assert normalize_url("http://example.test") == "http://example.test/"


def test_normalize_url_rejects_non_http() -> None:
    assert normalize_url("mailto:someone@example.test") is None
    assert normalize_url("javascript:void(0)") is None
    assert normalize_url("data:text/html,hi") is None
    # 纯 fragment 链接会解析回当前页面
    assert normalize_url("#section", "http://127.0.0.1:8000/") == "http://127.0.0.1:8000/"


def test_query_helpers() -> None:
    url = "http://127.0.0.1:8000/search?q=hello&lang=zh&q=again"
    assert query_params(url) == ["q", "lang"]
    assert same_origin(url, "http://127.0.0.1:8000/files") is True
    assert same_origin(url, "http://127.0.0.1:9999/files") is False
    assert is_dangerous("http://127.0.0.1:8000/logout", ["logout"]) is True


def test_set_query_param_supports_encoded_payload() -> None:
    base = "http://127.0.0.1:8000/files?path=readme.txt"
    encoded = set_query_param(base, "path", "..%2f..%2fetc%2fpasswd", encode=False)
    assert "%2f" in encoded
    normal = set_query_param(base, "path", "<marker>", encode=True)
    assert "%3Cmarker%3E" in normal


def test_crawl_finds_at_least_six_same_origin_urls(
    target_base_url: str,
    client: HttpClient,
) -> None:
    crawler = Crawler(client, CrawlSettings(max_depth=2, max_urls=50))
    result = crawler.crawl(target_base_url)
    urls = [page.url for page in result.pages]

    assert len(urls) >= 6
    assert len(urls) == len(set(urls))
    assert all(url.startswith(target_base_url) for url in urls)
    assert result.skipped == []


def test_crawl_extracts_forms_and_query_params(
    target_base_url: str,
    client: HttpClient,
) -> None:
    crawler = Crawler(client, CrawlSettings(max_depth=2, max_urls=50))
    result = crawler.crawl(target_base_url)

    home = next(page for page in result.pages if page.url == f"{target_base_url}/")
    actions = {form.action for form in home.forms}
    assert f"{target_base_url}/search" in actions
    assert f"{target_base_url}/login" in actions

    login_form = next(form for form in home.forms if form.action.endswith("/login"))
    assert login_form.method == "post"
    assert login_form.inputs == ["username", "password"]

    search_page = next(
        page for page in result.pages if page.url.endswith("/search?q=hello")
    )
    assert search_page.params == ["q"]


def test_crawl_respects_depth_and_url_limits(
    target_base_url: str,
    client: HttpClient,
) -> None:
    shallow = Crawler(client, CrawlSettings(max_depth=0, max_urls=50)).crawl(target_base_url)
    assert len(shallow.pages) == 1

    limited = Crawler(client, CrawlSettings(max_depth=2, max_urls=3)).crawl(target_base_url)
    assert len(limited.pages) == 3
