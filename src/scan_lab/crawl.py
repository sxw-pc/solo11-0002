"""同源 BFS 爬虫：提取链接、表单与查询参数。

只访问与起点同源（scheme + netloc 相同）的 http(s) 页面；
跳过 logout/delete 等危险路径；URL 统一规范化后去重。
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Sequence
from urllib.parse import (
    parse_qsl,
    quote_plus,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)

from bs4 import BeautifulSoup
from pydantic import BaseModel, ConfigDict, Field

from .config import CrawlSettings
from .errors import FetchError, ParseError
from .http import HttpClient

logger = logging.getLogger(__name__)


class Form(BaseModel):
    """页面中的一个表单。"""

    model_config = ConfigDict(extra="forbid")

    action: str
    method: str = "get"
    inputs: list[str] = Field(default_factory=list)


class Page(BaseModel):
    """爬虫产出的页面描述，供插件匹配与探测。"""

    model_config = ConfigDict(extra="forbid")

    url: str
    method: str = "GET"
    params: list[str] = Field(default_factory=list)
    forms: list[Form] = Field(default_factory=list)


class CrawlResult(BaseModel):
    """一次爬取的完整结果。"""

    model_config = ConfigDict(extra="forbid")

    pages: list[Page] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list)


def normalize_url(url: str, base: str | None = None) -> str | None:
    """规范化 URL：补全相对路径、去 fragment、排序 query、统一大小写。

    非 http(s) 链接（mailto:、javascript: 等）返回 None。
    """

    candidate = urljoin(base, url) if base else url
    parts = urlsplit(candidate.strip())
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        return None

    path = parts.path or "/"
    query_pairs = sorted(parse_qsl(parts.query, keep_blank_values=True))
    query = urlencode(query_pairs, doseq=True)
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, query, ""))


def same_origin(left: str, right: str) -> bool:
    """判断两个 URL 是否同源（scheme + netloc）。"""

    a = urlsplit(left)
    b = urlsplit(right)
    return a.scheme.lower() == b.scheme.lower() and a.netloc.lower() == b.netloc.lower()


def query_params(url: str) -> list[str]:
    """按出现顺序返回去重后的查询参数名。"""

    names: list[str] = []
    for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if key not in names:
            names.append(key)
    return names


def is_dangerous(url: str, keywords: Sequence[str]) -> bool:
    """路径中包含危险关键字（logout/delete 等）时返回 True。"""

    path = urlsplit(url).path.lower()
    return any(keyword.lower() in path for keyword in keywords if keyword)


def set_query_param(url: str, name: str, value: str, *, encode: bool = True) -> str:
    """替换 URL 中某个查询参数的值。

    ``encode=True`` 时按标准规则编码（XSS 标记用）；
    ``encode=False`` 时原样拼接，便于发送 ``..%2f`` 这类已编码 payload。
    """

    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    rendered: list[str] = []
    replaced = False
    for key, old_value in pairs:
        if key == name and not replaced:
            raw = quote_plus(value) if encode else value
            rendered.append(f"{quote_plus(key)}={raw}")
            replaced = True
        else:
            rendered.append(f"{quote_plus(key)}={quote_plus(old_value)}")
    if not replaced:
        raw = quote_plus(value) if encode else value
        rendered.append(f"{quote_plus(name)}={raw}")
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(rendered), ""))


def parse_html(text: str, url: str) -> BeautifulSoup:
    """把响应文本解析为 BeautifulSoup；空响应视为解析失败。"""

    if not text.strip():
        raise ParseError(url, "响应体为空，无法解析")
    try:
        return BeautifulSoup(text, "html.parser")
    except (ValueError, AssertionError) as exc:
        raise ParseError(url, f"HTML 解析失败: {exc}") from exc


def extract_forms(soup: BeautifulSoup, page_url: str) -> list[Form]:
    """提取 form[action][method] 及其 input/select/textarea 的 name。"""

    forms: list[Form] = []
    for node in soup.find_all("form"):
        action_raw = node.get("action") or page_url
        action = normalize_url(str(action_raw), page_url) or page_url
        method = str(node.get("method") or "get").lower()
        names: list[str] = []
        for field in node.find_all(["input", "select", "textarea"]):
            name = field.get("name")
            if name and str(name) not in names:
                names.append(str(name))
        forms.append(Form(action=action, method=method, inputs=names))
    return forms


def extract_links(soup: BeautifulSoup) -> list[str]:
    """提取页面中的 a[href]。"""

    links: list[str] = []
    for anchor in soup.find_all("a", href=True):
        href = anchor.get("href")
        if href:
            links.append(str(href))
    return links


class Crawler:
    """同源 BFS 爬虫。

    起点页面访问失败会直接抛出 FetchError（由调用方决定退出码 2）；
    后续页面失败只记入 ``skipped`` 并继续。
    """

    def __init__(self, client: HttpClient, settings: CrawlSettings) -> None:
        self._client = client
        self._settings = settings

    def crawl(self, start_url: str) -> CrawlResult:
        start = normalize_url(start_url)
        if start is None:
            raise ParseError(start_url, "起始 URL 不是合法的 http(s) 地址")

        start_page, start_links = self._visit(start)
        pages: list[Page] = [start_page]
        skipped: list[str] = []
        visited: set[str] = {start}
        queue: deque[tuple[str, int]] = deque()

        self._enqueue(queue, visited, start_links, start, depth=1)

        while queue and len(pages) < self._settings.max_urls:
            url, depth = queue.popleft()
            try:
                page, links = self._visit(url)
            except (FetchError, ParseError) as exc:
                logger.warning("跳过 %s: %s", url, exc)
                skipped.append(url)
                continue

            pages.append(page)
            if depth >= self._settings.max_depth:
                continue
            self._enqueue(queue, visited, links, url, depth=depth + 1)

        if len(pages) >= self._settings.max_urls:
            logger.info("达到 max_urls=%d 上限，停止爬取", self._settings.max_urls)
        return CrawlResult(pages=pages, skipped=skipped)

    def _visit(self, url: str) -> tuple[Page, list[str]]:
        response = self._client.get(url)
        soup = parse_html(response.text, url)
        page = Page(
            url=url,
            method="GET",
            params=query_params(url),
            forms=extract_forms(soup, url),
        )
        return page, extract_links(soup)

    def _enqueue(
        self,
        queue: deque[tuple[str, int]],
        visited: set[str],
        links: Sequence[str],
        base_url: str,
        *,
        depth: int,
    ) -> None:
        if depth > self._settings.max_depth:
            return
        for link in links:
            candidate = normalize_url(link, base_url)
            if candidate is None:
                continue
            if not same_origin(candidate, base_url):
                continue
            if is_dangerous(candidate, self._settings.skip_keywords):
                logger.debug("跳过危险路径: %s", candidate)
                continue
            if candidate in visited:
                continue
            visited.add(candidate)
            queue.append((candidate, depth))
