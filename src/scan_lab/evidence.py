"""证据组装：请求摘要、响应片段、cURL 复现命令。

插件通过这里生成可复核的文字证据，确保每条 finding 都能说明
"打了什么请求、响应里出现了什么"。
"""

from __future__ import annotations

import shlex
from typing import Mapping

DEFAULT_EXCERPT_LIMIT = 600
DEFAULT_MARKER_CONTEXT = 120


def excerpt(text: str, marker: str | None = None, limit: int = DEFAULT_EXCERPT_LIMIT) -> str:
    """截取响应片段；优先截取 marker 附近的上下文。

    返回内容会折叠连续空白，避免把整页 HTML 原样塞进报告。
    """

    if not text:
        return ""

    start = 0
    end = min(len(text), limit)
    if marker and marker in text:
        index = text.index(marker)
        start = max(0, index - DEFAULT_MARKER_CONTEXT)
        end = min(len(text), index + len(marker) + DEFAULT_MARKER_CONTEXT * 2)

    snippet = " ".join(text[start:end].split())
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    return f"{prefix}{snippet}{suffix}"


def build_evidence(
    method: str,
    url: str,
    status_code: int,
    body: str,
    marker: str | None = None,
) -> str:
    """生成一条 finding 的证据文本（请求行 + 响应片段）。"""

    return (
        f"请求: {method.upper()} {url} -> HTTP {status_code}\n"
        f"响应片段: {excerpt(body, marker)}"
    )


def build_curl(
    method: str,
    url: str,
    data: Mapping[str, str] | None = None,
) -> str:
    """生成可直接复现的 cURL 命令。"""

    parts: list[str] = ["curl", "-sS", "-i"]
    if method.upper() != "GET":
        parts.extend(["-X", method.upper()])
    if data:
        for key, value in data.items():
            parts.extend(["--data-urlencode", shlex.quote(f"{key}={value}")])
    parts.append(shlex.quote(url))
    return " ".join(parts)
