"""插件框架：Finding 模型、Plugin 基类与注册表。

新插件只需：
1. 继承 ``Plugin``，声明 ``name`` / ``severity`` / ``description``；
2. 实现 ``match(page)`` 与 ``run(page)``；
3. 用 ``@register_plugin`` 装饰，并在 ``scan_lab.plugins`` 中被导入。
"""

from __future__ import annotations

import importlib
from abc import ABC, abstractmethod
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict

from .crawl import Page
from .errors import PluginError
from .evidence import build_curl, build_evidence
from .http import HttpClient

Severity = Literal["info", "low", "medium", "high"]
Confidence = Literal["low", "medium", "high"]


class Finding(BaseModel):
    """一条漏洞发现；字段与报告 JSON 一一对应。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plugin: str
    severity: Severity
    url: str
    parameter: str
    payload: str
    evidence: str
    repro_curl: str
    confidence: Confidence = "medium"


class Plugin(ABC):
    """插件基类。

    - ``match(page)``：只做轻量判断，不发请求；
    - ``run(page)``：真正探测并返回 Finding 列表；
    - 构造函数接收本次扫描共享的 HttpClient，插件自身不保存可变全局状态。
    """

    name: ClassVar[str]
    severity: ClassVar[Severity] = "medium"
    confidence: ClassVar[Confidence] = "medium"
    description: ClassVar[str] = ""

    def __init__(self, client: HttpClient) -> None:
        self._client = client

    @abstractmethod
    def match(self, page: Page) -> bool:
        """该页面是否值得交给本插件探测。"""

    @abstractmethod
    def run(self, page: Page) -> list[Finding]:
        """执行探测；网络失败时允许抛出 FetchError，由扫描器统一记录为 skipped。"""

    def make_finding(
        self,
        *,
        url: str,
        parameter: str,
        payload: str,
        status_code: int,
        body: str,
        marker: str | None = None,
    ) -> Finding:
        """按当前插件的 name/severity/confidence 组装 Finding。"""

        return Finding(
            plugin=self.name,
            severity=self.severity,
            url=url,
            parameter=parameter,
            payload=payload,
            evidence=build_evidence("GET", url, status_code, body, marker),
            repro_curl=build_curl("GET", url),
            confidence=self.confidence,
        )


_REGISTRY: dict[str, type[Plugin]] = {}


def register_plugin(cls: type[Plugin]) -> type[Plugin]:
    """把插件类注册进全局表；名字重复或缺少元信息时直接报错。"""

    if not getattr(cls, "name", ""):
        raise PluginError(cls.__name__, "插件缺少 name")
    if getattr(cls, "severity", None) not in {"info", "low", "medium", "high"}:
        raise PluginError(cls.name, "插件 severity 非法")
    if cls.name in _REGISTRY:
        raise PluginError(cls.name, "插件名重复注册")
    _REGISTRY[cls.name] = cls
    return cls


def _load_builtins() -> None:
    """导入内置插件包，触发装饰器注册。"""

    if not _REGISTRY:
        importlib.import_module(f"{__package__}.plugins")


def available_plugins() -> dict[str, type[Plugin]]:
    """返回按名字排序的插件表（副本）。"""

    _load_builtins()
    if not _REGISTRY:
        raise PluginError("registry", "没有发现任何插件")
    return {name: _REGISTRY[name] for name in sorted(_REGISTRY)}


def get_plugin(name: str, client: HttpClient) -> Plugin:
    """按名字实例化插件；未知名字抛出 PluginError。"""

    registry = available_plugins()
    if name not in registry:
        known = ", ".join(registry)
        raise PluginError(name, f"未知插件，可用插件: {known}")
    return registry[name](client)
