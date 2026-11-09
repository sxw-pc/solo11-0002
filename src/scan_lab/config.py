"""扫描配置：加载 ``config/scan.yaml``，用 pydantic 做强校验。

CLI 参数可以覆盖这里的 HTTP / 爬虫字段，但覆盖后的结果仍走同一套模型校验。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .errors import ConfigError

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "scan.yaml"
LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class HttpSettings(BaseModel):
    """HTTP 会话参数。"""

    model_config = ConfigDict(extra="forbid")

    timeout: float = Field(default=5.0, gt=0, le=60)
    retries: int = Field(default=2, ge=0, le=5)
    rate_limit: float = Field(default=5.0, gt=0, le=100)
    user_agent: str = Field(
        default="scan-lab/0.1 (local-lab; authorized use only)",
        min_length=1,
        max_length=200,
    )


class CrawlSettings(BaseModel):
    """同源 BFS 爬虫参数。"""

    model_config = ConfigDict(extra="forbid")

    max_depth: int = Field(default=2, ge=0, le=5)
    max_urls: int = Field(default=50, ge=1, le=500)
    skip_keywords: list[str] = Field(
        default_factory=lambda: ["logout", "delete", "signout"],
        max_length=20,
    )


class ScanSettings(BaseModel):
    """一次扫描的完整配置。"""

    model_config = ConfigDict(extra="forbid")

    http: HttpSettings = Field(default_factory=HttpSettings)
    crawl: CrawlSettings = Field(default_factory=CrawlSettings)
    plugins: list[str] = Field(default_factory=lambda: ["xss_reflect", "path_traversal"])


def load_settings(config_path: Path | None = None) -> ScanSettings:
    """读取 YAML 配置；文件不存在时返回默认配置。

    显式传入的路径不存在、YAML 语法错误或字段校验失败时抛出 ConfigError。
    """

    if config_path is None:
        if not DEFAULT_CONFIG_PATH.is_file():
            return ScanSettings()
        path = DEFAULT_CONFIG_PATH
    else:
        path = Path(config_path)
        if not path.is_file():
            raise ConfigError(f"配置文件不存在: {path}")

    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"读取配置失败: {path}: {exc}") from exc

    try:
        data: Any = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"配置文件不是合法 YAML: {path}: {exc}") from exc

    if data is None:
        return ScanSettings()
    if not isinstance(data, dict):
        raise ConfigError(f"配置文件顶层必须是映射: {path}")

    try:
        return ScanSettings.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"配置字段校验失败: {path}: {exc}") from exc


def apply_overrides(
    settings: ScanSettings,
    *,
    timeout: float | None = None,
    rate_limit: float | None = None,
    max_depth: int | None = None,
    max_urls: int | None = None,
) -> ScanSettings:
    """把 CLI 上显式提供的参数合并进配置。"""

    http_update: dict[str, float] = {}
    crawl_update: dict[str, int] = {}
    if timeout is not None:
        http_update["timeout"] = timeout
    if rate_limit is not None:
        http_update["rate_limit"] = rate_limit
    if max_depth is not None:
        crawl_update["max_depth"] = max_depth
    if max_urls is not None:
        crawl_update["max_urls"] = max_urls

    http = settings.http.model_copy(update=http_update) if http_update else settings.http
    crawl = settings.crawl.model_copy(update=crawl_update) if crawl_update else settings.crawl
    if not http_update and not crawl_update:
        return settings
    return settings.model_copy(update={"http": http, "crawl": crawl})


def ensure_local_target(target: str) -> str:
    """校验目标只指向本机，返回去掉末尾斜杠的地址。

    这是硬约束：扫描器只允许 127.0.0.1 / localhost / ::1。
    """

    candidate = target.strip()
    if not candidate:
        raise ConfigError("--target 不能为空")

    parts = urlsplit(candidate)
    if parts.scheme not in {"http", "https"}:
        raise ConfigError(f"目标必须是 http(s) 地址: {target}")
    if parts.hostname is None:
        raise ConfigError(f"目标缺少主机名: {target}")
    if parts.hostname.lower() not in LOCAL_HOSTS:
        raise ConfigError(
            f"只允许扫描本地靶场（127.0.0.1/localhost/::1），拒绝: {parts.hostname}"
        )
    return candidate.rstrip("/") or candidate
