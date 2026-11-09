"""HTTP 会话封装：超时、重试、UA、简单限速、请求计数。

每个扫描任务创建一个 HttpClient；插件之间共用同一个会话，但不共享可变插件状态。
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from types import TracebackType
from typing import Mapping

import requests

from .config import HttpSettings
from .errors import FetchError

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """一次成功请求的结果快照。"""

    method: str
    url: str
    status_code: int
    text: str
    headers: dict[str, str]
    elapsed_ms: int


class RateLimiter:
    """固定间隔限速：两次请求之间至少间隔 1/rate_limit 秒。"""

    def __init__(self, rate_limit: float) -> None:
        if rate_limit <= 0:
            raise ValueError("rate_limit 必须大于 0")
        self._interval = 1.0 / rate_limit
        self._last_request = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        delay = self._last_request + self._interval - now
        if delay > 0:
            time.sleep(delay)
        self._last_request = time.monotonic()


class HttpClient:
    """requests.Session 的薄封装。

    - 每次真实 HTTP 尝试都计入 ``request_count``（含重试）。
    - 所有 requests 异常统一转换为 FetchError，调用方不需要感知底层库。
    - 每个请求按 debug 级别记录 method/url/status/elapsed_ms。
    """

    def __init__(self, settings: HttpSettings) -> None:
        self._settings = settings
        self._limiter = RateLimiter(settings.rate_limit)
        self._session = requests.Session()
        self._session.headers.update(
            {
                "User-Agent": settings.user_agent,
                "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            }
        )
        self.request_count = 0

    def get(
        self,
        url: str,
        params: Mapping[str, str] | None = None,
    ) -> HttpResponse:
        return self.request("GET", url, params=params)

    def post(
        self,
        url: str,
        data: Mapping[str, str] | None = None,
    ) -> HttpResponse:
        return self.request("POST", url, data=data)

    def request(
        self,
        method: str,
        url: str,
        params: Mapping[str, str] | None = None,
        data: Mapping[str, str] | None = None,
    ) -> HttpResponse:
        attempts = self._settings.retries + 1
        last_reason = "未知错误"

        for attempt in range(1, attempts + 1):
            self._limiter.wait()
            started = time.perf_counter()
            self.request_count += 1
            try:
                response = self._session.request(
                    method=method,
                    url=url,
                    params=dict(params) if params else None,
                    data=dict(data) if data else None,
                    timeout=self._settings.timeout,
                    allow_redirects=True,
                )
            except requests.RequestException as exc:
                last_reason = f"{type(exc).__name__}: {exc}"
                logger.debug(
                    "请求失败（第 %d/%d 次） %s %s: %s",
                    attempt,
                    attempts,
                    method,
                    url,
                    last_reason,
                )
                continue

            elapsed_ms = int((time.perf_counter() - started) * 1000)
            logger.debug(
                "%s %s -> %s (%d ms)",
                method,
                response.url,
                response.status_code,
                elapsed_ms,
            )
            return HttpResponse(
                method=method,
                url=response.url,
                status_code=response.status_code,
                text=response.text,
                headers=dict(response.headers),
                elapsed_ms=elapsed_ms,
            )

        raise FetchError(url, f"{last_reason}（已重试 {attempts - 1} 次）")

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
