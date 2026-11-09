"""scan-lab 抛出的异常分层。

所有自定义异常都继承 ScanLabError，调用方可以按层捕获，
避免出现裸的 ``except Exception``。
"""

from __future__ import annotations


class ScanLabError(Exception):
    """项目内所有自定义异常的基类。"""


class ConfigError(ScanLabError):
    """配置加载、参数校验失败（例如目标不是本地地址）。"""


class FetchError(ScanLabError):
    """HTTP 请求失败：超时、连接拒绝、DNS 解析失败等。"""

    def __init__(self, url: str, reason: str) -> None:
        self.url = url
        self.reason = reason
        super().__init__(f"{url}: {reason}")


class ParseError(ScanLabError):
    """页面解析失败：空响应、非法起始 URL、HTML 无法解析等。"""

    def __init__(self, url: str, reason: str) -> None:
        self.url = url
        self.reason = reason
        super().__init__(f"{url}: {reason}")


class PluginError(ScanLabError):
    """插件执行失败或插件注册表查询失败。"""

    def __init__(self, plugin: str, reason: str) -> None:
        self.plugin = plugin
        self.reason = reason
        super().__init__(f"{plugin}: {reason}")
