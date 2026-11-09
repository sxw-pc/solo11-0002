"""内置插件集合：导入即注册（注册表见 scan_lab.plugin）。"""

from __future__ import annotations

from . import path_traversal, xss_reflect

__all__ = ["path_traversal", "xss_reflect"]
