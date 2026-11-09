"""反射型 XSS 检测插件。

原理：为每个 GET 参数注入一个带尖括号的唯一标记，若响应体中
出现"未转义"的原始标记，即判定为反射型 XSS。标记只含安全字符，
因此正常转义的页面不会命中。
"""

from __future__ import annotations

import secrets

from ..crawl import Page, set_query_param
from ..plugin import Finding, Plugin, register_plugin


@register_plugin
class XssReflectPlugin(Plugin):
    """GET 参数反射检测。"""

    name = "xss_reflect"
    severity = "high"
    confidence = "high"
    description = "检测 GET 参数是否将输入未转义地反射到响应中"

    def match(self, page: Page) -> bool:
        return page.method.upper() == "GET" and bool(page.params)

    def run(self, page: Page) -> list[Finding]:
        findings: list[Finding] = []
        for parameter in page.params:
            token = secrets.token_hex(4)
            marker = f"<sl{token}>"
            url = set_query_param(page.url, parameter, marker, encode=True)
            response = self._client.get(url)
            # 只看原始标记：如果页面做了 HTML 转义，响应里只会出现 &lt;sl...&gt;
            if marker not in response.text:
                continue
            findings.append(
                self.make_finding(
                    url=url,
                    parameter=parameter,
                    payload=marker,
                    status_code=response.status_code,
                    body=response.text,
                    marker=marker,
                )
            )
        return findings
