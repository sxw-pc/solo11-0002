"""pytest 公共 fixture：在随机端口启动内置靶场，使用临时数据库。

测试不依赖 reports/ 残留，也不访问外网。
"""

from __future__ import annotations

import logging
import socket
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
for _path in (REPO_ROOT, REPO_ROOT / "src"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from scan_lab.config import CrawlSettings, HttpSettings, ScanSettings  # noqa: E402
from scan_lab.http import HttpClient  # noqa: E402

FAST_HTTP = HttpSettings(timeout=3.0, retries=0, rate_limit=100.0)
FAST_CRAWL = CrawlSettings(max_depth=2, max_urls=50)


def _wait_until_ready(base_url: str, attempts: int = 100) -> None:
    for _ in range(attempts):
        try:
            requests.get(f"{base_url}/", timeout=0.5)
            return
        except requests.RequestException:
            time.sleep(0.05)
    raise RuntimeError(f"靶场未能在预期时间内启动: {base_url}")


@pytest.fixture(scope="session")
def target_base_url(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """启动 Flask 靶场（随机端口 + 临时 sqlite），整个测试会话复用。"""

    from werkzeug.serving import make_server

    from target.app import create_app

    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    db_path = tmp_path_factory.mktemp("target-db") / "scan_lab.db"
    flask_app = create_app(db_path)
    server = make_server("127.0.0.1", 0, flask_app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, name="scan-lab-target", daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{server.server_port}"
    _wait_until_ready(base_url)
    try:
        yield base_url
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture()
def settings() -> ScanSettings:
    return ScanSettings(http=FAST_HTTP, crawl=FAST_CRAWL)


@pytest.fixture()
def client() -> Iterator[HttpClient]:
    with HttpClient(FAST_HTTP) as http_client:
        yield http_client


@pytest.fixture()
def closed_port() -> int:
    """返回一个刚释放、大概率无人监听的本地端口。"""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
