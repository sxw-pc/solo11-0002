"""靶场种子数据：建库、3 个用户、5 篇帖子。

用法：
    python -m target.seed [--db PATH]

数据库默认落在 target/scan_lab.db（已被 .gitignore 忽略）。
所有账号与口令均为演示用的虚构数据，不包含任何真实凭据。
"""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "scan_lab.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    FOREIGN KEY (author_id) REFERENCES users (id)
);
"""

# (username, password, email, role) —— 口令为明文，属靶场故意设计。
USERS: list[tuple[str, str, str, str]] = [
    ("alice", "alice-demo-pw", "alice@example.test", "user"),
    ("bob", "bob-demo-pw", "bob@example.test", "user"),
    ("admin", "admin-demo-pw", "admin@example.test", "admin"),
]

# (author_username, title, body)
POSTS: list[tuple[str, str, str]] = [
    ("alice", "欢迎来到 scan-lab", "这里是本地漏洞靶场的第一篇帖子。"),
    ("alice", "爬虫与深度", "同源 BFS 默认深度为 2，最多访问 50 个 URL。"),
    ("bob", "关于报告格式", "报告是 JSON，终端只打印摘要，不含可视化看板。"),
    ("bob", "插件怎么扩展", "在 plugins 目录新增模块并调用 register_plugin 即可。"),
    ("admin", "仅限本地测试", "请勿将本靶场暴露到公网，也不要用于未授权目标。"),
]


def init_db(db_path: Path | None = None) -> Path:
    """创建表并写入种子数据；重复执行不会产生重复数据。"""

    path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA)
        existing = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if existing == 0:
            conn.executemany(
                "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                USERS,
            )
        post_count = conn.execute("SELECT COUNT(*) FROM posts").fetchone()[0]
        if post_count == 0:
            ids = {
                row[1]: row[0]
                for row in conn.execute("SELECT id, username FROM users").fetchall()
            }
            conn.executemany(
                "INSERT INTO posts (author_id, title, body) VALUES (?, ?, ?)",
                [(ids[name], title, body) for name, title, body in POSTS],
            )
        conn.commit()
    return path


def ensure_seeded(db_path: Path | None = None) -> Path:
    """确保数据库可用：不存在则建库并写入种子数据。"""

    return init_db(db_path)


def main() -> int:
    parser = argparse.ArgumentParser(description="初始化 scan-lab 靶场数据库")
    parser.add_argument("--db", type=Path, default=None, help="sqlite 数据库路径")
    args = parser.parse_args()

    path = init_db(args.db)
    with sqlite3.connect(path) as conn:
        users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        posts = conn.execute("SELECT COUNT(*) FROM posts").fetchone()[0]
    print(f"数据库就绪: {path}")
    print(f"用户: {users} 条，帖子: {posts} 条")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
