"""scan-lab 故意有漏洞的本地靶场（Flask）。

警告：本应用故意包含反射型 XSS、路径穿越、SQL 注入、越权访问等问题，
只允许在 127.0.0.1 上用于自有/授权环境的扫描器回归测试，禁止暴露到公网。

可用入口：
    scan-lab serve-target --port 5001
    python -m target.app
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import Flask, Response, current_app, request

from target.seed import DEFAULT_DB_PATH, ensure_seeded

FILES_DIR = Path(__file__).resolve().parent / "files"


def _layout(title: str, body: str) -> str:
    """统一的页面骨架；导航里的链接是爬虫的主要入口。"""

    return f"""<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>{title} - scan-lab 靶场</title></head>
<body>
<header>
  <h1>scan-lab 靶场</h1>
  <nav>
    <a href="/">首页</a>
    <a href="/search?q=hello">搜索</a>
    <a href="/files?path=readme.txt">文件</a>
    <a href="/profile?id=1">用户 1</a>
    <a href="/profile?id=2">用户 2</a>
    <a href="/login">登录</a>
  </nav>
</header>
<main>{body}</main>
<footer><p>仅限本地测试，请勿用于未授权目标。</p></footer>
</body>
</html>"""


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(current_app.config["SCAN_LAB_DB"])
    conn.row_factory = sqlite3.Row
    return conn


def _page_not_found(message: str) -> Response:
    return Response(_layout("未找到", f"<p>{message}</p>"), status=404, mimetype="text/html")


def create_app(db_path: Path | None = None) -> Flask:
    """创建 Flask 应用；db_path 为空时使用 target/scan_lab.db。"""

    app = Flask(__name__)
    db_file = ensure_seeded(db_path if db_path is not None else DEFAULT_DB_PATH)
    app.config["SCAN_LAB_DB"] = str(db_file)

    @app.get("/")
    def index() -> str:
        body = """
<h2>本地漏洞靶场</h2>
<p>该站点故意包含漏洞，仅用于 scan-lab 扫描器的回归测试。</p>
<form action="/search" method="get">
  <label>搜索 <input type="text" name="q" value=""></label>
  <button type="submit">搜索</button>
</form>
<form action="/login" method="post">
  <label>用户名 <input type="text" name="username" value=""></label>
  <label>口令 <input type="password" name="password" value=""></label>
  <button type="submit">登录</button>
</form>
<p>也可以直接查看 <a href="/profile?id=3">用户 3</a> 的资料。</p>
"""
        return _layout("首页", body)

    @app.get("/search")
    def search() -> str:
        query = request.args.get("q", "")
        # 故意未转义：反射型 XSS 注入点
        body = f"""<h2>搜索结果</h2>
<p id="summary">你搜索了：{query}</p>
<p>没有找到匹配的帖子。</p>"""
        return _layout("搜索", body)

    @app.get("/files")
    def files() -> str | Response:
        relative = request.args.get("path", "readme.txt")
        # 故意不做目录约束：路径穿越注入点
        target = FILES_DIR / relative
        try:
            content = target.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            return _page_not_found("文件不存在。")
        return _layout("文件", f"<h2>文件内容</h2><pre>{content}</pre>")

    @app.get("/profile")
    def profile() -> str | Response:
        raw_id = request.args.get("id", "1")
        try:
            user_id = int(raw_id)
        except ValueError:
            return _page_not_found("用户不存在。")
        with _db() as conn:
            row = conn.execute(
                "SELECT id, username, email, role FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        if row is None:
            return _page_not_found("用户不存在。")
        # 故意不校验归属：越权访问（IDOR）注入点
        body = f"""<h2>用户资料</h2>
<ul>
  <li>id: {row["id"]}</li>
  <li>用户名: {row["username"]}</li>
  <li>邮箱: {row["email"]}</li>
  <li>角色: {row["role"]}</li>
</ul>"""
        return _layout("用户资料", body)

    @app.route("/login", methods=["GET", "POST"])
    def login() -> str:
        if request.method == "GET":
            body = """<h2>登录</h2>
<form action="/login" method="post">
  <label>用户名 <input type="text" name="username" value=""></label>
  <label>口令 <input type="password" name="password" value=""></label>
  <button type="submit">登录</button>
</form>"""
            return _layout("登录", body)

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # 故意使用字符串拼接：SQL 注入注入点
        sql = (
            "SELECT id, username, role FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        try:
            with _db() as conn:
                row = conn.execute(sql).fetchone()
        except sqlite3.Error as exc:
            return _layout("登录失败", f"<p>查询出错：{exc}</p>")
        if row is None:
            return _layout("登录失败", "<p>用户名或密码错误。</p>")
        return _layout(
            "登录成功",
            f"<p>欢迎，{row['username']}（角色：{row['role']}）。</p>",
        )

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5001, debug=False, use_reloader=False)
