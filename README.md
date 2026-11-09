# scan-lab

> **法律声明（务必先读）**
>
> 本项目包含一个**故意有漏洞的本地靶场**和一个只面向该靶场的扫描器。
> 仅允许用于**自己拥有**或**已获得明确书面授权**的环境，用于安全插件开发
> 与回归测试。扫描器默认且唯一允许的目标是 `127.0.0.1` / `localhost` /
> `::1`，其他主机会被直接拒绝。**严禁**对任何未授权目标使用；**严禁**
> 将内置靶场暴露到公网。因违规使用产生的一切后果由使用者自行承担。

## 这是什么

`scan-lab` 是一个可离线运行的本地 Web 漏洞扫描器：

- 同源爬取 → 插件匹配 → 探测 → 证据留存 → JSON 报告 + 终端摘要；
- 内置 Flask 靶场，故意包含反射型 XSS、路径穿越、SQL 注入、越权四类问题，
  用于验证扫描结果；
- 当前内置两个插件：`xss_reflect`（反射型 XSS）与 `path_traversal`（目录穿越）。

项目定位是安全团队开发/回归扫描插件的底座，不是批量攻击工具，也不是商业扫描器。

## 快速上手

```bash
# 1. 安装依赖与命令行入口
pip install -r requirements.txt
pip install -e .

# 2. 启动内置靶场（终端 A）
scan-lab serve-target --port 5001

# 3. 扫描靶场并落盘报告（终端 B）
scan-lab scan --target http://127.0.0.1:5001 \
  --plugins xss_reflect,path_traversal --out reports/r1.json

# 4. 查看已注册插件
scan-lab plugins list

# 5. 跑测试（测试自己起靶场，随机端口，不联网）
pytest -q
```

扫描结束会打印统计与每条 finding 的摘要，报告默认写入
`reports/scan-{timestamp}.json`。目标不可达或插件名未知时退出码为 2。

## 已知限制

以下能力**当前未实现**（与 `docs/项目说明.md` 第七节一致）：

1. SQL 注入检测（错误型 / 布尔盲注 / 时间盲注）——靶场里有注入点，但扫描器不检测。
2. SSRF 检测与 OOB 回连服务器。
3. 认证会话管理、多角色爬取、越权（IDOR）检测。
4. 误报抑制与置信度打分模型——当前每条 finding 的 `confidence` 是插件内置的固定值。
5. SARIF / HTML 报告——只输出 JSON 与终端摘要。
6. 并发扫描、断点续扫、扫描队列——当前为单进程顺序扫描。
7. WAF 绕过与编码变形库——路径穿越只硬编码尝试 4 个 payload。

补充说明：爬虫会提取表单的 action/method/input 名称，但当前插件只探测
GET 查询参数，不提交表单。

## 文档

详细的项目结构、功能边界、插件契约、扫描流程、配置与报告格式见
[docs/项目说明.md](docs/项目说明.md)。靶场说明见
[target/README.md](target/README.md)。
