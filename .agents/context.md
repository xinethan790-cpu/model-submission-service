# 项目速览（agent 会话上下文）

比赛模型提交服务：参赛队伍通过网页把「模型文件夹 + Docker 镜像」传到
`/data/submissions/<队伍名>/`，服务端实算 SHA256 供双方核对。

## 目录约定（本项目所有内容只能在 /data/submissions 内）

| 路径 | 用途 |
|---|---|
| `.service/` | 服务端代码：`app.py`（Flask app；生产由 waitress-serve 加载，端口 8080，见 docs/决策记录.md 2026-10-15）、`static/index.html`（前端单页）、`tokens.json`（双口令+cookie 密钥，0600，**禁止外传/入库**）、`state/sessions.json`（上传会话状态）、`cloudflared`（隧道二进制）、`venv/` |
| `.agents/` | agent 会话资料（skill / mcp / 上下文） |
| `tests/` | 测试脚本：`test_e2e.py`（主 E2E）、`test_js_sha.py`（前端 SHA256 与 openssl 对拍）、`test_client/`（本地构造的假模型/镜像样例） |
| `docs/` | 文档与决策记录（know why）：`参赛提交说明.md`（给参赛者）、`项目说明.md`、`决策记录.md`、`systemd-units/`（unit 文件备份） |
| `logs/` | 运行日志：`service.log`（app stdout/stderr）、`cloudflared.log`、测试运行记录 |
| `<队伍名>/` | 队伍数据目录（运行时产物，**不入 git**）：`model/`、`image.tar`、`SHA256SUMS`、`SUBMIT_INFO.json`，上传中另有 `.parts/` |

## 关键命令

```bash
# 重启服务（改了 app.py 必须重启；index.html 是静态读取，无需重启）
systemctl restart submissions-web
# Cloudflare 备用隧道（公网地址会随重启变化）
systemctl restart submissions-cloudflare
# 直连入口 http://<公网IP>/ ：公网 80 → 云 NAT → SSH 入口机 <入口机IP>
#   （主机别名 <入口机SSH别名>）上的 submissions-port80.service（纯 TCP 80→<数据机IP>:8080）。
#   转发服务部署在入口机上、不在本机；重装步骤见 docs/systemd-units/submissions-port80.service 头注释
ssh -o BatchMode=yes <入口机SSH别名> 'systemctl status submissions-port80'

# E2E 测试（自造随机队伍，测完自动删除；服务需在运行）
/data/submissions/.service/venv/bin/python /data/submissions/tests/test_e2e.py
# 524 断连/并发续传回归（同上）
/data/submissions/.service/venv/bin/python /data/submissions/tests/test_resume_524.py

# 日志
tail -f /data/submissions/logs/service.log
```

## 安全模型要点（改动时勿破坏）

- 双口令（submit / admin），HMAC 签名 cookie；提交口令不能按队名查别人。
- 路径强校验：`clean_team` / `clean_relpath` + realpath 兜底，文件只能落在队目录内。
- 磁盘保护：剩余 <5GB 拒写；单文件 100GB / 单队 200GB / 单请求 16MB 上限。
- 限流按**真实客户端 IP**（`client_ip()`：CF-Connecting-IP → X-Forwarded-For 首段
  → remote_addr，3600 req/min/IP）；经隧道后 remote_addr 全是 127.0.0.1，
  若改回直接用 remote_addr 会让所有队伍共享一个限流桶（并发互相挤掉）。
- `X-Relpath` 请求头 = `encodeURIComponent(relpath)`（HTTP 头只允许 ISO-8859-1，
  中文路径必须百分号编码，服务端 `unquote` 还原）。见 `docs/决策记录.md` 2026-10-14。
- 断点续传：`.parts/<sha1(rel)[:24]>.part`；finalize 时服务端实算 SHA256 比对。
- chunk 续传协议（2026-10-15 加）：`X-Offset` = 客户端预期的 part 当前大小，服务端在
  每文件锁（`file_lock`，锁序 file_lock 在外、`_lock` 在内）下与磁盘实际值比对，
  不一致回 409 + 实际 offset 让前端重新同步；part 超过声明大小时 begin 自动删除重传。
  前端分片 256KB–16MB 自适应（初值 4MB，按实测速率调整目标"25s 传完一片"，
  524/504/网络异常减半；走 Cloudflare 时必须远小于其 100s 源站超时，
  见 docs/决策记录.md 2026-10-15）。
- 前端文件级并发不设上限（文件夹内全部文件同时上传，浏览器按 HTTP/2 流
  上限排队）；服务端 waitress --threads=128 匹配。页面显示总速度 +
  预计剩余时间（30s 采样窗口，≤15s 求均值）。
- 模型文件上传=统一文件篮（basket）：「选择模型文件夹」（PC，webkitdirectory）
  与「添加文件」（手机，multiple、可多次累加）都汇入 basket（按 rel+size 去重），
  手机选择无文件夹前缀（relpath=basename，落在队目录根下）。
- 直连流量 remote_addr 全是 <入口机IP>（转发器不传 XFF），限流桶被所有直连
  用户共享（3600 req/min 足够）；CF 线路仍按 CF-Connecting-IP 分桶。
- waitress 3.x 断连语义（勿按流式假设写代码）：请求体收齐才调用 WSGI app
  （body 缓冲 ≤512KB 内存 + spill 临时文件），中途断连时 handler 不被调用、
  chunk 全有或全无；"chunk 写入中断"异常分支只在开发服务器回退下触发。
- 大文件（>1GB）前端不预哈希：begin 传空 sha 合法，finalize 以服务端实算
  值为准并返回给参赛者核对（见 docs/决策记录.md 2026-10-15）。
- 参赛者浏览器端失败会经 `POST /api/client-error` 上报进会话 `errors`（每条 ≤300 字符，
  每会话留 50 条），管理页 `/api/admin/teams` 的 `errors` 字段可见——排查"文件卡 0 字节"
  先看这里，再看 `logs/service.log`。

## 已知注意事项

- `tokens.json` 丢了 = 所有已登录 cookie 失效、需重新发放口令。备份只能放本机加密位置。
- `state/sessions.json` 中"队目录已不存在"的残留会话可安全删除（清理方法见 docs/项目说明.md）。
- cloudflared 快速隧道地址每次重启都变，要同步更新 `docs/参赛提交说明.md` 里的 URL。
- 直连地址 `http://<公网IP>:8080`（SSH 反代）目前**不可用**：隧道、远端
  监听、防火墙全链路验证过，唯一堵点是 <公网IP> 的云安全组未放行入站
  TCP 8080（云厂商控制台操作，服务端代劳不了）。规则加上后可用，
  记得把 `参赛提交说明.md` 里"目前尚未开放"改回可用。
- 镜像只支持参赛者本地 `docker save` 后上传 tar；服务器侧拉取（skopeo）已于
  2026-10-14 移除（见 docs/决策记录.md），不要再加回 pull 相关代码。
