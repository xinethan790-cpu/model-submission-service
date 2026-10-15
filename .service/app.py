#!/usr/bin/env python3
"""比赛提交服务：网页上传 模型 + Docker 镜像 到 /data/submissions/<队伍名>/

安全模型：
- 双口令：提交口令(参赛者) / 后台口令(组织者)，HMAC 签名 cookie
- 会话隔离：上传进度只绑定会话 ID，提交口令无法按队名查询任何队伍
- 路径强校验：清洗 + realpath 兜底，文件只能落在 /data/submissions/<队名>/ 内
- 磁盘保护：可用空间低于阈值直接拒绝写入
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import threading
import time
import uuid
from pathlib import Path

from urllib.parse import unquote

from flask import Flask, jsonify, request, send_from_directory, make_response

BASE = Path("/data/submissions")
SVC = BASE / ".service"
STATE_DIR = SVC / "state"
TOKENS_FILE = SVC / "tokens.json"
SESSIONS_FILE = STATE_DIR / "sessions.json"

PORT = 8080
MIN_FREE_BYTES = 5 * 1024 ** 3          # 磁盘低于 5GB 停止接收
MAX_FILE_BYTES = 100 * 1024 ** 3        # 单文件上限 100GB
MAX_TEAM_BYTES = 200 * 1024 ** 3        # 单队总量上限 200GB
MAX_CHUNK_REQUEST = 16 * 1024 ** 2      # 单次 HTTP 请求上限 16MB
COOKIE_TTL = 30 * 86400
MAX_REQ_PER_MIN = 3600                  # 每真实客户端 IP 每分钟（大文件分片上传轻松 >10 req/s）
MAX_LOGIN_PER_MIN = 20

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = MAX_CHUNK_REQUEST

_lock = threading.Lock()
_sessions = {}          # sid -> session dict
_rate = {}              # (ip, kind) -> [window_start, count]
_file_locks = {}        # (sid, rel) -> 单文件上传锁，串行化同一文件的 chunk 写入
_fl_guard = threading.Lock()


def file_lock(sid, rel):
    """获取某文件的上传锁。锁序约定：file_lock 在外，_lock 在内，勿反向嵌套。"""
    with _fl_guard:
        key = (sid, rel)
        if key not in _file_locks:
            _file_locks[key] = threading.Lock()
        return _file_locks[key]


# ---------------------------------------------------------------- 基础工具

def log(msg):
    print(f"[{time.strftime('%F %T')}] {msg}", flush=True)


def disk_ok():
    return shutil.disk_usage(BASE).free >= MIN_FREE_BYTES


def client_ip():
    """限流用的客户端 IP。
    经 Cloudflare 隧道/cloudflared 时所有请求的 remote_addr 都是 127.0.0.1，
    真实 IP 在 CF-Connecting-IP 头（其次 X-Forwarded-For 首段）。不取它则所有队伍
    共享同一限流桶，并发上传会互相挤掉。"""
    cip = request.headers.get("CF-Connecting-IP")
    if cip:
        return cip.strip()
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "?"


def rate_limit(ip, kind, limit):
    now = time.time()
    key = (ip, kind)
    w, c = _rate.get(key, (now, 0))
    if now - w > 60:
        w, c = now, 0
    c += 1
    _rate[key] = (w, c)
    if len(_rate) > 10000:
        _rate.clear()
    return c <= limit


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 ** 2), b""):
            h.update(chunk)
    return h.hexdigest()


def clean_team(name):
    if not isinstance(name, str) or not (1 <= len(name) <= 64):
        return None
    name = name.strip()
    if not name or name in (".", "..") or name.startswith("."):
        return None
    if any(ch.isspace() for ch in name) or any(ch in name for ch in "/\\") \
            or ".." in name or re.search(r"[\x00-\x1f]", name):
        return None
    return name


def clean_relpath(rel):
    """清洗模型文件相对路径；返回 None 表示非法。"""
    if not isinstance(rel, str) or not (0 < len(rel) <= 768):
        return None
    rel = rel.replace("\\", "/")
    if rel.startswith("/") or "\x00" in rel or re.search(r"[\x00-\x1f]", rel):
        return None
    parts = rel.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return None
    return "/".join(parts)


def target_path(session, rel):
    """rel 映射到队目录内最终路径，并完成 realpath 兜底校验。"""
    team_dir = BASE / session["team"]
    p = (team_dir / "image.tar") if rel == "image.tar" else team_dir / "model" / rel
    real = p.resolve()
    if not str(real).startswith(str(team_dir.resolve()) + os.sep) and real != team_dir.resolve() / "image.tar":
        return None
    return p


def part_path(session, rel):
    tag = hashlib.sha1(rel.encode()).hexdigest()[:24]
    return BASE / session["team"] / ".parts" / f"{tag}.part"


def team_used_bytes(session):
    return sum(f.get("size", 0) for f in session["files"].values())


def save_sessions_locked():
    tmp = SESSIONS_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_sessions, f, ensure_ascii=False)
    os.replace(tmp, SESSIONS_FILE)


def save_sessions():
    with _lock:
        save_sessions_locked()


# ---------------------------------------------------------------- 令牌与鉴权

def ensure_tokens():
    if TOKENS_FILE.exists():
        with open(TOKENS_FILE) as f:
            return json.load(f)
    toks = {
        "submit": secrets.token_hex(8),
        "admin": secrets.token_hex(8),
        "cookie_secret": secrets.token_hex(32),
    }
    with open(TOKENS_FILE, "w") as f:
        json.dump(toks, f, indent=2)
    os.chmod(TOKENS_FILE, 0o600)
    return toks


TOKENS = ensure_tokens()


def sign_cookie(role, token_id):
    exp = int(time.time()) + COOKIE_TTL
    msg = f"{role}.{token_id}.{exp}".encode()
    sig = hmac.new(TOKENS["cookie_secret"].encode(), msg, hashlib.sha256).hexdigest()
    return f"{role}.{token_id}.{exp}.{sig}"


def check_cookie(role):
    cookie = request.cookies.get("auth", "")
    parts = cookie.split(".")
    if len(parts) != 4:
        return False
    c_role, token_id, exp, sig = parts
    if c_role != role:
        return False
    try:
        if int(exp) < time.time():
            return False
    except ValueError:
        return False
    msg = f"{c_role}.{token_id}.{exp}".encode()
    expect = hmac.new(TOKENS["cookie_secret"].encode(), msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expect):
        return False
    want = TOKENS[role]
    return hmac.compare_digest(token_id, want)


def require(role):
    if not check_cookie(role):
        return None
    if not rate_limit(client_ip(), "api", MAX_REQ_PER_MIN):
        return "429"
    return "ok"


# ---------------------------------------------------------------- 会话

def load_sessions():
    if SESSIONS_FILE.exists():
        with open(SESSIONS_FILE) as f:
            _sessions.update(json.load(f))
    # 清理僵尸会话：队目录已不存在（如管理员删队后遗留）的活跃会话，
    # 见 docs/项目说明.md；其 .part 文件也随之消失，保留只会干扰 create_session
    for sid in list(_sessions):
        s = _sessions[sid]
        if not s.get("done") and not (BASE / s["team"]).exists():
            del _sessions[sid]
            log(f"清理僵尸会话 {sid[:8]} team={s['team']}（队目录不存在）")
    for s in _sessions.values():
        if (s.get("image") or {}).get("status") == "pulling":
            s["image"]["status"] = "interrupted"
            s["image"]["error"] = "服务重启中断，请重新选择镜像方式"


# ---------------------------------------------------------------- 页面

@app.get("/")
def index():
    return send_from_directory(SVC / "static", "index.html")


@app.get("/healthz")
def healthz():
    return jsonify(ok=True, disk_free_gb=round(shutil.disk_usage(BASE).free / 1024 ** 3, 1))


# ---------------------------------------------------------------- 登录

@app.post("/api/login")
def login():
    if not rate_limit(client_ip(), "login", MAX_LOGIN_PER_MIN):
        return jsonify(error="尝试过于频繁，请稍后再试"), 429
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    role = None
    if token and hmac.compare_digest(token, TOKENS["submit"]):
        role = "submit"
    elif token and hmac.compare_digest(token, TOKENS["admin"]):
        role = "admin"
    if not role:
        return jsonify(error="口令不正确"), 401
    resp = make_response(jsonify(role=role))
    resp.set_cookie("auth", sign_cookie(role, token), max_age=COOKIE_TTL, httponly=True, samesite="Lax")
    return resp


# ---------------------------------------------------------------- 提交流程（submit 角色）

@app.post("/api/session")
def create_session():
    gate = require("submit")
    if gate is None:
        return jsonify(error="未登录"), 401
    if gate != "ok":
        return jsonify(error="请求过于频繁"), 429
    data = request.get_json(silent=True) or {}
    team = clean_team(data.get("team", ""))
    if not team:
        return jsonify(error="队伍名不合法（1-64 字符，不能含 / \\ 空格或 ..）"), 400
    with _lock:
        if (BASE / team).exists():
            active = next((s for s in _sessions.values()
                           if s["team"] == team and not s.get("done")), None)
            if active:
                return jsonify(sid=active["sid"], team=team)
            return jsonify(error=f"队伍「{team}」已提交过，不能重复提交"), 409
        if not disk_ok():
            return jsonify(error="服务器磁盘空间不足，请联系管理员"), 503
        sid = uuid.uuid4().hex
        team_dir = BASE / team
        (team_dir / "model").mkdir(parents=True)
        (team_dir / ".parts").mkdir()
        _sessions[sid] = {
            "sid": sid, "team": team, "created": int(time.time()),
            "files": {}, "image": None, "done": False,
        }
        save_sessions_locked()
    log(f"session {sid[:8]} team={team} ip={request.remote_addr}")
    return jsonify(sid=sid, team=team)


def _get_session(sid, rel=None, rel_path=None):
    s = _sessions.get(sid)
    if not s:
        return None
    if s.get("done"):
        return None
    return s


@app.post("/api/file/begin")
def file_begin():
    gate = require("submit")
    if gate is None:
        return jsonify(error="未登录"), 401
    if gate != "ok":
        return jsonify(error="请求过于频繁"), 429
    data = request.get_json(silent=True) or {}
    s = _get_session(data.get("sid", ""))
    if not s:
        return jsonify(error="会话不存在或已完成"), 404
    rel = data.get("relpath", "")
    size = data.get("size")
    sha = (data.get("sha256") or "").strip().lower()
    if not isinstance(size, int) or not (0 < size <= MAX_FILE_BYTES):
        return jsonify(error="文件大小不合法"), 400
    # sha 可选：超大文件浏览器端预哈希耗时过长，允许不带（finalize 时以服务端
    # 实算值为准，参赛者事后自行核对）
    if sha and not re.fullmatch(r"[0-9a-f]{64}", sha):
        return jsonify(error="SHA256 不合法"), 400
    if rel != "image.tar":
        rel = clean_relpath(rel)
        if not rel:
            return jsonify(error="文件路径不合法"), 400
    tp = target_path(s, rel)
    if tp is None:
        return jsonify(error="文件路径不合法"), 400
    with file_lock(s["sid"], rel):
        with _lock:
            if s["files"].get(rel, {}).get("status") == "done":
                if not sha or s["files"][rel].get("server_sha256") == sha:
                    return jsonify(offset=size, status="done",
                                   sha256=s["files"][rel].get("server_sha256", ""))
                return jsonify(error="该文件已上传完成且内容不同，请重试"), 409
            if team_used_bytes(s) + size > MAX_TEAM_BYTES:
                return jsonify(error="超出单队总量上限(200GB)"), 413
            if not disk_ok():
                return jsonify(error="服务器磁盘空间不足，请联系管理员"), 503
            pp = part_path(s, rel)
            offset = pp.stat().st_size if pp.exists() else 0
            if offset > size:
                pp.unlink(missing_ok=True)
                offset = 0
            restart = request.headers.get("X-Restart") == "1"
            if restart:
                pp.unlink(missing_ok=True)
                offset = 0
            s["files"][rel] = {"size": size, "declared_sha256": sha,
                               "received": offset, "status": "uploading"}
            save_sessions_locked()
    return jsonify(offset=offset)


@app.post("/api/file/chunk")
def file_chunk():
    gate = require("submit")
    if gate is None:
        return jsonify(error="未登录"), 401
    if gate != "ok":
        return jsonify(error="请求过于频繁"), 429
    sid = request.headers.get("X-Sid", "")
    rel = unquote(request.headers.get("X-Relpath", ""))   # 前端 encodeURIComponent（HTTP 头仅允许 ISO-8859-1）
    s = _get_session(sid)
    if not s or rel not in s["files"]:
        return jsonify(error="会话或文件不存在"), 404
    st = s["files"][rel]
    if st["status"] == "done":
        return jsonify(error="文件已完成"), 409
    # X-Offset = 客户端预期的 part 当前大小；旧客户端不带此头则跳过校验
    exp_raw = request.headers.get("X-Offset")
    expected = int(exp_raw) if exp_raw is not None and exp_raw.isdigit() else -1
    pp = part_path(s, rel)
    received = 0
    last_save = [0.0]

    def _save():
        nonlocal received
        st["received"] = received
        save_sessions()

    with file_lock(sid, rel):
        if not disk_ok():
            return jsonify(error="服务器磁盘空间不足，请联系管理员"), 503
        actual = pp.stat().st_size if pp.exists() else 0
        if expected >= 0 and actual != expected:
            # offset 不一致：上一个中断的请求可能已写入部分数据（Cloudflare 524
            # 断连后服务端仍收完已传字节）。已落盘内容是有效文件前缀，不丢弃，
            # 返回实际 offset 让客户端重新同步后继续。
            log(f"{s['team']} {rel} offset 不一致 expected={expected} actual={actual}")
            return jsonify(error="offset 不一致，请按实际 offset 续传", offset=actual), 409
        received = actual
        try:
            with open(pp, "ab") as f:
                while True:
                    chunk = request.stream.read(1024 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
                    f.flush()
                    received += len(chunk)
                    if received > st["size"]:
                        break
                    if time.time() - last_save[0] > 1.0:
                        _save()
                        last_save[0] = time.time()
        except Exception as e:
            # 请求体读取中途异常（连接被上游断开等）：保留已写入数据，状态落盘
            log(f"{s['team']} {rel} chunk 写入中断: {e!r} received={received}")
            _save()
            return jsonify(received=received, done=received == st["size"])
    if received > st["size"]:
        return jsonify(error="数据超出声明大小，请重传该文件"), 400
    _save()
    return jsonify(received=received, done=received == st["size"])


@app.post("/api/file/finalize")
def file_finalize():
    gate = require("submit")
    if gate is None:
        return jsonify(error="未登录"), 401
    if gate != "ok":
        return jsonify(error="请求过于频繁"), 429
    data = request.get_json(silent=True) or {}
    sid = data.get("sid", "")
    s = _get_session(sid)
    if not s:
        return jsonify(error="会话不存在或已完成"), 404
    rel = data.get("relpath", "")
    st = s["files"].get(rel)
    if not st:
        return jsonify(error="文件不存在"), 404
    with file_lock(sid, rel):
        pp = part_path(s, rel)
        if not pp.exists() or pp.stat().st_size != st["size"]:
            return jsonify(error="文件未完成，请继续上传或重传"), 400
        digest = sha256_file(pp)
        # 未声明校验码的文件（超大文件跳过浏览器端预哈希）：以服务端实算为准
        if st["declared_sha256"] and digest != st["declared_sha256"]:
            return jsonify(error="SHA256 校验失败，请重传该文件"), 400
        tp = target_path(s, rel)
        tp.parent.mkdir(parents=True, exist_ok=True)
        os.replace(pp, tp)
        with _lock:
            st["status"] = "done"
            st["received"] = st["size"]
            st["server_sha256"] = digest
            save_sessions_locked()
    log(f"{s['team']}: 完成 {rel} ({st['size']} bytes)")
    return jsonify(ok=True, sha256=digest)


@app.get("/api/session")
def session_status():
    gate = require("submit")
    if gate is None:
        return jsonify(error="未登录"), 401
    if gate != "ok":
        return jsonify(error="请求过于频繁"), 429
    s = _sessions.get(request.args.get("sid", ""))
    if not s:
        return jsonify(error="会话不存在"), 404
    files = []
    for rel, st in s["files"].items():
        files.append({
            "relpath": rel, "size": st["size"], "received": st.get("received", 0),
            "status": st["status"],
            "sha256": st.get("server_sha256") or st.get("declared_sha256"),
        })
    return jsonify(team=s["team"], done=s["done"], files=files,
                   image=s.get("image"), disk_free_gb=round(shutil.disk_usage(BASE).free / 1024 ** 3, 1))


@app.post("/api/finalize-session")
def finalize_session():
    gate = require("submit")
    if gate is None:
        return jsonify(error="未登录"), 401
    if gate != "ok":
        return jsonify(error="请求过于频繁"), 429
    data = request.get_json(silent=True) or {}
    s = _sessions.get(data.get("sid", ""))
    if not s or s["done"]:
        return jsonify(error="会话不存在或已完成"), 404
    unfinished = [r for r, st in s["files"].items() if st["status"] != "done"]
    if s["files"] and unfinished:
        return jsonify(error=f"仍有 {len(unfinished)} 个文件未完成"), 400
    if not s["files"]:
        return jsonify(error="没有上传任何文件"), 400
    team_dir = BASE / s["team"]
    lines, info_files = [], []
    for rel, st in sorted(s["files"].items()):
        p = target_path(s, rel)
        path_in_team = "image.tar" if rel == "image.tar" else f"model/{rel}"
        lines.append(f"{st['server_sha256']}  {path_in_team}")
        info_files.append({"path": path_in_team, "size": st["size"], "sha256": st["server_sha256"]})
    (team_dir / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    info = {
        "team": s["team"],
        "completed_at": time.strftime("%F %T %z"),
        "image": s.get("image"),
        "files": info_files,
        "total_bytes": sum(f["size"] for f in info_files),
    }
    (team_dir / "SUBMIT_INFO.json").write_text(json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
    shutil.rmtree(team_dir / ".parts", ignore_errors=True)
    with _lock:
        s["done"] = True
        save_sessions_locked()
    log(f"{s['team']}: 提交完成，共 {len(info_files)} 个文件")
    return jsonify(ok=True, team=s["team"],
                   checksums=[{"path": f["path"], "size": f["size"], "sha256": f["sha256"]} for f in info_files])


@app.post("/api/client-error")
def client_error():
    """参赛者浏览器端报错上报（文件上传失败/镜像拉取启动失败/完成提交失败）。
    存进会话供管理页查看；内容做长度与字符清洗。"""
    gate = require("submit")
    if gate is None:
        return jsonify(error="未登录"), 401
    if gate != "ok":
        return jsonify(error="请求过于频繁"), 429
    data = request.get_json(silent=True) or {}
    s = _sessions.get(data.get("sid", ""))
    if not s:
        return jsonify(error="会话不存在"), 404
    rel = str(data.get("relpath") or "").strip()[:200]
    msg = re.sub(r"[\x00-\x1f]", " ", str(data.get("message") or "")).strip()[:300]
    if not msg:
        return jsonify(error="报错内容不能为空"), 400
    with _lock:
        s.setdefault("errors", []).append({
            "ts": time.strftime("%F %T"), "relpath": rel, "message": msg,
        })
        del s["errors"][:-50]
        save_sessions_locked()
    log(f"{s['team']} 客户端报错 {rel or '(通用)'}: {msg[:120]}")
    return jsonify(ok=True)


# ---------------------------------------------------------------- 管理（admin 角色）

def _du(path):
    total = 0
    for root, _dirs, files in os.walk(path):
        for n in files:
            fp = Path(root) / n
            if fp.is_file():
                total += fp.stat().st_size
    return total


@app.get("/api/admin/teams")
def admin_teams():
    gate = require("admin")
    if gate is None:
        return jsonify(error="需要后台口令"), 401
    if gate != "ok":
        return jsonify(error="请求过于频繁"), 429
    teams = []
    for d in sorted(BASE.iterdir()):
        if not d.is_dir() or d.name.startswith("."):
            continue
        info_f = d / "SUBMIT_INFO.json"
        sums_f = d / "SHA256SUMS"
        entry = {"team": d.name, "size": _du(d),
                 "complete": info_f.exists(),
                 "info": json.loads(info_f.read_text()) if info_f.exists() else None}
        if sums_f.exists():
            entry["sha256"] = [
                {"path": line.split("  ", 1)[1], "sha256": line.split("  ", 1)[0]}
                for line in sums_f.read_text().splitlines() if line.strip()
            ]
        else:
            entry["sha256"] = None
        active = [s for s in _sessions.values() if s["team"] == d.name and not s.get("done")]
        if active:
            st = active[0]
            entry["uploading"] = {
                "files": {r: f.get("status") for r, f in st["files"].items()},
                "image": st.get("image"),
            }
        errors = [e for s in _sessions.values() if s["team"] == d.name
                  for e in (s.get("errors") or [])]
        if errors:
            entry["errors"] = errors[-20:]
        teams.append(entry)
    return jsonify(teams=teams, disk_free_gb=round(shutil.disk_usage(BASE).free / 1024 ** 3, 1))


@app.post("/api/admin/delete")
def admin_delete():
    gate = require("admin")
    if gate is None:
        return jsonify(error="需要后台口令"), 401
    if gate != "ok":
        return jsonify(error="请求过于频繁"), 429
    data = request.get_json(silent=True) or {}
    team = clean_team(data.get("team", ""))
    if not team:
        return jsonify(error="队伍名不合法"), 400
    d = (BASE / team).resolve()
    if not str(d).startswith(str(BASE.resolve()) + os.sep):
        return jsonify(error="非法路径"), 400
    if not d.exists():
        return jsonify(error="该队伍不存在"), 404
    shutil.rmtree(d)
    with _lock:
        for sid, s in list(_sessions.items()):
            if s["team"] == team:
                del _sessions[sid]
        save_sessions_locked()
    log(f"admin: 删除队伍 {team}")
    return jsonify(ok=True)


# ---------------------------------------------------------------- 入口

# 初始化放模块级：waitress 以 import 方式加载 app 时 __main__ 不执行
BASE.mkdir(parents=True, exist_ok=True)
STATE_DIR.mkdir(parents=True, exist_ok=True)
load_sessions()


def main():
    log(f"submit service starting on 0.0.0.0:{PORT}, base={BASE}")
    app.run(host="0.0.0.0", port=PORT, threaded=True)


if __name__ == "__main__":
    main()
