#!/usr/bin/env python3
"""TCP 转发：0.0.0.0:80 -> <数据机IP>:8080（参赛提交直连入口）

部署位置：SSH 入口机 <入口机IP>（公网 <公网IP> 的 80 端口被云 NAT
转发到该机的 80）。配合 systemd 单元 submissions-port80.service 使用。

设计：
- 每连接一线程，双向 recv/sendall 管道（1MB 缓冲，天然背压）
- 上游连接失败仅记日志，不影响其他连接
- 客户端异常消失时，上游 waitress channel-timeout=600 会先断开，
  本进程随后收到 EOF 自动回收，无需额外心跳
- 纯字节转发，不解析 HTTP，兼容任意协议版本与分片上传
"""
import os
import socket
import sys
import threading
import time

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 80
# 目标地址由 systemd unit 的 Environment= 注入（仓库模板不写真实值）
TARGET_HOST = os.environ.get("RELAY_TARGET_HOST", "FILL-IN-DATA-MACHINE-IP")
TARGET_PORT = int(os.environ.get("RELAY_TARGET_PORT", "8080"))
BACKLOG = 512
BUF = 1024 * 1024


def log(msg: str) -> None:
    sys.stderr.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    sys.stderr.flush()


def pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(BUF)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client: socket.socket, addr) -> None:
    try:
        upstream = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10)
    except OSError as e:
        log(f"connect failed from {addr[0]}:{addr[1]}: {e}")
        client.close()
        return
    t1 = threading.Thread(target=pipe, args=(client, upstream), daemon=True)
    t2 = threading.Thread(target=pipe, args=(upstream, client), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    for s in (upstream, client):
        try:
            s.close()
        except OSError:
            pass


def main() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(BACKLOG)
    log(f"listening {LISTEN_HOST}:{LISTEN_PORT} -> {TARGET_HOST}:{TARGET_PORT}")
    while True:
        client, addr = srv.accept()
        threading.Thread(target=handle, args=(client, addr), daemon=True).start()


if __name__ == "__main__":
    main()
