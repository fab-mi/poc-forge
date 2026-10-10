import requests

def request(method, url, timeout=10, **kw):
    """统一请求入口:网络异常向上抛,由插件决定降级为 INCONCLUSIVE"""
    return requests.request(method, url, timeout=timeout, **kw)
