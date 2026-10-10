import time
from core.http import request
from core.result import (make_result, STATUS_VULNERABLE,
                         STATUS_NOT_FOUND, STATUS_INCONCLUSIVE)

MARKER = "forge-probe-marker"

def check(target):
    """Tomcat PUT 任意文件写入检测(CVE-2017-12615)
    检测信号:PUT 探针文件 201 + 读回内容一致(已实测,100% 确定)。
    严重性说明:实验证实尾斜杠变体可写入可执行 JSP(7*7=49),
    但 check 模式只写无害 .txt 探针,不验证 JSP 执行。
    已知限制:仅覆盖 .txt 原语;变体矩阵见课程 L2/Q5 实验记录。
    """
    name = f"forge_{int(time.time())}.txt"   # 唯一文件名,避免历史文件干扰
    url = f"{target.rstrip('/')}/{name}"
    try:
        r = request("PUT", url, data=MARKER)
    except Exception as e:
        return make_result("tomcat_put", target, STATUS_INCONCLUSIVE,
                           note=f"连接失败: {e}")
    if r.status_code != 201:
        return make_result("tomcat_put", target, STATUS_NOT_FOUND,
                           evidence={"put_status": r.status_code})
    back = request("GET", url)
    if back.status_code == 200 and MARKER in back.text:
        return make_result("tomcat_put", target, STATUS_VULNERABLE,
                           evidence={"put_status": 201, "readback": back.text})
    return make_result("tomcat_put", target, STATUS_INCONCLUSIVE,
                       note="PUT 非 201 但读回异常,需人工确认")
