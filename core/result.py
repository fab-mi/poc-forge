import datetime

STATUS_VULNERABLE   = "VULNERABLE"    # 确认存在
STATUS_NOT_FOUND    = "NOT_FOUND"     # 确认不存在
STATUS_INCONCLUSIVE = "INCONCLUSIVE"  # 测不了(超时/连接失败/证据矛盾)

def make_result(plugin, target, status, evidence=None, note=""):
    return {
        "plugin": plugin,
        "target": target,
        "status": status,            # 只有三种状态,没有第四种
        "evidence": evidence or {},  # 原始证据:响应码、读回内容等
        "note": note,
        "timestamp": datetime.datetime.now().isoformat(),
    }
