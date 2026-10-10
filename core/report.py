import datetime

def to_markdown(results):
    now = datetime.datetime.now().isoformat(timespec="seconds")
    lines = [f"# PoC-Forge 扫描报告", f"生成时间:{now}", "",
             "| 插件 | 目标 | 状态 | 证据 |",
             "|------|------|------|------|"]
    for r in results:
        ev = "`" + json.dumps(r["evidence"], ensure_ascii=False) + "`"
        lines.append(f"| {r['plugin']} | {r['target']} | **{r['status']}** | {ev} |")
    return "\n".join(lines)
