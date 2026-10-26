import argparse
import json
import sys

from core.report import to_markdown
from plugins import REGISTRY

__version__ = "0.1.0"


def main():
    ap = argparse.ArgumentParser(description="PoC-Forge: 授权本地靶场漏洞验证框架")
    ap.add_argument("--version", action="version", version=f"PoC-Forge {__version__}")
    ap.add_argument("-t", "--target", required=True,
                    help="目标,多个用逗号分隔: http://localhost:8080,http://localhost:8081")
    ap.add_argument("-p", "--plugin", required=True,
                    choices=["all"] + sorted(REGISTRY))
    ap.add_argument("-o", "--output", help="结果同时写入此文件")
    ap.add_argument("--format", choices=["json", "md"], default="json")
    a = ap.parse_args()

    if a.plugin == "all":
        plugins_to_run = list(REGISTRY.values())
    else:
        plugins_to_run = [REGISTRY[a.plugin]]

    results = []
    for target in a.target.split(","):
        target = target.strip()
        for mod in plugins_to_run:
            print(f"[*] 运行 {mod.NAME} -> {target}", file=sys.stderr)
            results.append(mod.check(target))

    if a.format == "md":
        out = to_markdown(results)
    else:
        out = json.dumps(results, ensure_ascii=False, indent=2)
    print(out)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(out)

    sys.exit(2 if any(r["status"] == "INCONCLUSIVE" for r in results) else 0)


if __name__ == "__main__":
    main()