import argparse, json, sys
from plugins.tomcat_put import check

PLUGINS = {"tomcat_put": check}   # L4 会重构为自动注册

def main():
    ap = argparse.ArgumentParser(description="PoC-Forge: 授权本地靶场漏洞验证框架")
    ap.add_argument("-t", "--target", required=True, help="目标,如 http://localhost:8080")
    ap.add_argument("-p", "--plugin", required=True, choices=sorted(PLUGINS))
    ap.add_argument("-o", "--output", help="结果同时写入此 JSON 文件")
    a = ap.parse_args()

    r = PLUGINS[a.plugin](a.target)
    print(json.dumps(r, ensure_ascii=False, indent=2))
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(json.dumps(r, ensure_ascii=False, indent=2))
    sys.exit(0 if r["status"] != "INCONCLUSIVE" else 2)

if __name__ == "__main__":
    main()
