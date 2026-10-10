#!/usr/bin/env bash
# 正反样例一键回归:期望矩阵 6 格,任何一格不符即失败
set -e
cd "$(dirname "$0")"
source .venv/Scripts/activate

(cd /d/workspace/security-lab/vulhub/tomcat/CVE-2017-12615 && docker compose up -d)
(cd /d/workspace/security-lab/vulhub/log4j/CVE-2021-44228 && docker compose up -d)
docker start clean-tomcat 2>/dev/null || docker run -d --name clean-tomcat -p 8081:8080 tomcat:9

wait_up() {  # 容器启动后 Tomcat/Solr 需要几秒到几十秒才真正可服务
  for i in $(seq 1 30); do
    curl -s -o /dev/null --max-time 2 "$1" && return 0
    sleep 2
  done
  echo "TIMEOUT waiting for $1" >&2
  return 1
}
wait_up http://localhost:8080/
wait_up http://localhost:8081/
wait_up http://localhost:8983/

python pocforge.py -t http://localhost:8080,http://localhost:8081,http://localhost:8983 \
  -p all -o reports/matrix.json

python - <<'EOF'
import json
results = json.load(open("reports/matrix.json", encoding="utf-8"))
expect = {  # (目标, 插件): 期望状态 —— 检测工具的回归就是一张期望矩阵
    ("http://localhost:8080", "tomcat_put"):  "VULNERABLE",
    ("http://localhost:8080", "log4j2_jndi"): "NOT_FOUND",
    ("http://localhost:8081", "tomcat_put"):  "NOT_FOUND",
    ("http://localhost:8081", "log4j2_jndi"): "NOT_FOUND",
    ("http://localhost:8983", "tomcat_put"):  "NOT_FOUND",
    ("http://localhost:8983", "log4j2_jndi"): "VULNERABLE",
}
seen = set()
for r in results:
    key = (r["target"], r["plugin"])
    assert key in expect, f"意外组合: {key}"
    assert r["status"] == expect[key], f"{key}: 期望 {expect[key]}, 实际 {r['status']}"
    seen.add(key)
assert seen == set(expect), f"矩阵缺格: {set(expect) - seen}"
print("REGRESSION OK (%d/%d)" % (len(seen), len(expect)))
EOF