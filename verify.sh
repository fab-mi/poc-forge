#!/usr/bin/env bash
# 正反样例一键回归:框架任何改动之后跑它,两个断言都过才算没改坏
set -e
cd "$(dirname "$0")"
source .venv/Scripts/activate

(cd /d/workspace/security-lab/vulhub/tomcat/CVE-2017-12615 && docker compose up -d)
docker start clean-tomcat 2>/dev/null || docker run -d --name clean-tomcat -p 8081:8080 tomcat:9

python pocforge.py -t http://localhost:8080 -p tomcat_put -o reports/pos.json
python pocforge.py -t http://localhost:8081 -p tomcat_put -o reports/neg.json

python - <<'EOF'
import json
pos = json.load(open("reports/pos.json", encoding="utf-8"))
neg = json.load(open("reports/neg.json", encoding="utf-8"))
assert pos[0]["status"] == "VULNERABLE", f"正样本未检出: {pos}"
assert neg[0]["status"] == "NOT_FOUND", f"负样本误报: {neg}"
print("REGRESSION OK")
EOF
