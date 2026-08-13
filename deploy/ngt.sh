#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# 原生(venv)运行 ngap_tester 连真实华为 AMF —— 不经 Docker，直接走本机 SCTP。
# 需先跑过 ./deploy/bootstrap.sh。默认用 config/huawei.json（可用 CFG=... 覆盖）。
#
# 用法:
#   ./deploy/ngt.sh sctp-ping
#   ./deploy/ngt.sh ng-setup
#   ./deploy/ngt.sh sweep --attack ue-release --amf-range 1-2000
#   ./deploy/ngt.sh path-switch --source-amf-ue-id <victim>
# ------------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"       # .../ngap_tester/deploy
REPO="$(cd "$HERE/.." && pwd)"              # .../ngap_tester
CFG="${CFG:-$REPO/config/huawei.json}"

[[ -x "$REPO/.venv/bin/python" ]] || { echo "先跑 ./deploy/bootstrap.sh 建好 venv" >&2; exit 1; }
[[ -f "$CFG" ]] || { echo "找不到配置 $CFG" >&2; exit 1; }

cd "$REPO"                                   # 让 'python -m ngaptester.cli' 能导入包
exec "$REPO/.venv/bin/python" -m ngaptester.cli --config "$CFG" "$@"
