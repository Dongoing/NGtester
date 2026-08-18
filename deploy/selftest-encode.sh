#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# 不连 AMF：把现场会发的每条 NGAP 都编一遍、再解一遍。
# 现场出发前 / pull 之后跑一次。失败就不要打那条。
# 用法:  ./deploy/selftest-encode.sh
# ------------------------------------------------------------------------------
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
cd "$REPO"
PY="${REPO}/.venv/bin/python"
[[ -x "$PY" ]] || PY="python3"

echo "==== encode/decode every field attack (no SCTP) ===="
"$PY" "$REPO/validate_builders.py"
echo
echo "==== CLI 子命令能解析 ===="
"$PY" -m ngaptester.cli --config config/huawei.json --help >/dev/null
for cmd in sctp-ping ng-setup path-switch ue-release error-indication ng-reset \
           handover-required ho-window-inject ran-config-update \
           ul-ran-config-transfer initial-ue chain-ps-release \
           chain-initue-release handover-notify pdu-notify cell-trace \
           ul-ran-status ul-nrppa gtpu-sink; do
  "$PY" -m ngaptester.cli --config config/huawei.json "$cmd" --help >/dev/null
  echo "  OK  $cmd --help"
done
echo
echo "selftest-encode 通过。连 AMF 的通路仍要现场 sctp-ping / ng-setup。"
