#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# 黑盒：打前/打后各跑一次，把会话和数据面快照打到 evidence/。
# 用法（仓库根，不要 sudo）:
#   ./deploy/real-amf/observe.sh before path-switch
#   ./deploy/real-amf/observe.sh after  path-switch
# ------------------------------------------------------------------------------
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WHEN="${1:?用法: $0 before|after <tag>}"
TAG="${2:-manual}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUTDIR="${REPO}/evidence"
mkdir -p "$OUTDIR"
OUT="${OUTDIR}/observe-${TAG}-${WHEN}-${STAMP}.txt"

{
  echo "==== observe $WHEN tag=$TAG $STAMP ===="
  echo
  echo "---- extract-ue-ids ----"
  "$REPO/deploy/extract-ue-ids.sh" || true
  echo
  echo "---- check-up ----"
  "$HERE/check-up.sh" || true
} | tee "$OUT"
echo
echo "已写 $OUT"
