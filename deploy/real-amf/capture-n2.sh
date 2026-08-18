#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# 黑盒：抓本机 ↔ 华为 AMF 的整条 N2（SCTP 38412）。攻击前开，打完 Ctrl-C。
# 用法（仓库根目录）:
#   sudo ./deploy/real-amf/capture-n2.sh path-switch
#   sudo ./deploy/real-amf/capture-n2.sh ue-release
# 解码:
#   ./deploy/real-amf/decode-n2.sh evidence/n2-*.pcap
# ------------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/real-amf.env"
REPO="$(cd "$HERE/../.." && pwd)"
TAG="${1:-n2}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUTDIR="${REPO}/evidence"
mkdir -p "$OUTDIR"
OUT="${OUTDIR}/n2-${TAG}-${STAMP}.pcap"

echo "==== N2 capture ===="
echo "  AMF   ${AMF_ADDR}:${AMF_PORT}"
echo "  file  $OUT"
echo "  先开本窗口，再去打攻击。打完回到这里 Ctrl-C。"
echo
tcpdump -i any -s 0 -w "$OUT" "host ${AMF_ADDR} and sctp"
echo
echo "已写 $OUT"
echo "解码: ./deploy/real-amf/decode-n2.sh $OUT"
