#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# 黑盒：抓本机 UDP 2152（GTP-U / N3）。Path Switch / HO 切面时用。
# 用法:  sudo ./deploy/real-amf/capture-n3.sh path-switch
# ------------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/real-amf.env"
REPO="$(cd "$HERE/../.." && pwd)"
TAG="${1:-n3}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUTDIR="${REPO}/evidence"
mkdir -p "$OUTDIR"
OUT="${OUTDIR}/n3-${TAG}-${STAMP}.pcap"

echo "==== N3 capture (GTP-U udp/2152) ===="
echo "  bind  ${HOST_IP}"
echo "  file  $OUT"
echo "  合法 gNB 和 gtpu-sink 都在这张地址上。看 ip.src 是 UPF 还是本机。"
echo
tcpdump -i any -s 0 -w "$OUT" "udp port 2152"
echo
echo "已写 $OUT"
echo "看包: tshark -r $OUT -Y gtp -T fields -e ip.src -e ip.dst -e gtp.teid"
