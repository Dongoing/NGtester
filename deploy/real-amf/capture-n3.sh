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
if [[ -n "${SUDO_USER:-}" ]]; then
  chmod 0777 "$OUTDIR" 2>/dev/null || true
fi
OUT="${OUTDIR}/n3-${TAG}-${STAMP}.pcap"

echo "==== N3 capture (GTP-U udp/2152) ===="
echo "  host  ${HOST_IP}  （合法 gNB 也绑在这里，不要再开 gtpu-sink）"
echo "  file  $OUT"
echo "  切面成功时会出现 TEID 0x11111111。"
echo
tcpdump -i any -s 0 -w "$OUT" "udp port 2152"
if [[ -n "${SUDO_USER:-}" ]]; then
  chown "${SUDO_USER}:" "$OUT" 2>/dev/null || true
  chmod a+r "$OUT" 2>/dev/null || true
fi
echo
echo "已写 $OUT"
echo "看包: ./deploy/real-amf/decode-n3.sh $OUT"
