#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# 黑盒：N3 pcap 里列出 GTP-U TEID。手册攻击用 --teid 0x11111111。
# 用法:  ./deploy/real-amf/decode-n3.sh evidence/n3-xxx.pcap
# ------------------------------------------------------------------------------
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PCAP="${1:-}"
if [[ -z "$PCAP" ]]; then
  PCAP="$(ls -t "$REPO"/evidence/n3-*.pcap 2>/dev/null | head -1 || true)"
  [[ -n "$PCAP" ]] || { echo "用法: $0 <n3.pcap>" >&2; exit 1; }
  echo "用最新: $PCAP"
fi
command -v tshark >/dev/null 2>&1 || { echo "需要 tshark" >&2; exit 1; }
echo "TEID 0x11111111 = 285217055 = 我们在 Path Switch / HO Ack 里声明的隧道"
echo
tshark -r "$PCAP" -Y gtp -T fields -E header=y -E separator=$'\t' \
  -e frame.number -e frame.time_relative \
  -e ip.src -e ip.dst -e gtp.teid 2>/dev/null || \
tshark -r "$PCAP" -Y udp.port==2152 -T fields -E header=y \
  -e frame.number -e ip.src -e ip.dst -e udp.length
