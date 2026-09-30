#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# 黑盒：把 N2 pcap 打成一行一条 NGAP（看 procedureCode / AU / 谁发给谁）。
# 用法:  ./deploy/real-amf/decode-n2.sh evidence/n2-xxx.pcap
# ------------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PCAP="${1:-}"
if [[ -z "$PCAP" ]]; then
  PCAP="$(ls -t "$REPO"/evidence/n2-*.pcap 2>/dev/null | head -1 || true)"
  [[ -n "$PCAP" ]] || { echo "用法: $0 <n2.pcap>   或先抓一条" >&2; exit 1; }
  echo "用最新: $PCAP"
fi
command -v tshark >/dev/null 2>&1 || { echo "需要 tshark: sudo apt-get install -y tshark" >&2; exit 1; }

cat <<'EOF'
procedureCode 速查（本仓库会发的）:
  21 NGSetup          25 PathSwitch         42 UEContextReleaseRequest
  41 UEContextRelease (Command/Complete)     9 ErrorIndication
  20 NGReset          12 HandoverRequired   13 HandoverRequest(/Ack)
  11 HandoverNotify   15 InitialUEMessage   35 RANConfigurationUpdate
  48 UL RAN Config Transfer   47 DL RAN Config Transfer
  24 Paging           30 PDUSessionResourceNotify
   2 CellTrafficTrace 49 UL RAN Status Transfer
  50 UL UE-assoc NRPPa
谁发给谁: ip.src=13.254.241.142 且不是合法 gNB 单独关联的，多半是流氓。
合法 gNB 和流氓共用源 IP，靠 SCTP 端口 / 时间对齐终端 C。
EOF
echo
echo "==== 一行一条 ===="
tshark -r "$PCAP" -Y ngap -T fields -E header=y -E separator=$'\t' \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e sctp.srcport \
  -e sctp.dstport \
  -e ngap.procedureCode \
  -e _ws.col.Info \
  -e ngap.AMF_UE_NGAP_ID \
  -e ngap.aMF_UE_NGAP_ID \
  -e ngap.RAN_UE_NGAP_ID \
  -e ngap.rAN_UE_NGAP_ID \
  -e ngap.nAS_PDU \
  2>/dev/null || tshark -r "$PCAP" -Y ngap -T fields -E header=y \
  -e frame.number -e ip.src -e ip.dst -e ngap.procedureCode -e _ws.col.Info

echo
echo "==== 5G-S-TMSI / GUTI（有则打）===="
tshark -r "$PCAP" -Y 'ngap || nas-5gs' -T fields -E header=y -E separator=$'\t' \
  -e frame.number \
  -e nas_5gs.mm.5g_tmsi \
  -e nas_5gs.mm.amf_set_id \
  -e nas_5gs.mm.amf_pointer \
  -e ngap.fiveG_S_TMSI \
  2>/dev/null | awk 'NR==1 || NF>1' || true
