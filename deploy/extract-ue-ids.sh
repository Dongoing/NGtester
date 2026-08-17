#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# 读出华为这一次随机的 AMF-UE-NGAP-ID / 5G-TMSI。
#
# 优先顺序：
#   1) UERANSIM nr-cli（UE 正在跑时最稳）
#   2) 已有 pcap：  sudo ./deploy/extract-ue-ids.sh -r /tmp/n2.pcap
#   3) 实时抓包：必须在【注册之前】开抓，或抓的同时重启 run-ue.sh
#      注册完再抓 20 秒，空结果是正常的（InitialContextSetup 已经过了）
#
# 用法（在 ngap_tester/ 下）:
#   ./deploy/extract-ue-ids.sh              # 先试 nr-cli，没有再提示抓包
#   ./deploy/extract-ue-ids.sh --watch      # tshark 一直抓到 Ctrl-C（先开这个再起 UE）
#   ./deploy/extract-ue-ids.sh 60           # tshark 抓 60 秒
#   ./deploy/extract-ue-ids.sh -r cap.pcap
#   ./deploy/extract-ue-ids.sh --from-log /path/to/gnb.log
# ------------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/real-amf/real-amf.env"

AMF_ADDR="${AMF_ADDR:?}"
UERANSIM_DIR="${UERANSIM_DIR:-$HOME/UERANSIM}"
UE_NODE="imsi-${UE1_IMSI}"

FIELDS=(
  -T fields -E header=y -E separator=$'\t'
  -e frame.time_relative
  -e ngap.procedureCode
  -e ngap.AMF_UE_NGAP_ID
  -e ngap.RAN_UE_NGAP_ID
  -e ngap.fiveG_S_TMSI
  -e nas_5gs.mm.5g_tmsi
  -e nas_5gs.mm.amf_set_id
  -e nas_5gs.mm.amf_pointer
)

try_nrcli() {
  local cli="$UERANSIM_DIR/build/nr-cli"
  [[ -x "$cli" ]] || return 1
  echo "[extract] nr-cli dump:"
  "$cli" -d 2>/dev/null || true
  echo "[extract] nr-cli $UE_NODE -e info :"
  if "$cli" "$UE_NODE" -e info 2>/dev/null; then
    echo
    echo "[extract] 在上面找 amfUeNgapId / AMF-UE-NGAP-ID / 5G-TMSI / GUTI"
    return 0
  fi
  return 1
}

from_log() {
  local f="$1"
  [[ -f "$f" ]] || { echo "没有这个日志: $f" >&2; exit 1; }
  echo "[extract] grep $f"
  grep -nEi 'amf-ue-ngap-id|amfUeNgapId|AMF_UE_NGAP_ID|5G-S-TMSI|5G-TMSI|GUTI' "$f" || {
    echo "日志里没有这些字段。UERANSIM 默认 info 级常常不打印 AU，改用 nr-cli 或抓包。"
    return 1
  }
}

dump_pcap() {
  command -v tshark >/dev/null 2>&1 || { echo "需要: sudo apt-get install -y tshark" >&2; exit 1; }
  tshark -r "$1" -Y ngap "${FIELDS[@]}"
}

live_tshark() {
  command -v tshark >/dev/null 2>&1 || { echo "需要: sudo apt-get install -y tshark" >&2; exit 1; }
  local secs="${1:-}"
  local filter="sctp port 38412 and host $AMF_ADDR"
  echo "[extract] filter: $filter"
  echo "[extract] 若 UE 已经注册完，这里会是空的。请保持本窗口抓着，去另一个终端重启 ./deploy/real-amf/run-ue.sh"
  echo
  if [[ -n "$secs" ]]; then
    timeout --signal=INT "$secs" tshark -i any -f "$filter" -Y ngap "${FIELDS[@]}" || true
  else
    tshark -i any -f "$filter" -Y ngap "${FIELDS[@]}"
  fi
}

echo "[extract] AMF=$AMF_ADDR  UE=$UE_NODE  （华为 AU 每次随机，旧数字作废）"

case "${1:-}" in
  -r)
    dump_pcap "${2:?用法: $0 -r file.pcap}"
    ;;
  --from-log)
    from_log "${2:?用法: $0 --from-log gnb.log}"
    ;;
  --watch)
    live_tshark
    ;;
  "" )
    if try_nrcli; then
      exit 0
    fi
    echo
    echo "[extract] nr-cli 没问到（UE 没在跑，或节点名不是 $UE_NODE）。"
    echo "  做法 A: 先 sudo $0 --watch，再重启 run-ue.sh"
    echo "  做法 B: sudo tcpdump -i any -s 0 -w /tmp/n2.pcap host $AMF_ADDR and sctp"
    echo "          重启 UE 后 Ctrl-C，再 $0 -r /tmp/n2.pcap"
    exit 1
    ;;
  * )
    if [[ "$1" =~ ^[0-9]+$ ]]; then
      live_tshark "$1"
    else
      echo "未知参数: $1" >&2
      exit 2
    fi
    ;;
esac

echo
echo "[extract] 把 AMF_UE_NGAP_ID 填进 --amf-ue-id / --source-amf-ue-id"
echo "         5G-TMSI / AMF-Set-ID / AMF-Pointer 填进 initial-ue / chain-initue-release"
