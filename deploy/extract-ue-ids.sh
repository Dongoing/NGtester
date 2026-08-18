#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# 读出华为这一次随机的 AMF-UE-NGAP-ID。
#
# 唯一稳妥的办法：问正在跑的 UERANSIM **gNB**
#   nr-cli --dump
#   nr-cli <UERANSIM-gnb-...> --exec "ue-list"
# 输出里的 amf-ngap-id 就是 AU。
#
# 不要问 UE 的 info/status —— UE CLI 没有这个字段。
# tshark 抓包是备选，必须在注册过程中抓。
#
# 用法（ngap_tester/ 下，gNB+UE 已注册）:
#   ./deploy/extract-ue-ids.sh
#   ./deploy/extract-ue-ids.sh --guti           # 再尽量拆 5G-S-TMSI（InitialUE 用）
#   ./deploy/extract-ue-ids.sh --watch          # 先开抓再重启 UE
#   ./deploy/extract-ue-ids.sh -r /tmp/n2.pcap
# ------------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/real-amf/real-amf.env"

AMF_ADDR="${AMF_ADDR:?}"
UERANSIM_DIR="${UERANSIM_DIR:-$HOME/UERANSIM}"
CLI="${UERANSIM_DIR}/build/nr-cli"

FIELDS=(
  -T fields -E header=y -E separator=$'\t'
  -e frame.time_relative
  -e ngap.procedureCode
  -e ngap.AMF_UE_NGAP_ID
  -e ngap.aMF_UE_NGAP_ID
  -e ngap.RAN_UE_NGAP_ID
  -e ngap.rAN_UE_NGAP_ID
)

print_au() {
  # stdin: nr-cli ue-list yaml
  local yaml="$1"
  echo "$yaml"
  echo
  local ids
  ids="$(printf '%s\n' "$yaml" | grep -E 'amf-ngap-id|amfUeNgapId|amf_ngap_id' | head -5 || true)"
  if [[ -z "$ids" ]]; then
    echo "[extract] ue-list 里没有 amf-ngap-id：UE 可能还没完成 InitialContextSetup"
    return 1
  fi
  echo "========================================"
  echo "  把下面的 amf-ngap-id 填进 --amf-ue-id / --source-amf-ue-id"
  echo "$ids"
  echo "========================================"
  return 0
}

try_nrcli() {
  [[ -x "$CLI" ]] || { echo "[extract] 没有 $CLI"; return 1; }

  echo "[extract] nr-cli --dump"
  local nodes
  nodes="$("$CLI" --dump 2>/dev/null || true)"
  echo "$nodes"
  [[ -n "$nodes" ]] || { echo "[extract] --dump 为空：nr-gnb / nr-ue 没在跑，或不是同一用户"; return 1; }

  local gnb
  gnb="$(printf '%s\n' "$nodes" | grep -E '^UERANSIM-gnb-' | head -1 || true)"
  if [[ -z "$gnb" ]]; then
    # 兜底：对每个非 imsi- 节点试 ue-list
    gnb="$(printf '%s\n' "$nodes" | grep -v '^imsi-' | head -1 || true)"
  fi
  if [[ -z "$gnb" ]]; then
    echo "[extract] dump 里没有 gNB 节点。合法 gNB 必须在跑。"
    return 1
  fi

  echo "[extract] nr-cli $gnb --exec ue-list"
  local out
  if ! out="$("$CLI" "$gnb" --exec "ue-list" 2>/dev/null)"; then
    echo "[extract] ue-list 失败"
    return 1
  fi
  print_au "$out"
}

try_guti() {
  [[ -x "$CLI" ]] || { echo "[extract] 没有 $CLI"; return 1; }
  local nodes ue
  nodes="$("$CLI" --dump 2>/dev/null || true)"
  echo "[extract] nr-cli --dump"
  echo "$nodes"
  ue="$(printf '%s\n' "$nodes" | grep -E "^imsi-${UE1_IMSI}$|^imsi-" | head -1 || true)"
  if [[ -z "$ue" ]]; then
    echo "[extract] dump 里没有 UE 节点。终端 B 的 run-ue.sh 必须在跑。"
    return 1
  fi
  echo
  echo "[extract] nr-cli $ue --exec info"
  local info
  info="$("$CLI" "$ue" --exec "info" 2>/dev/null || true)"
  echo "$info"
  echo
  echo "========================================"
  echo "  在上面找 GUTI / 5G-S-TMSI / TMSI / AMF-Set / AMF-Pointer"
  echo "  填 InitialUE / chain-initue-release："
  echo "    --amf-set-id 0x<10bit>  --amf-pointer 0x<6bit>  --tmsi <8hex>"
  echo "  终端 B（nr-ue）日志里搜 GUTI 往往更全。"
  echo "  或注册时抓 N2：sudo ./deploy/real-amf/capture-n2.sh guti"
  echo "  再 ./deploy/real-amf/decode-n2.sh evidence/n2-guti-*.pcap"
  echo "========================================"
  if [[ -z "$info" ]]; then
    echo "[extract] info 空。看终端 B 日志，或抓注册过程的 N2。"
    return 1
  fi
  return 0
}

dump_pcap() {
  command -v tshark >/dev/null 2>&1 || { echo "需要: sudo apt-get install -y tshark" >&2; exit 1; }
  tshark -r "$1" -Y ngap "${FIELDS[@]}"
}

live_tshark() {
  command -v tshark >/dev/null 2>&1 || { echo "需要: sudo apt-get install -y tshark" >&2; exit 1; }
  local secs="${1:-}"
  local filter="sctp port 38412 and host $AMF_ADDR"
  echo "[extract] $filter"
  echo "[extract] 保持本窗口，去另一个终端重启 ./deploy/real-amf/run-ue.sh"
  echo
  if [[ -n "$secs" ]]; then
    timeout --signal=INT "$secs" tshark -i any -f "$filter" -Y ngap "${FIELDS[@]}" || true
  else
    tshark -i any -f "$filter" -Y ngap "${FIELDS[@]}"
  fi
}

echo "[extract] AMF=$AMF_ADDR  （华为 AU 每次随机）"

case "${1:-}" in
  -r)
    dump_pcap "${2:?用法: $0 -r file.pcap}"
    ;;
  --guti)
    try_guti || true
    echo
    echo "[extract] 同时再读一次 AU（InitialUE 链也要用）:"
    try_nrcli || true
    ;;
  --watch)
    live_tshark
    ;;
  "" )
    if try_nrcli; then
      exit 0
    fi
    echo
    echo "[extract] nr-cli 没拿到 AU。检查："
    echo "  1) 终端 A 的 run-gnb.sh、终端 B 的 run-ue.sh 都还在"
    echo "  2) 本脚本和 UERANSIM 是同一用户（nr-cli 走本机 IPC）"
    echo "  3) 备选: sudo $0 --watch 然后再重启 run-ue.sh"
    exit 1
    ;;
  * )
    if [[ "$1" =~ ^[0-9]+$ ]]; then
      live_tshark "$1"
    else
      echo "未知参数: $1  （无参数 | --guti | --watch | -r pcap）" >&2
      exit 2
    fi
    ;;
esac
