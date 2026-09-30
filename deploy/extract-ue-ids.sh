#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# 读出华为这一次随机的 AMF-UE-NGAP-ID（AU）和合法 gNB 上的 RAN-UE-NGAP-ID（RU）。
#
# 唯一稳妥的办法：问正在跑的 UERANSIM **gNB**
#   nr-cli --dump
#   nr-cli <UERANSIM-gnb-...> --exec "ue-list"
# 输出里的 amf-ngap-id 是 AU，ran-ngap-id 是受害 RU。
# 华为 AMF 对 UE 关联消息会同时校验这一对；只填 AU、RU 用流氓默认 99/1 会被挡。
#
# GUTI 不在 UE 的 info 里（那里只有 SUPI/IMEI）。在 UE 的 status → stored-guti。
# 5G-S-TMSI = AMF Set ID + AMF Pointer + 5G-TMSI。AMF Region ID 不填进 retrieve-ue-info。
# tshark 抓包是备选，必须在注册过程中抓。
#
# 用法（ngap_tester/ 下，gNB+UE 已注册）:
#   ./deploy/extract-ue-ids.sh                  # AU/RU，并默认再打印 GUTI / 5G-S-TMSI
#   ./deploy/extract-ue-ids.sh --guti           # 与无参数相同（保留旧写法）
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

yaml_field() {
  # $1 yaml, $2 extended regex of the key
  printf '%s\n' "$1" | grep -E "$2" | head -1 | sed -E 's/^[^:]*:[[:space:]]*//' | tr -d "\"' " || true
}

as_hex() {
  local v="${1#0x}"
  v="${v#0X}"
  if [[ "$v" =~ ^[0-9]+$ ]]; then
    printf '0x%x' "$((10#$v))"
  elif [[ "$v" =~ ^[0-9a-fA-F]+$ ]]; then
    printf '0x%x' "$((16#$v))"
  else
    printf '%s' "$1"
  fi
}

as_tmsi() {
  local v="${1#0x}"
  v="${v#0X}"
  if [[ "$v" =~ ^[0-9]+$ ]]; then
    printf '%08x' "$((10#$v))"
  else
    printf '%08s' "$v" | tr ' ' '0'
  fi
}

cli_dump() {
  local nodes
  nodes="$("$CLI" --dump 2>/dev/null || true)"
  if [[ -z "$nodes" ]]; then
    nodes="$(sudo "$CLI" --dump 2>/dev/null || true)"
  fi
  printf '%s\n' "$nodes"
}

cli_exec() {
  # $1 node  $2 command. UE 由 sudo 拉起时，普通用户的 nr-cli 看不到它。
  local out
  out="$("$CLI" "$1" --exec "$2" 2>/dev/null || true)"
  if [[ -z "$out" ]]; then
    out="$(sudo "$CLI" "$1" --exec "$2" 2>/dev/null || true)"
  fi
  printf '%s\n' "$out"
}

print_au() {
  local yaml="$1" au ru au_v ru_v
  au_v="$(yaml_field "$yaml" 'amf-ngap-id|amfUeNgapId|amf_ngap_id')"
  ru_v="$(yaml_field "$yaml" 'ran-ngap-id|ranUeNgapId|ran_ngap_id')"
  if [[ -z "$au_v" ]]; then
    echo "[extract] ue-list 里没有 amf-ngap-id：UE 可能还没完成 InitialContextSetup"
    return 1
  fi
  echo "AU  --amf-ue-id / --source-amf-ue-id    $au_v"
  if [[ -n "$ru_v" ]]; then
    echo "RU  --ran-ue-id（受害侧，不是 99）       $ru_v"
  else
    echo "[extract] 没有 ran-ngap-id"
    return 1
  fi
  return 0
}

try_nrcli() {
  [[ -x "$CLI" ]] || { echo "[extract] 没有 $CLI"; return 1; }

  local nodes gnb out
  nodes="$(cli_dump)"
  [[ -n "$nodes" ]] || { echo "[extract] nr-cli 看不到节点：nr-gnb / nr-ue 没在跑"; return 1; }

  gnb="$(printf '%s\n' "$nodes" | grep -E '^UERANSIM-gnb-' | head -1 || true)"
  if [[ -z "$gnb" ]]; then
    gnb="$(printf '%s\n' "$nodes" | grep -v '^imsi-' | head -1 || true)"
  fi
  if [[ -z "$gnb" ]]; then
    echo "[extract] 没有 gNB 节点。合法 gNB 必须在跑。"
    return 1
  fi

  out="$(cli_exec "$gnb" ue-list)"
  [[ -n "$out" ]] || { echo "[extract] ue-list 为空"; return 1; }
  print_au "$out"
}

try_guti() {
  [[ -x "$CLI" ]] || { echo "[extract] 没有 $CLI"; return 1; }
  local nodes ue status set_id ptr tmsi
  nodes="$(cli_dump)"
  ue="$(printf '%s\n' "$nodes" | grep -E "^imsi-${UE1_IMSI}$|^imsi-" | head -1 || true)"
  if [[ -z "$ue" ]]; then
    echo "[extract] 没有 UE 节点。终端 B 的 run-ue.sh 要还在。"
    return 1
  fi

  # info 只有 SUPI/IMEI。GUTI 在 status 的 stored-guti。
  status="$(cli_exec "$ue" status)"
  [[ -n "$status" ]] || { echo "[extract] UE status 为空"; return 1; }

  set_id="$(yaml_field "$status" 'amf-set-id|amfSetId|amf_set_id')"
  ptr="$(yaml_field "$status" 'amf-pointer|amfPointer|amf_pointer')"
  tmsi="$(yaml_field "$status" '(^|[[:space:]])tmsi[[:space:]]*:')"
  if [[ -z "$set_id" || -z "$ptr" || -z "$tmsi" || "$tmsi" == "null" || "$set_id" == "null" ]]; then
    echo "[extract] status 里没有 stored-guti。注册还没分到 GUTI，或 UE 已掉线。"
    return 1
  fi

  set_id="$(as_hex "$set_id")"
  ptr="$(as_hex "$ptr")"
  tmsi="$(as_tmsi "$tmsi")"
  echo "AMF Set ID   --amf-set-id     $set_id"
  echo "AMF Pointer  --amf-pointer    $ptr"
  echo "5G-TMSI      --tmsi           $tmsi"
  echo "retrieve-ue-info --amf-set-id $set_id --amf-pointer $ptr --tmsi $tmsi"
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
  --guti|"")
    au_ok=0
    try_nrcli || au_ok=1
    echo
    guti_ok=0
    try_guti || guti_ok=1
    if [[ $au_ok -ne 0 && $guti_ok -ne 0 ]]; then
      echo
      echo "[extract] AU/RU 和 GUTI 都没拿到。检查："
      echo "  1) 终端 A 的 run-gnb.sh、终端 B 的 run-ue.sh 都还在"
      echo "  2) 本脚本和 UERANSIM 是同一用户（nr-cli 走本机 IPC）"
      echo "  3) 备选: sudo $0 --watch 然后再重启 run-ue.sh"
      exit 1
    fi
    ;;
  --watch)
    live_tshark
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
