#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# 内网里看 UERANSIM 数据面通不通（不要 ping 8.8.8.8）。
#
# 5G 数据面两截：
#   N6  UE tun → UPF → DNN（huawei.com 内网）
#   N3  合法 gNB ↔ UPF 的 GTP-U（UDP 2152）—— 攻击 Path Switch 切的是这一截
#
# 用法（仓库根目录，UE 已注册、uesimtun0 已出现）:
#   ./deploy/real-amf/check-up.sh           # IP / 网关 / ping / ps-list
#   ./deploy/real-amf/check-up.sh --n3      # 再抓 8 秒 N3 GTP-U
#   PING_TARGET=10.x.x.x ./deploy/real-amf/check-up.sh
# ------------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/real-amf.env"

UERANSIM_DIR="${UERANSIM_DIR:-$HOME/UERANSIM}"
CLI="${UERANSIM_DIR}/build/nr-cli"
HOST_IP="${HOST_IP:-}"
TUN="${TUN:-uesimtun0}"
PING_TARGET="${PING_TARGET:-}"

echo "==== 1) UE 隧道 $TUN ===="
if ! ip link show "$TUN" >/dev/null 2>&1; then
  echo "FAIL: 没有 $TUN。UE 没建上 PDU 会话，或 run-ue.sh 没用 sudo。"
  exit 1
fi
ip -4 -o addr show "$TUN"
ip -4 route show dev "$TUN" || true

UE_CIDR="$(ip -4 -o addr show "$TUN" | awk '{print $4}' | head -1)"
UE_IP="${UE_CIDR%%/*}"
PREFIX="${UE_CIDR##*/}"
echo "  UE_IP=$UE_IP /$PREFIX"

GW="$(ip -4 route show dev "$TUN" | awk '/default/{print $3; exit}')"
if [[ -z "$GW" && -n "$UE_IP" && "$PREFIX" != "32" ]]; then
  # 没有 default 时试网段 .1（很多 UPF 池子把网关放这儿）
  IFS=. read -r a b c d <<<"$UE_IP"
  GW="$a.$b.$c.1"
  echo "  无 default 路由，试网关 $GW"
fi
[[ -n "$GW" ]] && echo "  GW=$GW"

echo
echo "==== 2) UERANSIM UE 会话（ps-list）===="
if [[ -x "$CLI" ]]; then
  "$CLI" --dump 2>/dev/null || true
  "$CLI" "imsi-${UE1_IMSI}" --exec "ps-list" 2>/dev/null || \
    echo "  nr-cli ps-list 失败（节点名可能不是 imsi-${UE1_IMSI}，看 --dump）"
else
  echo "  没有 nr-cli"
fi

echo
echo "==== 3) N6 探测（内网，不是外网）===="
echo "  通 = 至少 ICMP 到了 UPF/DNN 网关；不通也不等于 N3 死（华为常禁 ICMP）"
try_ping() {
  local dst="$1"
  echo "  ping -I $TUN $dst"
  ping -I "$TUN" -c 3 -W 2 "$dst" && return 0
  return 1
}
ok=0
if [[ -n "$PING_TARGET" ]]; then
  try_ping "$PING_TARGET" && ok=1 || true
  echo "  （PING_TARGET 来自环境 / 华为给的内网地址）"
elif [[ -n "$GW" ]]; then
  try_ping "$GW" && ok=1 || true
else
  echo "  不知道该 ping 谁。问华为要一个 DNN=$DNN 里能回包的地址，然后："
  echo "    PING_TARGET=<那个地址> $0"
fi

echo
echo "==== 4) 结论（N6）===="
if [[ "$ok" -eq 1 ]]; then
  echo "  N6 有回包：数据面转发是通的。Path Switch 前后各跑一次，对比 ping。"
else
  echo "  N6 没回包：先看第 1 步有没有 UE_IP（有 = 会话建了）。"
  echo "  再看 --n3：N3 有 GTP-U 说明 UPF↔gNB 在动，只是 DNN 不回 ICMP。"
  echo "  问华为要：DNN $DNN 里一台会回 ping/HTTP 的内网地址。"
fi

if [[ "${1:-}" == "--n3" ]]; then
  echo
  echo "==== 5) N3 GTP-U（UDP 2152，合法 gNB 的 $HOST_IP）===="
  echo "  另开终端对 $TUN 打 ping/流量，这里应看到 2152。"
  echo "  Path Switch 成功切面后：旧 TEID 变少，pcap 里出现 TEID 0x11111111。"
  echo "  同机不要开 gtpu-sink（和 nr-gnb 抢 2152）。"
  if ! command -v tcpdump >/dev/null; then
    echo "  需要: sudo apt-get install -y tcpdump"
    exit 0
  fi
  if [[ -z "$HOST_IP" ]]; then
    echo "  real-amf.env 里 HOST_IP 为空"
    exit 0
  fi
  echo "  抓 8 秒：sudo tcpdump -n -i any udp port 2152 and host $HOST_IP"
  sudo tcpdump -n -c 20 -i any udp port 2152 and host "$HOST_IP" || true
fi
