#!/bin/bash
# 5g-lab: 多 UE 启动脚本 —— 给"正在运行的 gNB"挂上多个模拟 UE（每个不同 IMSI）
#
# 前提：先用 ran.sh 起好一对 gNB+UE（那是 UE #1，IMSI ...001）。
#       本脚本再额外挂 N 个 UE（默认从 IMSI #2 起），全部连同一个 gNB。
#
# 用法：
#   ./scripts/ue.sh up   ueransim <core> <数量> [起始序号]   # 起 N 个额外 UE
#   ./scripts/ue.sh up   oai      <core> <数量> [起始序号]
#   ./scripts/ue.sh down ueransim <core>                     # 停本 ran×core 的所有额外 UE
#   ./scripts/ue.sh list                                     # 列出所有额外 UE
#   ./scripts/ue.sh ping ueransim <core>                     # 让每个额外 UE ping 一次外网
#
# 示例（Open5GS 上同时跑 5 个 UERANSIM UE）：
#   ./scripts/ran.sh up ueransim open5gs        # gNB + UE#1 (IMSI ...001)
#   ./scripts/ue.sh  up ueransim open5gs 4      # 再加 UE#2..#5 (IMSI ...002..005)
#
# 说明：
#   - IMSI 用核心网里已灌好的 10 个（001010000000001..010），最多同时 10 个 UE。
#   - UERANSIM 多 UE 已实测（5 个并发注册+各自独立 IP+ping 通）。
#   - OAI(RFsim) 多 UE 本脚本已支持，但未在本环境逐一实测；OAI RFsim 一个 gNB 挂多个 UE
#     有时需 gNB 侧参数配合，若某个 UE 起不来看 `docker logs <容器>` 排查。
#   - srsUE(ZMQ) 是点对点射频，一个 gNB 只能接一个 srsUE，故本脚本不支持 srsran 多 UE。

set -e
export MSYS_NO_PATHCONV=1   # 防止 Git Bash 把 /dev/net/tun 等容器内路径转成 Windows 路径
LAB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ACTION="$1"; RAN="$2"; CORE="$3"; COUNT="${4:-1}"; START="${5:-2}"

usage() {
  echo "用法: $0 {up|down|list|ping} {ueransim|oai} {open5gs|oai|free5gc|sdcore} [数量] [起始序号]"
  exit 1
}

imsi_of() { printf "0010100000000%02d" "$1"; }   # 序号 → IMSI

load_env() {
  local f="$LAB_ROOT/ran/env/$1.env"
  [[ -f "$f" ]] || { echo "缺少 env: $f"; exit 1; }
  # shellcheck disable=SC1090
  set -a; source "$f"; set +a
}

prefix() { echo "xue-$1-$2"; }   # 额外 UE 容器名前缀：xue-<ran>-<core>

case "$ACTION" in
  list)
    docker ps --filter "name=xue-" --format 'table {{.Names}}\t{{.Status}}'
    exit 0 ;;
  up|down|ping) [[ -z "$RAN" || -z "$CORE" ]] && usage ;;
  *) usage ;;
esac

[[ "$RAN" == "srsran" ]] && { echo "srsUE(ZMQ) 是点对点射频，一个 gNB 只能接一个 UE，不支持多 UE。请用 ueransim 或 oai。"; exit 1; }
load_env "$CORE"
PFX=$(prefix "$RAN" "$CORE")

case "$ACTION" in
  down)
    ids=$(docker ps -aq --filter "name=${PFX}-")
    [[ -n "$ids" ]] && docker rm -f $ids >/dev/null && echo ">> 已停止 $RAN×$CORE 的所有额外 UE" || echo "（没有额外 UE 在跑）"
    ;;
  ping)
    for c in $(docker ps --filter "name=${PFX}-" --format '{{.Names}}'); do
      if [[ "$RAN" == "ueransim" ]]; then IF=uesimtun0; else IF=oaitun_ue1; fi
      r=$(docker exec "$c" bash -c "ping -I $IF -c 2 -W 3 8.8.8.8 2>/dev/null | tail -1" 2>/dev/null || echo "无隧道")
      echo "$c: $r"
    done
    ;;
  up)
    END=$((START + COUNT - 1))
    [[ $END -gt 10 ]] && { echo "IMSI 池只有 10 个（001..010），起始 $START + 数量 $COUNT 超了"; exit 1; }
    echo ">> 在 $CORE 上为 $RAN gNB 挂 $COUNT 个额外 UE（IMSI 序号 $START..$END）"
    for n in $(seq "$START" "$END"); do
      IMSI=$(imsi_of "$n"); NAME="${PFX}-${n}"
      docker rm -f "$NAME" >/dev/null 2>&1 || true
      if [[ "$RAN" == "ueransim" ]]; then
        docker run -dit --name "$NAME" --network "$CORE_NETWORK" \
          --cap-add NET_ADMIN --device /dev/net/tun --privileged \
          -v "$LAB_ROOT/ran/ueransim:/mnt/ueransim" \
          -e COMPONENT_NAME=ueransim-ue -e GNB_HOST=ueransim-gnb \
          -e MCC="$MCC" -e MNC="$MNC" -e APN="${APN:-internet}" \
          -e SLICE_SST="${SLICE_SST:-1}" -e SLICE_SD="${SLICE_SD:-}" \
          -e UE1_IMSI="$IMSI" -e UE1_KI="$UE1_KI" -e UE1_OP="$UE1_OP" \
          -e UE1_OP_TYPE="${UE1_OP_TYPE:-OPC}" -e UE1_AMF="${UE1_AMF:-8000}" \
          docker_ueransim >/dev/null
      else  # oai
        docker run -dit --name "$NAME" --network "$CORE_NETWORK" \
          --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun --privileged \
          -v "$LAB_ROOT/ran/oai:/mnt/oai" --entrypoint /bin/bash \
          -e GNB_HOST=oai-gnb -e APN="${APN:-internet}" \
          -e SLICE_SST="${SLICE_SST:-1}" -e SLICE_SD="${SLICE_SD:-}" \
          -e UE1_IMSI="$IMSI" -e UE1_KI="$UE1_KI" \
          -e UE1_OP="${UE1_OPC:-$UE1_OP}" \
          oaisoftwarealliance/oai-nr-ue:2025.w46 /mnt/oai/nr-ue-init.sh >/dev/null
      fi
      echo "   $NAME  IMSI $IMSI"
    done
    echo ">> 完成。查看注册：docker logs -f ${PFX}-${START}    数据面：./scripts/ue.sh ping $RAN $CORE"
    ;;
esac
