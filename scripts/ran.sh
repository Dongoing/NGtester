#!/bin/bash
# 5g-lab 基站管理脚本 —— 把任意基站挂接到任意核心网
# 用法:
#   ./scripts/ran.sh up   <ueransim|srsran|oai> <open5gs|oai|free5gc|sdcore>
#   ./scripts/ran.sh down <ueransim|srsran|oai> <open5gs|oai|free5gc|sdcore>
#   ./scripts/ran.sh logs <ueransim|srsran|oai> <open5gs|oai|free5gc|sdcore> [gnb|ue]
#
# 8 种核心网×基站组合示例:
#   ./scripts/ran.sh up ueransim open5gs
#   ./scripts/ran.sh up srsran   oai
#   ./scripts/ran.sh up oai      free5gc

set -e
LAB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RAN_DIR="$LAB_ROOT/ran"
ACTION="$1"; RAN="$2"; CORE="$3"; WHICH="$4"

usage() {
  echo "用法: $0 {up|down|logs} {ueransim|srsran|oai} {open5gs|oai|free5gc|sdcore} [gnb|ue]"
  exit 1
}
[[ -z "$ACTION" || -z "$RAN" || -z "$CORE" ]] && usage

case "$RAN" in
  ueransim) COMPOSE="ueransim.yaml" ;;
  srsran)   COMPOSE="srsran-gnb.yaml" ;;
  oai)      COMPOSE="oai-gnb.yaml" ;;
  *) usage ;;
esac

ENVFILE="$RAN_DIR/env/$CORE.env"
[[ -f "$ENVFILE" ]] || { echo "缺少核心网参数文件: $ENVFILE"; exit 1; }

# SD-Core 的 AMF 是 K8s pod，IP 会变；启动前动态刷新到 env
if [[ "$CORE" == "sdcore" && "$ACTION" == "up" ]]; then
  AMF_IP=$(kubectl get pod -n sdcore -l app=amf -o jsonpath='{.items[0].status.podIP}' 2>/dev/null)
  if [[ -n "$AMF_IP" ]]; then
    sed -i "s|^CORE_AMF_ADDR=.*|CORE_AMF_ADDR=$AMF_IP|" "$ENVFILE"
    echo ">> SD-Core AMF pod IP = $AMF_IP（已写入 $CORE.env）"
  else
    echo "!! 无法获取 AMF pod IP，确认 SD-Core 已部署且 pod Running"; exit 1
  fi
fi

# srsRAN 只支持挂 docker-compose 版核心网（需静态 IP 同网段）
if [[ "$RAN" == "srsran" && "$CORE" == "sdcore" ]]; then
  echo "srsRAN(ZMQ) 暂不支持挂接 SD-Core（跨 kind 网络），请用 ueransim"; exit 1
fi

cd "$RAN_DIR"
case "$ACTION" in
  up)   docker compose -f "$COMPOSE" --env-file "$ENVFILE" up -d ;;
  down) docker compose -f "$COMPOSE" --env-file "$ENVFILE" down ;;
  logs)
    proj=$(grep -E '^CORE_NAME=' "$ENVFILE" | cut -d= -f2)
    case "$RAN" in
      ueransim) svc="ueransim-${WHICH:-gnb}" ;;
      srsran)   svc="srsran-${WHICH:-gnb}" ;;
      oai)      [[ "${WHICH:-gnb}" == "ue" ]] && svc="oai-nr-ue" || svc="oai-gnb" ;;
    esac
    docker compose -f "$COMPOSE" --env-file "$ENVFILE" logs -f "$svc"
    ;;
  *) usage ;;
esac
