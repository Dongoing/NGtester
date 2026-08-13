#!/bin/bash
# 5g-lab 核心网管理脚本
# 用法:
#   ./scripts/core.sh up   <open5gs|oai|free5gc|sdcore>
#   ./scripts/core.sh down <open5gs|oai|free5gc|sdcore>
#   ./scripts/core.sh ps   <open5gs|oai|free5gc|sdcore>
#   ./scripts/core.sh logs <open5gs|oai|free5gc> [服务名]

set -e
LAB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$LAB_ROOT/scripts/common.sh"   # OS 检测 + kind/helm 定位（跨 Windows/Ubuntu）
ACTION="$1"
CORE="$2"
SVC="$3"

usage() { echo "用法: $0 {up|down|ps|logs} {open5gs|oai|free5gc|sdcore} [服务名]"; exit 1; }
[[ -z "$ACTION" || -z "$CORE" ]] && usage

ensure_net() {  # 三套 docker 核心网共享的固定网络（AMF 恒在 172.30.0.10）
  docker network inspect net-5glab >/dev/null 2>&1 || \
    docker network create net-5glab --subnet 172.30.0.0/16 --gateway 172.30.0.1 --ip-range 172.30.200.0/24
}

core_dir() {  # 核心网名 → 目录名（oai 的目录是 oai-cn5g）
  case "$1" in oai) echo oai-cn5g ;; *) echo "$1" ;; esac
}

compose_core() {  # docker compose 版核心网（open5gs/oai/free5gc）
  local dir="$LAB_ROOT/cores/$(core_dir "$1")"
  [[ -d "$dir" ]] || { echo "未知核心网: $1"; exit 1; }
  ( cd "$dir" && shift && docker compose -f core.yaml "$@" )
}

case "$CORE" in
  open5gs|oai|free5gc)
    case "$ACTION" in
      up)
        ensure_net
        compose_core "$CORE" up -d
        if [[ "$CORE" == "open5gs" ]]; then
          echo ">> 预置 Open5GS 测试订阅..."
          sleep 8
          "$LAB_ROOT/scripts/provision.sh" open5gs || true
        elif [[ "$CORE" == "free5gc" ]]; then
          echo ">> 等 WebUI 就绪后预置 free5GC 订阅..."
          for i in $(seq 1 30); do curl -s -o /dev/null http://localhost:5000/api/login && break; sleep 2; done
          "$LAB_ROOT/scripts/provision.sh" free5gc || true
        fi
        echo ">> $CORE 核心网已启动"
        ;;
      down) compose_core "$CORE" down ;;
      ps)   compose_core "$CORE" ps ;;
      logs) ( cd "$LAB_ROOT/cores/$(core_dir "$CORE")" && docker compose -f core.yaml logs -f ${SVC:-} ) ;;
      *) usage ;;
    esac
    ;;
  sdcore)
    HELM="$HELM_BIN"
    case "$ACTION" in
      up)
        kubectl create namespace sdcore 2>/dev/null || true
        "$HELM" install sd-core oci://ghcr.io/omec-project/sd-core --version 4.1.3 \
          -n sdcore -f "$LAB_ROOT/cores/sdcore/values.yaml"
        echo ">> SD-Core 部署中，用 './scripts/core.sh ps sdcore' 观察 pod 就绪"
        ;;
      down) "$HELM" uninstall sd-core -n sdcore || true ;;
      ps)   kubectl get pods -n sdcore ;;
      logs) kubectl logs -n sdcore -l app=${SVC:-amf} -f ;;
      *) usage ;;
    esac
    ;;
  *) usage ;;
esac
