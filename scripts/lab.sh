#!/bin/bash
# 5g-lab 统一入口 —— 薄封装，转发到各专用脚本（它们已做 Windows/Ubuntu 自适应）
# 用法:
#   ./scripts/lab.sh core  up|down|ps|logs <open5gs|oai|free5gc|sdcore> [服务]
#   ./scripts/lab.sh ran   up|down|logs <ueransim|srsran|oai> <core> [gnb|ue]
#   ./scripts/lab.sh ue    up|down|list|ping <ueransim|oai> <core> [数量] [起始]
#   ./scripts/lab.sh clock                 # 修 WSL2 时钟（原生 Linux 自动跳过）
#   ./scripts/lab.sh images [all|base|oai|free5gc|infra]
#   ./scripts/lab.sh sdcore-setup          # SD-Core 的 kind 节点一次性准备
#   ./scripts/lab.sh status                # 列出所有容器状态

set -e
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sub="${1:-}"; shift 2>/dev/null || true

case "$sub" in
  core)         exec bash "$D/core.sh" "$@" ;;
  ran)          exec bash "$D/ran.sh" "$@" ;;
  ue)           exec bash "$D/ue.sh" "$@" ;;
  clock)        exec bash "$D/fix-clock.sh" "$@" ;;
  images)       exec bash "$D/pull-images.sh" "$@" ;;
  sdcore-setup) exec bash "$D/sdcore-setup.sh" "$@" ;;
  status)       docker ps --format 'table {{.Names}}\t{{.Status}}' ;;
  *)
    echo "用法: $0 {core|ran|ue|clock|images|sdcore-setup|status} ..."
    echo "  例: $0 core up open5gs   |   $0 ran up ueransim open5gs   |   $0 ue up ueransim open5gs 4"
    exit 1 ;;
esac
