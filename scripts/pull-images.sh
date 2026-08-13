#!/bin/bash
# 5g-lab: 一键拉取并打标签所有需要的 Docker 镜像
# 迁移到新机器后先跑这个（需要能访问 ghcr.io / docker.io，若在国内可能要配代理或镜像加速）。
#
# 用法: ./scripts/pull-images.sh [all|base|oai|free5gc|infra]
#   不带参数 = all（全部）

set -e
WHAT="${1:-all}"

pull_tag() {  # pull_tag <远程镜像> <本地标签>
  echo ">> $1  ->  $2"
  docker pull "$1" && docker tag "$1" "$2"
}
pull() { echo ">> $1"; docker pull "$1"; }

# ---- 基础镜像：herlesupreeth 预构建，pull 后打成本地短标签（compose 里用短标签）----
base_images() {
  pull_tag ghcr.io/herlesupreeth/docker_open5gs:master docker_open5gs
  pull_tag ghcr.io/herlesupreeth/docker_ueransim:master docker_ueransim
  pull_tag ghcr.io/herlesupreeth/docker_srsran:master  docker_srsran
  pull_tag ghcr.io/herlesupreeth/docker_srslte:master  docker_srslte
}

# ---- OAI CN5G + RAN ----
oai_images() {
  for nf in amf ausf nrf smf udm udr upf; do pull oaisoftwarealliance/oai-$nf:develop; done
  pull oaisoftwarealliance/trf-gen-cn5g:latest
  pull oaisoftwarealliance/oai-gnb:2025.w46
  pull oaisoftwarealliance/oai-nr-ue:2025.w46
}

# ---- free5GC + eUPF ----
free5gc_images() {
  for nf in amf ausf chf nrf nssf pcf smf udm udr webui; do pull free5gc/$nf:v4.2.3; done
  pull ghcr.io/edgecomllc/eupf:latest
}

# ---- 基础设施 ----
infra_images() {
  pull mongo:6.0     # open5gs
  pull mongo:4.4     # free5gc
  pull mysql:9.6.0   # oai
  pull alpine:3.20   # free5gc eupf-routes 辅助
}

case "$WHAT" in
  base)    base_images ;;
  oai)     oai_images ;;
  free5gc) free5gc_images ;;
  infra)   infra_images ;;
  all)     base_images; oai_images; free5gc_images; infra_images ;;
  *) echo "用法: $0 [all|base|oai|free5gc|infra]"; exit 1 ;;
esac

echo ""
echo ">> 完成。注意：SD-Core 的镜像（ghcr.io/omec-project/*）由 kind 集群的 containerd"
echo "   在 helm 部署时自动拉取，不在本脚本内。"
