#!/bin/bash
# 5g-lab UERANSIM gNB 启动脚本
# 容器 IP 运行时自动探测，AMF 地址由 CORE_AMF_ADDR 注入 —— 可挂接任意核心网

set -e

# 取容器主 IPv4（双栈网络下 /etc/hosts 末行可能是 IPv6，必须显式取 IPv4）
GNB_IP=$(ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1 | head -1)
[[ -z "$GNB_IP" ]] && GNB_IP=$(awk 'END{print $1}' /etc/hosts)

echo "gNB IP: $GNB_IP, AMF: $CORE_AMF_ADDR, PLMN: $MCC/$MNC, TAC: $TAC, SST: ${SLICE_SST:-1}"

# 可选：注入额外路由（格式 "网段:网关,网段:网关"，SD-Core 场景用于到 UPF N3 的路由）
if [[ -n "$EXTRA_ROUTES" ]]; then
  IFS=',' read -ra ROUTES <<< "$EXTRA_ROUTES"
  for r in "${ROUTES[@]}"; do
    net="${r%%:*}"; gw="${r##*:}"
    ip route replace "$net" via "$gw" && echo "route added: $net via $gw"
  done
fi

SLICE_BLOCK="  - sst: ${SLICE_SST:-1}"
if [[ -n "$SLICE_SD" ]]; then
  SLICE_BLOCK="$SLICE_BLOCK
    sd: $SLICE_SD"
fi

cat > /UERANSIM/config/gnb.yaml <<EOF
mcc: '$MCC'
mnc: '$MNC'

nci: '0x000000010'
idLength: 32
tac: $TAC

linkIp: $GNB_IP
ngapIp: $GNB_IP
gtpIp: $GNB_IP

amfConfigs:
  - address: $CORE_AMF_ADDR
    port: 38412

slices:
$SLICE_BLOCK

ignoreStreamIds: true
EOF

cd /UERANSIM/build
./nr-gnb -c /UERANSIM/config/gnb.yaml &
exec bash $@
