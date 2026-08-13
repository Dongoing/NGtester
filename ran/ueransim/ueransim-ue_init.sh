#!/bin/bash
# 5g-lab UERANSIM UE 启动脚本
# 通过 Docker DNS 解析 gNB 容器（服务名 ueransim-gnb），凭据由环境变量注入

set -e

# 等待并解析 gNB 地址（compose 服务名在共享网络上有 DNS 别名）
GNB_HOST=${GNB_HOST:-ueransim-gnb}
for i in $(seq 1 30); do
  GNB_IP=$(getent ahostsv4 $GNB_HOST | awk '{print $1}' | head -1)
  [[ -n "$GNB_IP" ]] && break
  echo "waiting for gNB DNS ($GNB_HOST)..."; sleep 2
done
if [[ -z "$GNB_IP" ]]; then echo "ERROR: cannot resolve gNB host $GNB_HOST"; exit 1; fi

echo "UE IMSI: $UE1_IMSI, gNB: $GNB_IP, PLMN: $MCC/$MNC, APN: ${APN:-internet}"

SLICE_INDENT="      sst: ${SLICE_SST:-1}"
NSSAI_BLOCK="  - sst: ${SLICE_SST:-1}"
if [[ -n "$SLICE_SD" ]]; then
  SLICE_INDENT="$SLICE_INDENT
      sd: $SLICE_SD"
  NSSAI_BLOCK="$NSSAI_BLOCK
    sd: $SLICE_SD"
fi

cat > /UERANSIM/config/ue.yaml <<EOF
supi: 'imsi-$UE1_IMSI'
mcc: '$MCC'
mnc: '$MNC'

key: '$UE1_KI'
op: '$UE1_OP'
opType: '${UE1_OP_TYPE:-OPC}'
amf: '${UE1_AMF:-8000}'
imei: '${UE1_IMEI:-356938035643803}'
imeiSv: '${UE1_IMEISV:-4370816125816151}'

gnbSearchList:
  - $GNB_IP

uacAic:
  mps: false
  mcs: false

uacAcc:
  normalClass: 0
  class11: false
  class12: false
  class13: false
  class14: false
  class15: false

sessions:
  - type: 'IPv4'
    apn: '${APN:-internet}'
    slice:
$SLICE_INDENT

configured-nssai:
$NSSAI_BLOCK

default-nssai:
$NSSAI_BLOCK

integrity:
  IA1: true
  IA2: true
  IA3: true

ciphering:
  EA1: true
  EA2: true
  EA3: true

integrityMaxRate:
  uplink: 'full'
  downlink: 'full'
EOF

cd /UERANSIM/build
./nr-ue -c /UERANSIM/config/ue.yaml &
exec bash $@
