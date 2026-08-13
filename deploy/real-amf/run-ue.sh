#!/bin/bash
# ------------------------------------------------------------------------------
# 渲染并启动“合法 UE”，触发 5G-AKA 认证 + 注册 + 建 PDU 会话。
# 必须先在【另一个终端】跑 ./run-gnb.sh 且 NG Setup 成功。
# 用法:  ./run-ue.sh
# 成功后会出现 tun 网卡 uesimtun0，可: ping -I uesimtun0 <某地址>
# ------------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/real-amf.env"

UERANSIM_DIR="${UERANSIM_DIR:-$HOME/UERANSIM}"
AMF_ADDR="${AMF_ADDR:-}"

if [[ ! -x "$UERANSIM_DIR/build/nr-ue" ]]; then
  echo "[ue] 找不到 $UERANSIM_DIR/build/nr-ue，请先跑 ../bootstrap.sh 编译 UERANSIM" >&2
  exit 1
fi

# UE 通过 RLS(UDP) 找 gNB；gNB、UE 同机时用同一个源 IP。`|| true` 防 set -e 提前退出。
GNB_LINK_IP="${HOST_IP:-}"
if [[ -z "$GNB_LINK_IP" && -n "$AMF_ADDR" ]]; then
  GNB_LINK_IP="$(ip -4 route get "$AMF_ADDR" 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1 || true)"
fi
GNB_LINK_IP="${GNB_LINK_IP:-127.0.0.1}"

echo "[ue] IMSI=$UE1_IMSI  gNB search=$GNB_LINK_IP  PLMN=$MCC/$MNC  DNN=${DNN:-internet}"

SLICE_INDENT="      sst: ${SLICE_SST:-1}"
NSSAI_BLOCK="  - sst: ${SLICE_SST:-1}"
if [[ -n "${SLICE_SD:-}" ]]; then
  SLICE_INDENT="$SLICE_INDENT
      sd: $SLICE_SD"
  NSSAI_BLOCK="$NSSAI_BLOCK
    sd: $SLICE_SD"
fi

cat > "$HERE/ue.yaml" <<EOF
supi: 'imsi-$UE1_IMSI'
mcc: '$MCC'
mnc: '$MNC'

key: '$UE1_KI'
op: '$UE1_OPC'
opType: '${UE1_OP_TYPE:-OPC}'
amf: '${UE1_AMF:-8000}'
imei: '${UE1_IMEI:-356938035643803}'
imeiSv: '${UE1_IMEISV:-4370816125816151}'

gnbSearchList:
  - $GNB_LINK_IP

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
    apn: '${DNN:-internet}'
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

echo "[ue] 已生成 $HERE/ue.yaml，启动 nr-ue(需 root 建 tun) ..."
exec sudo "$UERANSIM_DIR/build/nr-ue" -c "$HERE/ue.yaml"
