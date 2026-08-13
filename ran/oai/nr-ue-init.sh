#!/bin/bash
# 5g-lab OAI NR-UE (RFsim) 启动脚本：解析 gNB 地址，全部参数走命令行

set -e
GNB_HOST=${GNB_HOST:-oai-gnb}
for i in $(seq 1 30); do
  GNB_IP=$(getent hosts $GNB_HOST | awk '{print $1}' | head -1)
  [[ -n "$GNB_IP" ]] && break
  echo "waiting for gNB DNS ($GNB_HOST)..."; sleep 2
done
if [[ -z "$GNB_IP" ]]; then echo "ERROR: cannot resolve gNB host $GNB_HOST"; exit 1; fi

echo "OAI UE: IMSI=$UE1_IMSI gNB=$GNB_IP APN=${APN:-internet} SST=${SLICE_SST:-1} SD=${SLICE_SD:-<none>}"

SD_OPT=""
if [[ -n "$SLICE_SD" ]]; then
  SD_OPT="--uicc0.nssai_sd $((SLICE_SD))"
fi

exec /opt/oai-nr-ue/bin/nr-uesoftmodem \
  -O /mnt/oai/nr-ue.conf \
  -E --rfsim -r 106 --numerology 1 -C 3619200000 \
  --rfsimulator.serveraddr $GNB_IP \
  --uicc0.imsi $UE1_IMSI \
  --uicc0.key $UE1_KI \
  --uicc0.opc ${UE1_OPC:-$UE1_OP} \
  --uicc0.dnn ${APN:-internet} \
  --uicc0.nssai_sst ${SLICE_SST:-1} $SD_OPT
