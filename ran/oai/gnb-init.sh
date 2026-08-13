#!/bin/bash
# 5g-lab OAI gNB (RFsim) 启动脚本：渲染配置模板后直接运行 nr-softmodem

set -e
GNB_IP=$(awk 'END{print $1}' /etc/hosts)
echo "OAI gNB: IP=$GNB_IP AMF=$CORE_AMF_ADDR PLMN=$MCC/$MNC TAC=$TAC SST=${SLICE_SST:-1} SD=${SLICE_SD:-<none>}"

cp /mnt/oai/gnb.conf.template /tmp/gnb.yaml
sed -i "s|LAB_TAC|${TAC}|g" /tmp/gnb.yaml
sed -i "s|LAB_MCC|${MCC}|g" /tmp/gnb.yaml
sed -i "s|LAB_MNC|${MNC}|g" /tmp/gnb.yaml
sed -i "s|LAB_SST|${SLICE_SST:-1}|g" /tmp/gnb.yaml
if [[ -n "$SLICE_SD" ]]; then
  sed -i "s|LAB_SD|${SLICE_SD}|g" /tmp/gnb.yaml
else
  sed -i "/LAB_SD/d" /tmp/gnb.yaml
fi
sed -i "s|LAB_AMF_IP|${CORE_AMF_ADDR}|g" /tmp/gnb.yaml
sed -i "s|LAB_GNB_IP|${GNB_IP}|g" /tmp/gnb.yaml

exec /opt/oai-gnb/bin/nr-softmodem -O /tmp/gnb.yaml -E --rfsim --rfsimulator.serveraddr server
