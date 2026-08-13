#!/bin/bash
# ------------------------------------------------------------------------------
# 渲染并启动“合法 gNB”，连真实华为 AMF。必须在镜像网络的 WSL2 里跑。
# 先跑过 ../bootstrap.sh（装依赖 + 编译 UERANSIM）。
# 用法:  ./run-gnb.sh      (前台运行，日志直接打屏；Ctrl-C 停止)
# ------------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/real-amf.env"

UERANSIM_DIR="${UERANSIM_DIR:-$HOME/UERANSIM}"
AMF_ADDR="${AMF_ADDR:?请在 real-amf.env 里设置 AMF_ADDR}"
AMF_PORT="${AMF_PORT:-38412}"

if [[ ! -x "$UERANSIM_DIR/build/nr-gnb" ]]; then
  echo "[gnb] 找不到 $UERANSIM_DIR/build/nr-gnb，请先跑 ../bootstrap.sh 编译 UERANSIM" >&2
  exit 1
fi

# 自动探测朝 AMF 的源 IP(=华为 AMF 看到的 gNB 源 IP)。`|| true` 防止 grep 无匹配时
# 在 `set -e`/`pipefail` 下提前退出，交给下面的显式检查报错。
if [[ -z "${HOST_IP:-}" ]]; then
  HOST_IP="$(ip -4 route get "$AMF_ADDR" 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1 || true)"
fi
if [[ -z "$HOST_IP" ]]; then
  echo "[gnb] 无法自动探测到达 $AMF_ADDR 的源 IP，请在 real-amf.env 里手动填 HOST_IP" >&2
  exit 1
fi

echo "[gnb] linkIp/ngapIp/gtpIp=$HOST_IP  AMF=$AMF_ADDR:$AMF_PORT  PLMN=$MCC/$MNC  TAC=$TAC  NCI=$NCI"
echo "[gnb] 提醒: 把源 IP $HOST_IP 报给华为做 gNB 白名单"

SLICE_BLOCK="  - sst: ${SLICE_SST:-1}"
if [[ -n "${SLICE_SD:-}" ]]; then
  SLICE_BLOCK="$SLICE_BLOCK
    sd: $SLICE_SD"
fi

cat > "$HERE/gnb.yaml" <<EOF
mcc: '$MCC'
mnc: '$MNC'

nci: '${NCI:-0x000000010}'
idLength: ${GNB_ID_LEN:-32}
tac: $TAC

linkIp: $HOST_IP
ngapIp: $HOST_IP
gtpIp: $HOST_IP

amfConfigs:
  - address: $AMF_ADDR
    port: $AMF_PORT

slices:
$SLICE_BLOCK

ignoreStreamIds: true
EOF

echo "[gnb] 已生成 $HERE/gnb.yaml，启动 nr-gnb ..."
exec "$UERANSIM_DIR/build/nr-gnb" -c "$HERE/gnb.yaml"
