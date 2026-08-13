#!/bin/bash
# 5g-lab: 修复 WSL2 时钟跳变（每次 WSL/Docker 重启后跑一次）
#
# 现象：WSL2 VM 时钟走得比宿主慢 ~3%，Hyper-V 时间同步每 ~30s 把它步进对齐宿主，
#       产生 ~2s 的跳变。5G 基站的 L1 定时器对时钟跳变敏感 → "Radio link failure"，
#       UE 反复掉线、PDU 会话建不起来。
# 修复：解绑 guest 的 Hyper-V timesync VMBus 设备，让 VM 时钟平滑慢走（不再步进）。
#       5G 靠相对定时，匀速慢走无碍，跳变才致命。
#
# 说明：这是运行时设置，WSL 重启后失效，需重跑本脚本。

set -e
LAB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$LAB_ROOT/scripts/common.sh"

# 原生 Linux 的 Docker 共享宿主内核，没有 WSL2/Hyper-V 那个虚拟机时钟问题，无需修。
if [[ "$LAB_NEED_CLOCKFIX" != true ]]; then
  echo ">> 检测到原生 Linux（非 WSL2/Docker Desktop），无 VM 时钟跳变问题，跳过。"
  exit 0
fi

TS_CLASS=9527e630   # Hyper-V TimeSync VMBus class_id 前缀

echo ">> 定位并解绑 Hyper-V timesync 设备..."
docker run --rm --privileged --pid=host alpine nsenter -t 1 -m -u -i -n sh -c "
TS=\$(grep -il '$TS_CLASS' /sys/bus/vmbus/devices/*/class_id 2>/dev/null | head -1)
if [ -z \"\$TS\" ]; then echo '   未找到 timesync 设备（可能已解绑）'; exit 0; fi
DEV=\$(dirname \"\$TS\"); ID=\$(cat \"\$DEV/device_id\" | tr -d '{}')
if [ -e /sys/bus/vmbus/drivers/hv_utils/\$ID ]; then
  echo \"\$ID\" > /sys/bus/vmbus/drivers/hv_utils/unbind && echo \"   已解绑 timesync (\$ID)\"
else
  echo '   timesync 已处于解绑状态'
fi"

echo ">> 验证 30s 内无跳变..."
NODE=$(docker ps --format '{{.Names}}' | grep -E "sdcore-control-plane|o5gs-nrf|oai-nrf|f5gc-nrf" | head -1)
if [ -z "$NODE" ]; then NODE=$(docker ps --format '{{.Names}}' | head -1); fi
if [ -n "$NODE" ]; then
  docker exec "$NODE" sh -c 'prev=$(date +%s%N); j=0; for i in $(seq 1 30); do sleep 1; now=$(date +%s%N); d=$(( (now-prev)/1000000 )); [ $d -gt 1400 ] && { echo "   仍有跳变 ${d}ms @${i}s"; j=1; }; prev=$now; done; [ $j -eq 0 ] && echo "   时钟稳定，30s 无跳变 ✅"'
else
  echo "   （无运行容器可测，跳过验证）"
fi
