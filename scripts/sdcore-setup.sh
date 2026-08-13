#!/bin/bash
# 5g-lab: SD-Core (kind) 一次性节点环境准备
# 在 `helm install sd-core` 之前跑一次；kind 集群重建后需重跑。
# 固化了手工调通 SD-Core 时对 kind 节点做的所有网络准备。

set -e
LAB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$LAB_ROOT/scripts/common.sh"   # OS 检测 + kind 定位（跨 Windows/Ubuntu）
NODE=sdcore-control-plane
KIND="$KIND_BIN"

echo ">> 1/6 确保 kind 集群存在"
"$KIND" get clusters 2>/dev/null | grep -q '^sdcore$' || "$KIND" create cluster --name sdcore
kubectl config use-context kind-sdcore >/dev/null

echo ">> 2/6 修复 containerd 代理（若宿主开了代理，指向 host-gateway 而非 127.0.0.1）"
HOST_PROXY=$(docker exec $NODE bash -c 'echo ${HTTP_PROXY:-}')
if [[ "$HOST_PROXY" == *127.0.0.1* || "$HOST_PROXY" == *localhost* ]]; then
  GW=$(docker exec $NODE getent hosts host.docker.internal | awk '{print $1}')
  PORT=$(echo "$HOST_PROXY" | grep -oE '[0-9]+$')
  docker exec $NODE bash -c "mkdir -p /etc/systemd/system/containerd.service.d && cat > /etc/systemd/system/containerd.service.d/http-proxy.conf <<EOF
[Service]
Environment=\"HTTP_PROXY=http://$GW:$PORT\"
Environment=\"HTTPS_PROXY=http://$GW:$PORT\"
Environment=\"NO_PROXY=172.20.0.0/16,10.96.0.0/16,10.244.0.0/16,localhost,127.0.0.1,.svc,.svc.cluster.local,$GW\"
EOF
systemctl daemon-reload && systemctl restart containerd"
  echo "   containerd 代理已指向 $GW:$PORT"
else
  echo "   宿主未用 127.0.0.1 代理，跳过"
fi

echo ">> 3/6 安装 multus + 标准 CNI 插件（UPF 的 macvlan 需要）"
kubectl get ds -n kube-system kube-multus-ds >/dev/null 2>&1 || \
  kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/master/deployments/multus-daemonset-thick.yml >/dev/null
docker exec $NODE bash -c '
if [ ! -f /opt/cni/bin/macvlan ]; then
  PX=""; [ -n "${HTTP_PROXY:-}" ] && PX="-x ${HTTP_PROXY}"
  cd /tmp && curl -fsSL $PX -o cni.tgz https://github.com/containernetworking/plugins/releases/download/v1.5.1/cni-plugins-linux-amd64-v1.5.1.tgz
  tar -xzf cni.tgz -C /opt/cni/bin
fi
echo "   macvlan 插件就位"'

echo ">> 4/6 在节点上建 UPF 的 access/core macvlan 网关 + UE 池回程"
docker exec $NODE bash -c '
ip link show access-gw >/dev/null 2>&1 || { ip link add access-gw link eth0 type macvlan mode bridge; ip addr add 192.168.252.1/24 dev access-gw; ip link set access-gw up; }
ip link show core-gw   >/dev/null 2>&1 || { ip link add core-gw   link eth0 type macvlan mode bridge; ip addr add 192.168.250.1/24 dev core-gw;   ip link set core-gw up; }
sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip route replace 192.168.100.0/24 via 192.168.250.3 2>/dev/null || true
iptables -t nat -C POSTROUTING -s 192.168.100.0/24 -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -o eth0 -j MASQUERADE
echo "   网关与 NAT 就绪"'

echo ">> 5/6 放行 gNB<->pod 直连（SCTP 多归属地址不能被 masquerade 改写）"
docker exec $NODE bash -c '
iptables -t nat -C POSTROUTING -s 172.20.0.0/16 -d 10.244.0.0/16 -j ACCEPT 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s 172.20.0.0/16 -d 10.244.0.0/16 -j ACCEPT
iptables -t nat -C POSTROUTING -s 10.244.0.0/16 -d 172.20.0.0/16 -j ACCEPT 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s 10.244.0.0/16 -d 172.20.0.0/16 -j ACCEPT
echo "   no-NAT 规则就绪"'

echo ">> 6/6 完成。接着执行:"
echo "     ./scripts/core.sh up sdcore     # helm 部署（首次等镜像拉取，用 ps 观察）"
echo "     ./scripts/ran.sh  up ueransim sdcore"
