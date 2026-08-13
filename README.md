# 5g-lab —— 可插拔的 4 核心网 × 3 基站 Docker 实验环境

一套可任意编排的 5G SA 实验平台：**4 套核心网**（Open5GS / OAI CN5G / free5GC / SD-Core）
和 **3 种基站**（UERANSIM / srsRAN / OAI），基站可以用一条命令挂接到任意核心网。

参考项目 [herlesupreeth/docker_open5gs](https://github.com/herlesupreeth/docker_open5gs)
的编排思路重构：核心网与基站解耦成独立 compose，基站侧网络与 AMF 地址全部参数化。

> **首次部署 / 迁移到新机器**：先看 [`INSTALL.md`](INSTALL.md)（前提软件、拉镜像、
> kind/helm、各核心网首启）。本文档面向已装好环境后的日常使用。

---

## 1. 设计要点

| 机制 | 说明 |
|---|---|
| **共享网络 + 固定 AMF** | 三套 docker 核心网（Open5GS/OAI/free5GC）都接共享网络 `net-5glab`（172.30.0.0/16），AMF 恒在 **172.30.0.10**。**一次只跑一套**，所以基站 env 对三套完全一致、AMF IP 永不变。SD-Core 例外（跑在 kind，172.20.0.0/16）。 |
| **基站可插拔** | 基站 compose 里网络声明为 `external`，通过 `--env-file` 注入 `CORE_NETWORK` + `CORE_AMF_ADDR`，即可挂接任意核心网。 |
| **统一 profile** | PLMN、TAC、切片、10 组 UE 凭据四套完全一致（见第 4 节），集中在 `ran/env/<core>.env`。 |
| **动态 IP 隔离** | 外挂基站的动态 IP 限制在 `172.30.200.0/24`，不与核心网网元静态 IP 冲突。 |

### 目录结构
```
5g-lab/
├── INSTALL.md                     # 安装 / 迁移手册（新机器从这里开始）
├── README.md                      # 本文档：日常使用
├── cores/                         # 4 套核心网
│   ├── open5gs/  core.yaml + .env + 各网元配置模板
│   ├── oai-cn5g/ core.yaml + conf/ + database/oai_db.sql（内置 10 订阅）
│   ├── free5gc/  core.yaml + config/ + cert/ + subscriber.json  （UPF 用 eUPF）
│   └── sdcore/   values.yaml                    （kind + Helm，内置 10 订阅）
├── ran/                           # 3 种基站（可插拔）
│   ├── ueransim.yaml    + ueransim/    模拟 gNB+UE
│   ├── srsran-gnb.yaml  + srsran/ srslte/  ZMQ 射频仿真
│   ├── oai-gnb.yaml     + oai/         RFsim 射频仿真
│   └── env/             open5gs.env / oai.env / free5gc.env / sdcore.env
├── scripts/
│   ├── pull-images.sh   一键拉取+打标签所有镜像（迁移第一步）
│   ├── fix-clock.sh     修 WSL2 时钟跳变（每次 WSL 重启后跑）
│   ├── core.sh          核心网启停（含自动灌订阅）
│   ├── ran.sh           基站启停（挂接任意核心网）
│   ├── ue.sh            给运行中的 gNB 多挂几个 UE（多 UE 实验）
│   ├── provision.sh     灌 10 个订阅（core.sh 自动调用）
│   └── sdcore-setup.sh  SD-Core 的 kind 节点一次性准备
├── scripts/common.sh    # 公共库：OS 检测 + 定位 kind/helm（跨 Windows/Ubuntu）
└── tools/               kind / helm（Windows 自带 .exe；Ubuntu 装到 PATH 即可）
```

---

## 2. 快速开始

> 前置：Docker 已运行（Windows：Docker Desktop + WSL2；Ubuntu：Docker Engine）。命令从
> `5g-lab/` 目录执行（Windows 用 Git Bash，Ubuntu 用普通终端）。首次部署/迁移见
> [`INSTALL.md`](INSTALL.md)。

### 启动一套核心网 + 一套基站（以 Open5GS + UERANSIM 为例）
```bash
./scripts/core.sh up open5gs           # 启动核心网并自动预置测试订阅
./scripts/ran.sh  up ueransim open5gs  # gNB+UE 挂上去
```

### 验证端到端
```bash
docker exec ueransim-open5gs-ueransim-ue-1 \
  ping -I uesimtun0 -c 4 8.8.8.8
```

### 停止
```bash
./scripts/ran.sh  down ueransim open5gs
./scripts/core.sh down open5gs
```

---

## 3. 8 种核心网 × 基站组合

任意基站接任意 docker-compose 核心网，只需换第 3 个参数：

```bash
./scripts/ran.sh up ueransim open5gs     # UERANSIM → Open5GS   ✅
./scripts/ran.sh up ueransim oai         # UERANSIM → OAI       ✅
./scripts/ran.sh up ueransim free5gc     # UERANSIM → free5GC   ✅
./scripts/ran.sh up ueransim sdcore      # UERANSIM → SD-Core   ✅
./scripts/ran.sh up srsran   open5gs     # srsRAN   → Open5GS   ✅
./scripts/ran.sh up srsran   oai         # srsRAN   → OAI
./scripts/ran.sh up oai      open5gs     # OAI gNB  → Open5GS   ✅
./scripts/ran.sh up oai      oai         # OAI gNB  → OAI
```

> ✅ = 已实测打通（注册 + PDU 会话 + 数据面 ping）。其余组合参数一致，同理可用。
>
> ⚠️ **一次只跑一套核心网**：三套 docker 核心网的 AMF 都固定在 172.30.0.10，同时起两套会
> IP 冲突（第二套 AMF 起不来）。要换核心网，先把当前这套 `down` 再起另一套。
> 但**同一个核心网上可以同时挂多个不同 gNB**（如 UERANSIM + srsRAN 一起接 Open5GS）。

### 手动方式（不用脚本）
```bash
cd ran
docker compose -f ueransim.yaml --env-file env/free5gc.env up -d
```
换 `env/*.env` 即换核心网，换 `-f *.yaml` 即换基站类型。

## 3.5 一个 gNB 挂多个 UE（做实验用）

先用 `ran.sh` 起好一对 gNB+UE（UE #1，IMSI ...001），再用 `ue.sh` 额外挂 N 个 UE，
每个用不同 IMSI（从池里递增取），全部连同一个 gNB：

```bash
./scripts/ran.sh up ueransim open5gs        # gNB + UE#1 (IMSI ...001)
./scripts/ue.sh  up ueransim open5gs 4      # 再加 UE#2..#5 (IMSI ...002..005)
./scripts/ue.sh  ping ueransim open5gs      # 每个额外 UE 各 ping 一次外网
./scripts/ue.sh  list                       # 列出所有额外 UE
./scripts/ue.sh  down ueransim open5gs      # 停掉所有额外 UE（主对不动）
```
- 参数：`ue.sh up <ueransim|oai> <core> <数量> [起始序号]`，起始序号默认 2。
- 最多 10 个 UE 同时在线（IMSI 池就 10 个）。**UERANSIM 已实测** 5 个 UE 并发注册 + 各自
  独立 IP + 同时 ping 通。
- **OAI(RFsim)** 多 UE `ue.sh` 已支持但未在本环境逐一实测（OAI 一个 gNB 挂多个 UE 有时需
  gNB 侧配合）；**srsUE(ZMQ)** 是点对点射频，一个 gNB 只能接一个 srsUE，`ue.sh` 会拒绝
  `srsran` 并提示，要多个 srsUE 得起多个 gNB。

---

## 4. 统一 profile（四套核心网完全一致）

> **一次只跑一套核心网**，所以四套共用同一套标识和同一个 AMF/gNB IP，你的测试脚本永远
> 指向同一个地址、同一组 UE 凭据，不用每次换。

| 项 | 统一值 |
|---|---|
| PLMN (MCC/MNC) | **001 / 01** |
| TAC | 1 |
| 切片 S-NSSAI | sst=1, sd=010203 |
| DNN / APN | internet |
| UE IMSI | **001010000000001 .. 001010000000010**（10 个，递增） |
| UE MSISDN | 0900000001 .. 0900000010（递增，与 IMSI 对应） |
| UE Key (K) | 8baf473f2f8fd09487cccbd7097c6862（10 个 UE 共用） |
| UE OPc | 8e27b6af0e692e750f32667a3b14605d（10 个 UE 共用） |
| AMF (Milenage) | 8000 |

每套核心网都预置了这 **10 个订阅**（同 K/OPc，IMSI 和 MSISDN 递增），支持最多 10 个 UE
同时接入。订阅来源：Open5GS/free5GC 由 `provision.sh` 自动灌，OAI 在 `database/oai_db.sql`
内置，SD-Core 在 `values.yaml` 的 simapp 内置。

三套 docker 核心网都接**共享网络 `net-5glab`（172.30.0.0/16）**，AMF 恒定 **172.30.0.10**，
srsRAN gNB/UE 恒定 172.30.0.180 / .181。所以 `ran/env/{open5gs,oai,free5gc}.env` 除了
`CORE_NAME` 外内容完全相同。

**SD-Core 例外**：跑在 kind K8s 里，网络是 `kind`(172.20.0.0/16)，AMF 是会变 IP 的 pod
（`ran.sh up ... sdcore` 每次自动刷新）。但 PLMN / UE 凭据 / 切片与上面**完全一致**。

各核心网 UE 地址池仍各自不同（内部实现，不影响测试）：Open5GS 10.51/OAI 10.53/free5GC
10.60/SD-Core 192.168.100。订阅数据均已内置或由脚本自动预置成上面这组统一 UE。

### 管理界面
- Open5GS WebUI：http://localhost:9800 （`admin` / `1423`）
- free5GC WebUI：http://localhost:5000 （`admin` / `free5gc`）

---

## 5. 核心网启停命令

```bash
./scripts/core.sh up   <open5gs|oai|free5gc|sdcore>
./scripts/core.sh down <open5gs|oai|free5gc|sdcore>
./scripts/core.sh ps   <open5gs|oai|free5gc|sdcore>
./scripts/core.sh logs <open5gs|oai|free5gc> [服务名]
```

### SD-Core 专属流程（首次 / kind 集群重建后）
SD-Core 跑在 kind 单节点 K8s 里，比 docker-compose 那三套多两步：
```bash
./scripts/sdcore-setup.sh          # 一次性节点准备（CNI 插件/macvlan 网关/no-NAT/代理）
./scripts/core.sh up sdcore        # helm 部署，用 ps 等约 16 个 pod 全 Running（upf-0 要 5/5）
./scripts/ran.sh  up ueransim sdcore   # 会自动把当前 AMF pod IP 写进 sdcore.env
```
`sdcore-setup.sh` 固化了调通过程中对 kind 节点做的全部网络准备，幂等可重跑。

---

## 6. 设计背后的技术决策（论文可参考）

1. **free5GC 为什么换 eUPF**：free5GC 官方 UPF 依赖 `gtp5g` 内核模块，WSL2 默认内核不带。
   eUPF（eBPF/XDP 实现）不需要内核模块，`core.yaml` 里用 `ghcr.io/edgecomllc/eupf` 替代，
   并由 `eupf-routes` 辅助容器在 VM 根命名空间加 UE 池回程路由 + NAT。

2. **SD-Core 为什么用 kind**：SD-Core 官方只提供 Helm/K8s 部署路径，没有 docker-compose。
   用 kind 在 Docker 里起单节点 K8s 是官方推荐的最省心路径。AMF 的 N2(SCTP) 通过
   kind 节点 IP `172.20.0.2:38412` 暴露，基站从 docker 的 `kind` 网络接入。

3. **OAI UE 只认 OPc**：OAI nr-ue 不支持 OP，需传 OPc。Open5GS 订阅用 OP 时，
   `env/open5gs.env` 里额外提供了换算好的 `UE1_OPC`。

4. **时钟跳变（最重要的环境坑）**：WSL2 VM 时钟走得比宿主慢约 3%，Hyper-V 时间同步每
   ~30s 把它步进对齐宿主，产生 ~2s 跳变。5G 基站 L1 定时器对跳变敏感 → "Radio link
   failure"、UE 反复掉线、PDU 会话建不起来。**真正有效的修复**是解绑 guest 的 Hyper-V
   timesync（让时钟平滑慢走，不再步进）：
   ```bash
   ./scripts/fix-clock.sh    # 每次 WSL/Docker 重启后跑一次
   ```
   （单纯 `w32tm /resync` 或重启 WSL 只能暂时缓解，跳变会复发；解绑 timesync 才是根治。）

5. **SD-Core 的 SCTP over kind（两个坑）**：
   - **双栈取错 IP**：kind 网络是 IPv4+IPv6 双栈，早期 gNB 把自己的 NGAP 地址取成了
     IPv6，SCTP 走 IPv4，地址族不匹配 → 收到 INIT-ACK 后立即 ABORT。修复：gNB/UE 启动
     脚本显式取 eth0 的 IPv4（`ip -4 addr`）。这是 SD-Core 接入调了最久的根因。
   - **SCTP 多归属被 NAT 改写**：gNB 直连 AMF pod 时，kindnet 默认 masquerade 会改写
     源地址，破坏 SCTP INIT 里的多归属地址参数。`sdcore-setup.sh` 加了
     `172.20.0.0/16 <-> 10.244.0.0/16` 双向 no-NAT 规则放行。

6. **AMF pod IP 会变**：SD-Core 的 AMF 是 K8s pod，重启后 IP 变。`ran.sh up ... sdcore`
   每次启动前会自动把当前 AMF pod IP 刷进 `sdcore.env`，无需手动改。

---

## 7. 常见问题

- **基站反复 "Radio link failure" / UE 不停掉线重连**：WSL2 时钟跳变，跑
  `./scripts/fix-clock.sh`（每次 WSL/Docker 重启后都要跑一次）。
- **基站起不来 / 无法解析 gNB**：确认对应核心网已 `up` 且 AMF 健康
  （`./scripts/core.sh ps <core>`）。
- **`ue.sh` 起的额外 UE 秒退**：已在脚本里用 `-dit` + `MSYS_NO_PATHCONV=1` 解决；若自己
  手写 `docker run` 起 UERANSIM UE，务必带 `-dit`（否则 init 结尾的 `exec bash` 读 EOF 退出）。
- **Windows 端口被占**：宿主保留端口段（如 9829–9928）会导致 compose 报
  `ports are not available`，本项目已避开，自定义映射时用 `netsh interface ipv4
  show excludedportrange protocol=tcp` 查保留段。
- **UE 注册成功但 ping 不通**：检查对应 UPF 容器的 tun 接口和 NAT
  （Open5GS 看 `o5gs-upf`，free5GC 看 `f5gc-eupf` + `f5gc-eupf-routes`）。
- **配置脚本报 `bad interpreter: /bin/bash^M`**：文件被存成了 CRLF（Windows 拷到 Linux
  常见），在 `5g-lab/` 下执行转回 LF：
  ```bash
  find . \( -name '*.sh' -o -name '*.yaml' -o -name '*.env' \) -exec sed -i 's/\r$//' {} +
  ```
