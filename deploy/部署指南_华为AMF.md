# 对接华为 AMF 部署指南（装环境）

> **现场怎么打、随机 AU 怎么读、全部攻击命令：见 [`操作手册_华为AMF.md`](操作手册_华为AMF.md)。**
> 当前现场：AMF `14.66.2.5`，绑定 `13.254.241.142`，PLMN `460/08`。

面向对象：一台**能联网**的 Win11 测试主机（已装 WSL2），直连华为 AMF。目标是从 GitHub
`git clone` 后，在 WSL 里**一键装好、直接跑**：

- **UERANSIM**（合法 gNB + UE）→ 让一个真实 UE 完成认证/注册（造受害者）
- **ngap_tester**（流氓 gNB）→ 针对已注册 UE 发攻击

> **不需要** Docker Desktop，也**不跑** 5g-lab 那套 4 核心网 —— 核心网就是真实华为 AMF。

---

## 0. 为什么必须在 WSL 原生 + 镜像网络里跑（很重要）

NGAP 走 **SCTP**（不是 TCP/UDP）。在 Windows 上：

1. **WinNAT 不支持 SCTP** —— 经 NAT 出去的 SCTP 直接被丢。
2. **Docker Desktop 的 host 网络只代理 TCP/UDP**（vpnkit），SCTP 送不出去；引擎还跑在
   隔离 VM 里，拿不到主机网卡，macvlan 在 Windows 也不可用。

所以**用 Docker（Desktop）任何网络模式都连不上外部真实 AMF 的 SCTP**。可靠做法：

> 开 **WSL 镜像网络(mirrored)**，让 WSL2 直接共享 Windows 主机的真实网卡（与 AMF 同网段、
> 无 NAT），并在 WSL 里**原生**跑 UERANSIM 和 ngap_tester。WSL2 内核自带 SCTP
> (`CONFIG_IP_SCTP=y`)，SCTP 直达 AMF，源 IP 就是主机在 AMF 侧网卡上的真实 IP。

---

## 1. Windows 宿主：开镜像网络（一次性）

把 `deploy/wslconfig-mirrored.txt` 里的 `[wsl2]` 段拷进 `%USERPROFILE%\.wslconfig`
（即 `C:\Users\<你>\.wslconfig`），然后管理员 PowerShell：

```powershell
wsl --shutdown
```

要求：Windows 11 22H2+，且**宿主 IPv6 开启**（关了 IPv6 会让镜像模式只剩 lo 网卡）。

## 2. 准备一个 WSL Ubuntu（若没有）

```powershell
wsl --update            # 确保 WSL2 内核较新(6.6.x 自带 SCTP)
wsl --install -d Ubuntu-22.04
```

进入 Ubuntu（后续命令都在 Ubuntu 里）：`wsl -d Ubuntu-22.04`

## 3. 克隆仓库（私有仓库需 token）

```bash
# NGtester 是私有仓库：用带 PAT 的地址，或先 gh auth login
git clone -b main https://<GITHUB_TOKEN>@github.com/Dongoing/NGtester.git ngap_tester
cd ngap_tester
```
`main` 分支里已经带上了本 `deploy/`（UERANSIM real-amf 配置 + bootstrap + ngt.sh），
所以**一次 clone 就够**。

## 4. 一键装环境

```bash
chmod +x deploy/*.sh deploy/real-amf/*.sh
./deploy/bootstrap.sh
```
bootstrap 会：检查内核 SCTP → 装依赖(build 工具/libsctp/python venv) → 编译 UERANSIM →
建 ngap_tester 的 Python venv。首次约 5-10 分钟。

## 5. 填现场参数

两处要和华为核心网对齐（PLMN/TAC/切片/DNN），并确保 UE 凭据已在华为**开户**：

- `deploy/real-amf/real-amf.env` —— UERANSIM 合法 gNB+UE（PLMN/TAC/切片/DNN/IMSI/K/OPc）
- `config/huawei.json` —— ngap_tester 流氓 gNB（`gnb_id` **必须与 UERANSIM 不同**）

### 交给华为网管的开户清单（默认=5g-lab 测试值）

| 项 | 值 | 说明 |
|---|---|---|
| IMSI/SUPI | `460081111111113` | 已写入 `real-amf.env` |
| K (Ki) | `1234567890abcde1234567890abcde12` | |
| OPc（类型 OPc，非 OP） | `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF` | |
| AMF(鉴权域) | `8000` | |
| PLMN(MCC/MNC) | `460` / `08` | |
| TAC | `1` | |
| S-NSSAI(SST/SD) | `1` / `010101` | |
| DNN | `internet` | |
| AMF N2 | `14.66.2.5:38412` | |
| 本机源 IP | `13.254.241.142` | |

## 6. 起合法 gNB + UE（造受害者）

```bash
./deploy/ngt.sh sctp-ping                # 先确认 L4 到 AMF 通，并看到源 IP（报给华为白名单）

./deploy/real-amf/run-gnb.sh             # 终端 A：NG Setup
./deploy/real-amf/run-ue.sh              # 终端 B：认证 + 注册 + 建会话
ping -I uesimtun0 8.8.8.8                # 可选：验证数据面
```
看到 `Registration is successful` 即华为 AMF 上已有一个真实注册的受害 UE。

## 7. 流氓 gNB（ngap_tester）攻击

华为 AMF-UE-NGAP-ID **每次随机**，不要 sweep。读 ID 和全部攻击命令见
[`操作手册_华为AMF.md`](操作手册_华为AMF.md)。

```bash
./deploy/ngt.sh ng-setup
sudo ./deploy/extract-ue-ids.sh 30
./deploy/ngt.sh path-switch --source-amf-ue-id <本次AU>
```

---

## 8. 迁移后自检清单

- [ ] `.wslconfig` 已 mirrored 且 `wsl --shutdown` 过；`ip -4 addr` 能看到主机真实网卡 IP（不是只有 lo）
- [ ] `grep -w SCTP /proc/net/protocols` 有输出（内核支持 SCTP）
- [ ] `./deploy/bootstrap.sh` 成功；`~/UERANSIM/build/nr-gnb` 存在；`.venv` 建好
- [ ] `./deploy/ngt.sh sctp-ping` 显示 SUCCESS，并打印出源 IP
- [ ] `run-gnb.sh` 看到 NG Setup successful；`run-ue.sh` 看到 Registration successful
- [ ] `config/huawei.json` 的 `gnb_id` 与 `real-amf.env` 的 `NCI` 对应的 gNB-ID 不同

## 9. 故障排查

| 现象 | 原因 / 处理 |
|---|---|
| WSL 里只有 `lo` 网卡 | 没进镜像模式，或宿主关了 IPv6。改 `.wslconfig` + 开 IPv6 + `wsl --shutdown` |
| `sctp-ping` FAILED | 流量被 NAT（没进镜像模式）/ 路由不通 / AMF 防火墙未放行本机源 IP |
| `sctp-ping` OK 但 NG Setup REJECT | 不是网络问题，是 PLMN/TAC/切片/gNB-ID 不匹配或源 IP 未白名单 |
| UE 认证/注册失败 | 凭据没在华为开户，或 K/OPc/PLMN/IMSI 前缀不符；首次 SQN re-sync 属正常 |
| `grep SCTP /proc/net/protocols` 空 | 内核太旧无 SCTP：Windows 跑 `wsl --update` 后 `wsl --shutdown` 重试 |
| `bad interpreter: /bin/bash^M` | 脚本 CRLF。仓库 `.gitattributes` 已强制 LF；仍出现则 `sed -i 's/\r$//' deploy/*.sh deploy/real-amf/*.sh` |
