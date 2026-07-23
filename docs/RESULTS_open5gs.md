# Open5GS 2.8.0 + UERANSIM — 动态验证实测结果（2026-07-10）

在 `net-5glab` 上对运行中的 Open5GS 2.8.0（`o5gs-amf`）+ UERANSIM 实测 T01–T06。攻击者为
`ngap-tester` 伪造 gNB（`--rm` 容器，动态 IP 172.30.200.x）。证据：`evidence/live-open5gs/*.jsonl`。

## 结果总表

| 测试 | 结果 | 关键证据 |
|---|---|---|
| **T01** Path Switch → {NH,NCC} 泄露 | ✅ **CONFIRMED** | 3 个活跃 UE(AMF-UE-ID 7/8/9) 各返回 32B NH + NCC=2；`imsi-…0001` 亦命中 |
| **T02** Path Switch → 下行傍受 | ⚠️ **部分**：控制面劫持 ✅，用户面下行重定向 ❌ | 见下 |
| **T03** Error Indication → 跨 UE 释放 | ✅ **CONFIRMED** | `Performing local release for AMF_UE_NGAP_ID[17]` (ngap-handler.c:5165)；UE 下行 100% 丢包 |
| **T04** NG Reset(部分) → 跨 gNB 拆除 | ✅ **CONFIRMED + 升级为 AMF 崩溃** | 见下（**新发现：单包 crash AMF**）|
| **T05** Handover Required → 强制迁移 | ✅ **无绑定确认**（密钥泄露条件性）| `HandoverRequired`→`cannot find target gNB-id[0xabcde]` (ngap-handler.c:3460) |
| **T06** UE Context Release | ✅ **阴性对照通过**（攻击被拒）| UE 存活(ping 0% 丢包)；:1784 内联绑定生效 |
| **T07** RAN Config Update → 寻呼傍受 | ✅ **CONFIRMED**（第二攻击面）| 攻击者截获 3 条 PAGING，含受害 **5G-S-TMSI=c000019c** |
| **T08** UL RAN Config Transfer → SON 注入 | ✅ **CONFIRMED**（盲中继）| AMF 把 SON 配置中继给受害 UERANSIM gNB（其收到并记 "Unhandled NGAP (24)"）|
| **p06** PDU Session Resource Notify | ⚪ **NOT-APPLICABLE**（未实现）| 2026-07-22 live：`Not implemented(choice:1, proc:30)` (`ngap-sm.c:128`)；pcap `open5gs_p06_pdu_notify/` |
| **p09** Handover Notify | 🟡 idle 挡住 / 🔴 **HO 窗口 CONFIRMED** | idle→ErrorIndication；**窗口内**：Release→受害 gNB，UE→CM-IDLE；pcap `open5gs_ho_window_p21_p09/` |
| **p16** UL UE-Assoc NRPPa | ⚪ **NOT-APPLICABLE**（未实现）| 2026-07-22 live：`Not implemented(choice:1, proc:50)`；pcap `open5gs_p16_ul_nrppa/` |
| **p17** Cell Traffic Trace | ⚪ **NOT-APPLICABLE**（未实现）| 2026-07-22 live：`Not implemented(choice:1, proc:2)`；pcap `open5gs_p17_cell_trace/` |
| **p21** UL RAN Status Transfer | 🟡 idle 挡住 / 🔴 **HO 窗口 CONFIRMED** | idle→ErrorIndication；**窗口内**：DL RAN Status(7) 回到攻击者；pcap 同上 |

## 新 5 builders — Open5GS live（2026-07-22）

前提：`o5gs-amf` + UERANSIM，受害 `AMF_UE_NGAP_ID=1`（CM-CONNECTED，ping 正常）。
伪造 gNB 经 `ngap-tester` 完成 NG Setup 后逐条发送。每条均有
`pcap/open5gs_pXX_*/{amf_ngap_nas_sbi,smf_sbi_pfcp,legit_gnb_n2_n3}.pcap`。

| 消息 | proc | AMF 实测反应 | 跨 gNB 危害 | 与源码核验 |
|---|:--:|---|---|---|
| PDU Session Resource Notify | 30 | `Not implemented`（无 handler） | 无 | 吻合 ⚪ |
| Handover Notify | 11 | idle：无 HO 目标 → ErrorIndication | **HO 窗口内可利用**（见下） | 吻合 🟡→🔴 |
| UL UE-Assoc NRPPa | 50 | `Not implemented` | 无 | 吻合 ⚪ |
| Cell Traffic Trace | 2 | `Not implemented` | 无（TCE 路径未进） | 吻合 ⚪ |
| UL RAN Status Transfer | 49 | idle：无 `target_ue` → ErrorIndication | **HO 窗口内可利用**（见下） | 吻合 🟡→🔴 |

**idle 结论**：常态无切换时五条不可利用（3×未实现 + 2×门控）。**门控不是缓解**——攻击者可用
同一伪造 gNB 先发 `HandoverRequired`（p03，无绑定）打开窗口，再注入 p21/p09。

## 切换窗口注入 — p03→p21/p09（2026-07-22）🔴 ✅

命令：`ho-window-inject --amf-ue-id 1 --ran-ue-id 99 --mode both`
（TargetID = FakeGNB 自身 `gnb_id=0x1234`；pcap `open5gs_ho_window_p21_p09/`）。

| 步骤 | 方向 | proc | 结果 |
|---|---|:--:|---|
| NG Setup | 攻击者↔AMF | 21 | 接受 |
| HandoverRequired（伪造源，受害 AU=1）| 攻击者→AMF | 12 | 无绑定命中受害；创建 target_ue AU=2 |
| HandoverRequest | AMF→攻击者 | 13 | 攻击者学到 target-amf=2 |
| HandoverRequestAcknowledge | 攻击者→AMF | 13 | 准备完成 |
| HandoverCommand | AMF→**受害 gNB** | 12 | UERANSIM `Unhandled successful-outcome` |
| **p21** UplinkRANStatusTransfer (AU=1) | 攻击者→AMF | 49 | — |
| **DownlinkRANStatusTransfer** | AMF→**攻击者** | 7 | **p21 中继确认** |
| **p09** HandoverNotify (AU=2) | 攻击者→AMF | 11 | 完成切换 |
| UEContextReleaseCommand | AMF→**受害 gNB** | 41 | **p09 跨 gNB 释放确认** |
| UEContextReleaseComplete | 受害 gNB→AMF | 41 | 受害侧完成 |
| 受害 UE | — | — | `RRC Release` → **CM-IDLE** |

AMF 日志：`HandoverRequired` → `UE Context Release [Action:4]`。
受害 gNB：`UE Context Release Command received` → `Releasing RRC connection for UE[1]`。

**论文要点**：Open5GS 对 p09/p21 的“需进行中 HO”门控**可被攻击者用无绑定的 p03 自行打开**；
窗口内 p21=PDCP 状态中继到攻击者，p09=把受害从源 gNB 释放并切到攻击者 serving 上下文。

## T01 — Path Switch 密钥泄露 ✅

`sweep --attack path-switch --amf-range 1-16` 发现 3 个活跃受害者，各泄露 {NH,NCC}：
```
[HIT] AMF-UE-NGAP-ID=7: NCC=2 NH=8db8e6c864189a8ad7a4848455e7ff57187242f499c7de69bf1aee372da0fe0d
[HIT] AMF-UE-NGAP-ID=8: NCC=2 NH=599afee7b0be6081da5ead38b3adbf5ee1c0b2ede144a9fda5f1396d4df13d02
[HIT] AMF-UE-NGAP-ID=9: NCC=2 NH=c54a642d5ccc9922b928a26ca3d1fe2d198d6a7bd6c57f12244a7158fb6ba024
```
AMF 日志：`[OLD] RAN_UE_NGAP_ID[9] → [NEW] RAN_UE_NGAP_ID[99] AMF_UE_NGAP_ID[9]`（受害重绑到攻击者）。
**结论：单条伪造 Path Switch 使 AMF 把受害 UE 的下一跳密钥材料 {NH,NCC} 交给伪造 gNB。密钥泄露成立。**

## T02 — 下行傍受/中断（重要的诚实修正）

**控制面劫持 ✅ CONFIRMED**：Path Switch ACK 返回 {NH,NCC}（NH=c0a49058…），并把受害 UE
（AMF-UE-ID 14）重绑到攻击者 RAN[99]。此后**合法 gNB 的上行 NAS 失败**：
```
ERROR: No RAN UE Context : AMF_UE_NGAP_ID[14] (ngap-handler.c:168)
ERROR: ngap_handle_uplink_nas_transport: Failed to find RAN UE by NGAP UE IDs (ngap-handler.c:889)
```
→ 受害 UE 被从合法 gNB 劫持到伪造 gNB 的 AMF 上下文（**跨 gNB 控制面劫持/DoS**）。

**用户面下行重定向 ❌ 未复现（本栈）**：在 UPF 上 `tcpdump udp 2152` 抓包证明：
- 攻击者 TEID `0x11111111` **从未出现在 UPF 下行出口**（`grep -c '1111 1111'` = 0）；
- 攻击者 sink（172.30.200.5，已用合成 G-PDU 验证可达可解码）**未收到任何下行**；
- 受害 UE 的 8.8.8.8 ping **持续正常**（下行仍走合法 gNB 172.30.10.11）。

**根因（源码）**：Open5GS SMF `nsmf-handler.c:969-1006` 仅当 `sess->handover.prepared == true`
时才把 UPF 下行 FAR 改到新 N3 端点（`OGS_PFCP_MODIFY_N2_HANDOVER`）。该标志由**完整切换准备**
（Handover Required→Request→Ack）置位；**裸 Path Switch 不置位**，故 SMF 不重编程 UPF 下行。
这也解释了 T01 观察到的**空 ACK transfer**（SMF 未产出新 UL TNL）。

**对论文的修正**：Open5GS 2.8.0 上，伪造 Path Switch 的即时影响是 **{NH,NCC} 密钥泄露 +
控制面 UE 劫持/DoS**；**免无线的下行用户面重定向/傍受在本栈未成立**（受 SMF `handover.prepared`
门控）。tester 与 `gtpu-sink` 已就绪，若先用 Handover 置位或在其它栈（free5gc/SD-Core）复测可再验证。

## T03 — Error Indication 跨 UE 释放 ✅

```
WARNING: Performing local release for RAN_UE_NGAP_ID[17] AMF_UE_NGAP_ID[17] (ngap-handler.c:5165)
```
受害 UE(17) 攻击后 8.8.8.8 ping **100% 丢包**。**只带受害 AMF-UE-NGAP-ID 的伪造 Error
Indication 即释放了另一 gNB 上的受害 UE**（绕过 :179 的全局查找路径）。

## T04 — NG Reset 部分：跨 gNB 拆除 **+ AMF 崩溃（新发现）** ✅🔥

`ng-reset --targets 18:99` → `NGResetAcknowledge` 返回；受害 UE(18) ping **100% 丢包**。
**但随即 AMF 进程崩溃**：
```
FATAL: amf_nsmf_pdusession_handle_update_sm_context:
       Assertion `gnb->ng_reset_ack' failed. (../src/amf/nsmf-handler.c:928)
... open5gs-amfd ... 8 Aborted
```
容器状态 `o5gs-amf  Exited (134)`（134 = 128+SIGABRT）。**一条未认证的伪造 NG Reset(部分)
携带一个正在进行 PDU 会话更新的受害 AMF-UE-NGAP-ID，即可断言失败并 SIGABRT 掉整个 AMF**
→ 不止拆除单个受害 UE，而是**打掉 AMF、影响该 AMF 上所有 UE 的远程 DoS**（比源码预期的“跨 gNB
拆除”更严重的升级）。恢复需 `docker restart o5gs-amf` + gNB/UE 重连。
> 竞态：需受害 UE 恰有在途的 SMF UpdateSMContext；实测稳定触发。值得在论文单列为可靠远程 AMF DoS。

## T05 — Handover Required 强制迁移 ✅（无绑定；密钥泄露条件性）

```
INFO:  HandoverRequired (ngap-handler.c:3298)
ERROR: Handover required : cannot find target gNB-id[0xabcde] (ngap-handler.c:3460)
```
AMF **无源 gNB 绑定地**定位了受害 UE(2) 并执行到 target-gNB 解析——因 0xABCDE 未注册而止步，
受害 UE 存活。**证明无绑定**；若攻击者再注册一个 gNB-id=0xABCDE 的伪造 gNB 作为 target，
迁移将继续并把 {NH,NCC} 交付该攻击者 target（条件性密钥泄露，同源码 `:3624-3625` 接受任意 gNB-id）。

## T06 — UE Context Release（阴性对照）✅

`ue-release --amf-ue-id 15 --ran-ue-id 99` 后受害 UE **存活**（ping 0% 丢包）。Open5GS 在
`:1784` 内联 `ran_ue->gnb_id != gnb->id` 绑定检查，跨 gNB 释放被拒。**证明我们的方法也能如实
显示“加固路径挡住攻击”**，结论是过程/版本相关，而非“无差别可打”。

## T07 — RAN Configuration Update → 寻呼(Paging)傍受 ✅（第二独立攻击面）

攻击链（全部实测）：
1. 伪造 gNB 发 `RAN CONFIGURATION UPDATE`（SupportedTAList 声称 TAC=1）→ AMF 回
   `RANConfigurationUpdateAcknowledge`（**无覆盖校验，攻击者成功声称受害 TAI**）。
2. 攻击者发 Error Indication 把受害 UE 置为 CM-IDLE（保留注册）。
3. 对受害 UE 注入下行（UPF ping UE IP）→ AMF 对空闲 UE 发起寻呼。
4. AMF 按 TAI fan-out（`ngap-path.c:522-527`）把 PAGING 也发给攻击者伪造 gNB。

证据 `evidence/live-open5gs/T07_paging.jsonl`（截获 3 条）：
```json
{"attack":"paging-intercept","paging":{"message":"Paging",
 "fiveg_s_tmsi":"0001:00:c000019c","tais":["000001"],"fiveg_tmsi":"c000019c"}}
```
**结论：攻击者伪造 gNB 声称一个它并不服务的 TAI，即截获受害 UE 的寻呼与其 5G-S-TMSI
（c000019c）——可持续跟踪/定位受害者、或拒绝其寻呼。** 与 UE 上下文绑定无关的独立面。

## T08 — Uplink RAN Configuration Transfer → SON/Xn 盲中继注入 ✅

`ul-ran-config-transfer --target-gnb-id 0x1`（UERANSIM gNB，攻击者不控制）：AMF 接受伪造
gNB 的 `SONConfigurationTransfer` 并**盲中继**给目标 gNB。目标 UERANSIM gNB 在同一时刻收到：
```
[ngap] error: Unhandled NGAP initiating-message received (24)   # DownlinkRANConfigurationTransfer
```
**结论：未认证攻击者经 AMF 向一个它并不控制的受害 gNB 注入了 SON/Xn 配置中继**（AMF 无
source/target 邻居关系校验）。UERANSIM 未实现 SON 处理故记为 Unhandled，但**中继本身已完成**。

## 影响分级小结（Open5GS 2.8.0）

| 能力 | 结果 |
|---|---|
| 机密泄露（{NH,NCC}）| ✅ Path Switch（T01）|
| 远程 AMF 崩溃 DoS（全 UE）| ✅🔥 NG Reset 部分（T04，新发现）|
| 跨 gNB 单 UE 释放/劫持 | ✅ Error Indication（T03）、Path Switch 控制面（T02）|
| 强制迁移（条件性密钥泄露）| ✅ Handover Required（T05）|
| **寻呼傍受 + 5G-S-TMSI 泄露** | ✅ RAN Config Update 声称假 TAI（T07）|
| **跨 gNB SON/Xn 配置注入** | ✅ UL RAN Config Transfer 盲中继（T08）|
| 下行用户面即时傍受 | ❌ 本栈未成立（SMF `handover.prepared` 门控）|
| 加固过程正确挡住 | ✅ UE Context Release（T06 阴性对照）|
| 新 5 builders（idle）| ⚪/🟡 常态不可利用（3 未实现 + 2 HO 门控）|
| **HO 窗口 p21/p09** | 🔴 ✅ p03 自开窗后：PDCP 中继 + 受害源 gNB 释放 |

## 两个独立攻击面（论文结构）

- **面 A：UE 上下文绑定缺失**（AMF-UE-NGAP-ID 未绑定发起者）→ T01 密钥泄露、T03 释放、
  T04 拆除+崩溃、T05 迁移、T02 控制面劫持。
- **面 B：拓扑/中继信任缺失**（独立于 A）→ T07 假 TAI 寻呼傍受、T08 SON 盲中继注入。
