# OAI CN5G + UERANSIM — 动态验证实测结果（2026-07-10）

在 `net-5glab` 上对运行中的 OAI CN5G（`oai-amf` @ 172.30.0.10）+ UERANSIM 实测。攻击者为
`ngap-tester` 伪造 gNB。证据：`evidence/live-oai/*.jsonl`。UE `001010000000001`
（RAN-UE-NGAP-ID=0x1, AMF-UE-NGAP-ID=0x1）5GMM-REGISTERED。SCTP PPID 修正对 OAI 亦有效。

## 核心发现：静态标记 🔴 ≠ 动态可利用

OAI 是 C++、**只实现子集（大量 stub）**。源码静态分析（`SOURCE_VERIFICATION.md`）按「缺少
绑定检查」把若干 handler 标 🔴，但**动态实测显示这些跨 gNB 效果多数不成立**——OAI 要么不实现
该过程，要么把响应/命令**路由回请求方（攻击者）**而非受害 gNB。在四栈中，OAI 对「裸伪造 gNB
可达的跨 gNB 攻击面」**实际最不可利用**。

## 结果总表

| 测试 | OAI 结果 | 说明 |
|---|---|---|
| **T01** Path Switch | ⚪ **未实现** | 无 ACK（"no reply"）；OAI 不实现 Path Switch |
| **T06** UE Context Release | ◑ **无绑定查找存在，但受害未断连** | 见下（源码级订正）|
| **T04** NG Reset | 🟢 **ack 且不崩溃、受害存活** | 与 Open5GS「拆除+崩溃」形成强对照 |
| **T07** RAN Config Update | ◑ 被解析、无 ACK | OAI 收到并 dispatch，未见服务 TAI 生效证据 |
| **T08** UL RAN Config Transfer（SON）| ⚪ **解析但不中继** | 目标 gNB 未收到 Downlink 中继（无 "Unhandled (24)"）|
| **p06** PDU Session Resource Notify | ⚪ **stub / 无效果** | 2026-07-22：解码 proc=30，无后续动作；pcap `oai_p06_pdu_notify/` |
| **p09** Handover Notify | 🔴 ✅ **跨 gNB 释放 + SR 被拒** | Release→受害 gNB→CM-IDLE；~11s Service Request 被 AMF Reject；pcap/日志已替换 `oai_p09_handover_notify/` |
| **p16** UL UE-Assoc NRPPa | ◑ **解码失败，未进 handler** | 错误 RAN 与真实 (RAN,AMF) 对均 `Decode …NRPPa… error`；pcap `oai_p16_ul_nrppa_*` |
| **p17** Cell Traffic Trace | ⚪ **stub / 无效果** | 解码 proc=2，无后续；pcap `oai_p17_cell_trace/` |
| **p21** UL RAN Status Transfer | 🟡 **进入 handler，无有效投递** | 尝试发 DownlinkRANStatusTransfer，但 `assoc Id (0) has not been found`（无 HO target）；pcap `oai_p21_ul_ran_status/` |

## 新 5 builders — OAI live（2026-07-22）

前提：受害 `AMF-UE-NGAP-ID=0x03`、`RAN-UE-NGAP-ID=0x01`，5GMM-REGISTERED，ping 正常。

### p09 Handover Notify — 跨 gNB 释放 ✅🔴（本轮最强 OAI 发现）

**复测（2026-07-22，替换原 pcap/日志）**：`handover-notify --amf-ue-id 1 --ran-ue-id 99`  
证据目录：`pcap/oai_p09_handover_notify/`（含 pcap + `ue_full.log` / `amf_p09_and_recovery.txt` /
`SUMMARY.txt`）。

**1) 一刀释放（确认）**
- AMF：`Received Handover Notify` → `ran_ue_ngap_id (99) amf_ue_ngap_id (1)` →
  **`Send UE Release Command to source gNB`**
- 受害 gNB：`UE Context Release Command received` → `Releasing RRC connection for UE[1]`
- UE：`RRC Release received` → **CM-IDLE**（14:34:23）
- pcap：攻击者 NG Setup(21)+Notify(11)；AMF→受害 gNB Release(41)+Complete(41)

**2) 随后 Service Request —— 这就是“AMF 状态乱”的实测含义（确认）**
- ~11s 后 UE：`Service request required due to [IDLE-UPLINK-DATA-PENDING]` → 短暂 **CM-CONNECTED**
- AMF：为 SR 建了**新** `nas_context`（`amf_ue_ngap_id 2`），状态机却在 **`5GMM-DEREGISTERED`**：
  `5GMM state transition: not valid, state=5GMM-DEREGISTERED, event=SERVICE_REQUEST_RECEIVED`
  → **`Send Service Reject with cause 101`**
- UE：`Service Reject` / `MESSAGE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE` → **未能像 Open5GS 那样干净恢复**

**与 Open5GS HO-窗 p09 对照**：两边都会拆源侧到 CM-IDLE；Open5GS 约 38s 后可再 CM-CONNECTED，
OAI 约 11s 后发 Service Request 却被 AMF **因状态机不一致而 Reject**——“乱”有日志句柄，不是推测。

**与 T06 的关键对照**：同一套全局 `amf_ue_id_2_ue_ngap_context`，UE Release Request 把命令发回
**攻击者**（受害不断）；Handover Notify 把 Release 发往**受害真实 gNB** → 跨 gNB 释放成立，
且无需进行中切换。

### 其余四条（简）

| 消息 | 实测 |
|---|---|
| p06 / p17 | stub：报文到达并解码，无状态改写 / 无跨 gNB 危害 |
| p16 | 本 tester 编码的 NRPPa 被 OAI ASN.1 解码拒绝 → **未能验证**源码标红的 LMF 注入路径 |
| p21 | handler 跑通并尝试中继 DL RAN Status，但无 `target_gnb_assoc_id` → SCTP assoc 0 发送失败；**无进行中 HO 时不可利用** |

## T06 — UE Context Release Request（源码级订正）◑

OAI handler `amf_n2::handle_itti_message(itti_ue_context_release_request)`
（`component/oai-amf/src/amf-app/amf_n2.cpp:1347`）：
```cpp
if (amf_ue_id_2_ue_ngap_context(amf_ue_ngap_id, unc)) { ... }   // :1356 全局、无 gnb 绑定（漏洞存在）
...
sctp_s_38412.sctp_send_msg(itti_msg->assoc_id, itti_msg->stream, &b);  // :1385 发回【请求方=攻击者】
```
**关键**：OAI 确实用全局 `amf_ue_id_2_ue_ngap_context()` 无绑定地解析到受害 UE 上下文（缺失
绑定成立），**但随后把 `UEContextReleaseCommand` 发回请求方的 association（攻击者），而非受害
UE 的真实 gNB**。实测：OAI 回我们一条 `UEContextReleaseCommand`，受害 UE **ping 持续 0% 丢包
（未断连）**；日志的 "Remove gNB gnb_id 0x1234" 只是攻击者容器断开后的清理。
→ **订正 `SOURCE_VERIFICATION.md` 对 OAI p02 的 🔴**：绑定缺失属实，但因命令路由回请求方，
**跨 gNB 断连效果不成立**（类比 Open5GS T02 的诚实订正）。

## chain-initue-release — InitialUE(TMSI) → Release（2026-07-31）◑

命令：`chain-initue-release`；脚本：`verify_chain_initue_then_release.sh oai`；  
证据：`pcap/chain_oai_initue_then_release/`。

实测（受害 AU=6，TMSI=`4e4f2ed4`；当时仍可用较短 NAS，OAI 亦回 DL）：
1. **H0** 单独 Release(AU=6) → Command（proc 41）回攻击者，受害 DN ping **0%**。
2. **InitialUE** → DL `DownlinkNASTransport` **AU=7 RU=99**（新 AU 暴露；常为 Service Reject）。
3. Release(6) → Complete：`No UE NGAP context … 6`（ID 已迁）。
4. Release(7) → Complete：`Removed … amf_ue_ngap_id 7`（清攻击者腿；**old context** 分支 **不拆** 受害 PDU）。
5. 受害 DN **仍通** — Command 未打到合法 gNB。

与 Open5GS 完整 SR 对照：两者都能用 DL 学新 AU；Open5GS 改绑更「脏」（Holding + Idle 扰动），
OAI 侧重 ID 记账 + Command 回弹。均 **非** SD-Core/p09 式跨 gNB 断连。

## T04 — NG Reset（g01）— 版本相关（复测订正）

**复测**（用精确受害 AMF-UE-NGAP-ID + 仅 AMF-UE-ID 的「脆弱路径」变体 `--targets <V>`）：
OAI 回 `NGResetAcknowledge`，AMF healthy（不崩溃），**受害 UE 上下文未被移除**（stats 表中
受害 ID 保持不变、无 `remove_ue_context` 日志、UE ping 持续）。

**版本说明（论文关键）**：源码 `oai-cn5g-fed@8e32ecc` 的 partOfNG 处理器有无绑定的
`remove_ue_context_with_amf_ue_ngap_id(amf_ue_ngap_id)` 全局路径（`amf_n2.cpp:638`，故
`SOURCE_VERIFICATION.md` 标 OAI g01=🔴）；但**本实验运行的镜像是 `oaisoftwarealliance/oai-amf:develop`**，
其 NG Reset **实测不拆除跨 gNB 受害**。→ 与 Open5GS 的「拆除 + SIGABRT 崩溃」形成鲜明对照，
且**印证「必须 pin 版本、动态验证收敛静态标记」**：同一 handler 家族在 8e32ecc（源码 🔴）与
develop（实测无效）行为不同。若论文要主张 OAI g01 🔴，须在 8e32ecc 上复现。

## T01 — Path Switch ⚪ 未实现

`path-switch --source-amf-ue-id 1` → "no reply"。OAI 不实现 Path Switch handler，故 Open5GS/
free5GC 的头号密钥泄露在 OAI 上**无攻击面**（"未实现 ≠ 安全"，但此处确无该面）。

## T08 — UL RAN Config Transfer（SON，g09）⚪

`ul-ran-config-transfer --target-gnb-id 0x1` → OAI 解析出 `SONConfigurationTransfer
(xn-TNL-configuration-info)` 并 `Sending ITTI Uplink RAN Configuration Transfer`，**但未向
目标 gNB 发出 Downlink 中继**（UERANSIM 目标 gNB 无收包日志）。OAI 未实现该盲中继 → 无效果。

## OAI 影响小结

| 能力 | OAI |
|---|---|
| Path Switch 密钥泄露 | ⚪ 未实现（无此面）|
| 远程 AMF 崩溃 DoS | 🟢 无（NG Reset 不崩溃）|
| 跨 gNB 单 UE 释放（UE Context Release）| ◑ 无绑定查找存在，但命令路由回请求方 → **受害未断连** |
| InitUE→Release 链（`chain-initue-release`）| ◑ DL 学新 AU + Release(learned) 清攻击者腿；Command→请求方；**受害 PDU 仍通** |
| 跨 gNB 单 UE 释放（**Handover Notify p09**）| 🔴 ✅ **Release Command 发往受害真实 gNB → RRC 释放** |
| SON/Xn 盲中继 | ⚪ 解析但不中继 |
| 假 TAI 寻呼 | ◑ 解析、未见生效 |
| p16 NRPPa / p21 RAN Status | ◑/🟡 本轮未形成可用跨 gNB 危害（解码失败 / 无 HO target）|

**一句话（2026-07-22 订正）**：OAI 对多数过程仍「子集 + 难利用」，但 **p09 Handover Notify
是明确可利用的跨 gNB 释放面**（与 T06 路由回攻击者形成鲜明对照）。p02/g01 等静态 🔴 仍多被
动态证伪；p09 静态 🔴 被动态**证实**。**静态标记必须由动态验证收敛。**
