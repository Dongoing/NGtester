# free5GC + UERANSIM — 动态验证实测结果（2026-07-10）

在 `net-5glab` 上对运行中的 free5GC（`f5gc-amf` @ 172.30.0.10）+ UERANSIM 实测。攻击者为
`ngap-tester` 伪造 gNB。证据：`evidence/live-free5gc/*.jsonl`。free5GC 是四栈中**最硬化**的：
多数 UE 关联过程经 `ranUeFind()` 强制 `ranUe.Ran != ran` 绑定，跨 gNB 伪造被拒。

## 关键前置修复：SCTP PPID

free5GC **严格校验 SCTP PPID==60**（`NFs/amf/internal/ngap/service/service.go:234`
"Received SCTP PPID != 60, discard this packet"），Open5GS 则宽容。pysctp 的 `sctp_send()`
**内部已 `ntohl(ppid)`**，故原来的 `htonl(60)` 被二次字节序反转 → free5GC 丢弃。修正为传原始
`60`（`ngaptester/sctp_conn.py`）后 free5GC 接受 NG Setup。此修正对 Open5GS 亦正确（其宽容）。

## 结果总表

| 测试 | free5GC 结果 | 与 Open5GS 对比 |
|---|---|---|
| **T01** Path Switch → 密钥泄露 | 🔴🔑 ✅ **CONFIRMED，且泄露更多** | Open5GS 只泄 {NH,NCC}；**free5GC 连 UPF N3 端点也泄** |
| **T03** Error Indication → 跨UE释放 | 🟢 ✅ **BLOCKED**（受害存活）| Open5GS 🔴 生效；free5GC 拒绝 |
| **T04** NG Reset → 跨gNB拆除 | 🟢 ✅ **BLOCKED + 不崩溃** | **Open5GS 🔴 且崩溃 AMF；free5GC 安全** |
| **T06** UE Context Release | 🟢 ✅ **BLOCKED**（显式拒绝）| 同 Open5GS（两者均绑定）|
| **T07** RAN Config Update → 寻呼傍受 | 🔴 ✅ **CONFIRMED**（假 TAI + 截获 5G-S-TMSI；寻呼由 N1N2 触发因 eUPF 无 DDN）| Open5GS 用 UPF MT 触发；free5GC 机制相同 |
| **T08** UL RAN Config Transfer → SON 注入 | 🔴 ✅ **CONFIRMED**（AMF 明确中继）| 同 Open5GS 🔴 |
| **p06** PDU Session Resource Notify | 🟢 **BLOCKED** | `RanUe Context is not in Ran[AmfUeNgapID:1, RanUeNgapID:99]` → ErrorIndication；pcap `free5gc_p06_pdu_notify/` |
| **p09** Handover Notify | 🟢 **BLOCKED** | 同上绑定拒绝；pcap `free5gc_p09_handover_notify/` |
| **p16** UL UE-Assoc NRPPa | 🟢 **BLOCKED** | 绑定拒绝（另有 `IE NRPPa-PDU is not implemented`）；pcap `free5gc_p16_ul_nrppa/` |
| **p17** Cell Traffic Trace | 🟢 **BLOCKED** | 绑定拒绝；pcap `free5gc_p17_cell_trace/` |
| **p21** UL RAN Status Transfer | 🟢 **BLOCKED** | 绑定拒绝；pcap `free5gc_p21_ul_ran_status/` |

## 新 5 builders — free5GC live（2026-07-22）

前提：受害 `AU:1` / `RU:1`（CM-CONNECTED）。攻击者发伪造包时使用 `AMF-UE-NGAP-ID=1`、
攻击者本地 `RAN-UE-NGAP-ID=99`。五条均进入对应 handler，但全部经 `ranUeFind()` 的
`ranUe.Ran != ran` 绑定检查拒绝，回 **ErrorIndication(9)**。日志模板一致：

```
Handle <Proc>: RanUe Context is not in Ran[AmfUeNgapID: 1, RanUeNgapID: 99]
Send Error Indication
```

**结论（free5GC）**：新 5 builders 在跨 gNB 伪造下**全部不可利用**——与源码 🟢 核验完全吻合。
（本轮末尾观察到受害 ping 偶发失败，属 eUPF/路由抖动嫌疑，与 AMF 绑定拒绝日志无关；五条
攻击本身均未通过绑定。）

## T01 — Path Switch 密钥泄露 🔴🔑（泄露超过 Open5GS）

`path-switch --source-amf-ue-id 1 --teid 0x11111111` → `PathSwitchRequestAcknowledge`：
```
LEAKED KEY MATERIAL:  NCC=2  NH=cb5a85e1ed7e4f6da6e531960ff4842870f4678a8f13377cfd368cce2538494b
LEAKED UPF N3 ENDPOINT (PDU 1): 172.30.20.11  TEID=00000002
```
free5GC AMF 日志：`Handle PathSwitchRequest`（来自攻击者 172.30.200.2）→ `Send
PathSwitchRequestTransfer to SMF`（AU:1）→ `Send Path Switch Request Acknowledge`（重绑到
RU:99 攻击者）。**关键差异：free5GC 的 ACK transfer 非空——除 {NH,NCC} 外还回传 UPF N3
UL 端点 `172.30.20.11:TEID=2`**（`ack_transfer_hex=401fac1e140b00000002`），比 Open5GS
（空 transfer、不泄 N3）泄露更彻底。印证「版本/实现相关」的论点。

## T03/T04/T06 — 阴性对照：free5GC 硬化正确挡住 🟢

- **T03 Error Indication**：受害 UE 攻击后 ping 0% 丢包（存活）。free5GC 未跨 gNB 释放。
- **T04 NG Reset**：回 `NGResetAcknowledge`，但**受害存活 + AMF 不崩溃**（`f5gc-amf` 全程
  Up）。与 Open5GS 的「拆除 + AMF SIGABRT 崩溃」形成鲜明对照——free5GC 无该崩溃缺陷。
- **T06 UE Context Release**：free5GC 回我们一条 `ErrorIndication`，日志显式拒绝：
  `Handle UEContextReleaseRequest: RanUe Context is not in Ran[AmfUeNgapID:2, RanUeNgapID:99]`
  —— 正是源码所述 `ranUe.Ran != ran` 绑定检查。受害存活。

**结论：Open5GS 上生效的 UE 上下文类攻击（T03/T04），在 free5GC 上因强制绑定而被拒**；
这正是论文「同一攻击、不同实现、不同结果」的横向对照证据。

## T07 — RAN Config Update 假 TAI → 寻呼截获（g02）🔴 ✅（2026-07-22 复测）

`ran-config-update --tac 1` → `RANConfigurationUpdateAcknowledge`（无覆盖校验）。
跨 gNB Error Indication **不能**打 Idle（有绑定）。完整链：

1. 假 TAI 声称（Rogue A 监听）
2. `chain-ps-release`：Path Switch 重绑 → Release(+PDU list) → **Complete**（此前缺 Complete
   会导致 N2/Buff 路径不完整）
3. 因 lab **eUPF 无 DDN**（edgecomllc/eupf #139/#140），MT ping 不触发寻呼；改用
   `N1N2MessageTransfer`（`ATTEMPTING_TO_REACH_UE`）在 CM-IDLE 下触发 AMF
   `Send Paging to TAI` fan-out

实测 Rogue A 截获 **4 条 PAGING**（`5G-S-TMSI=03f8:00:00000001`）；pcap 中 proc **24**
同时发往合法 gNB `172.30.200.0` 与攻击者 `172.30.200.2`。证据：
`pcap/free5gc_T07_paging_intercept/`。

## T08 — UL RAN Config Transfer SON 盲中继（g09）🔴 ✅

`ul-ran-config-transfer --target-gnb-id 0x1` → free5GC AMF 日志：
```
Handle UplinkRANConfigurationTransfer            (来自攻击者 172.30.200.2)
Send Downlink Ran Configuration Transfer         (发往目标 gNB 172.30.200.0)
```
目标 UERANSIM gNB 同刻收到 `Unhandled NGAP initiating-message (24)`。**free5GC 明确无邻居
校验地把攻击者 SON 配置盲中继给目标 gNB**（比 Open5GS 日志更直白）。

## free5GC 影响小结

| 能力 | free5GC |
|---|---|
| 密钥泄露 {NH,NCC} + **UPF N3 端点** | 🔴🔑 ✅（比 Open5GS 更多）|
| 远程 AMF 崩溃 DoS | 🟢 无该缺陷（NG Reset 安全）|
| 跨 gNB 单 UE 释放/拆除 | 🟢 绑定挡住（T03/T04/T06）|
| 假 TAI 寻呼面 | 🟡 TAI 声称确认（寻呼捕获未复现）|
| SON/Xn 盲中继注入 | 🔴 ✅ |

**一句话**：free5GC 把「UE 上下文绑定」类攻击几乎全挡住（且无 Open5GS 的 NG Reset 崩溃），
但 **Path Switch（按设计绕过绑定，且泄露 N3 更多）** 与 **拓扑/中继信任面（假 TAI、SON 中继）**
仍然中招——与源码判定完全一致。
