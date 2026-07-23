# SD-Core + UERANSIM — 动态验证实测结果（2026-07-10）

SD-Core 跑在 **kind (K8s)**，AMF N2 暴露在 **`kind` docker 网络的 172.20.0.2:38412**（非
net-5glab）。tester 用 `--network kind --config config/sdcore.json`。UE `001010000000001`
的 **AMF-UE-NGAP-ID 是大随机数（如 16071652），不可枚举——须从 AMF 日志读取**
（`kubectl logs -n sdcore -l app=amf | grep AMF_UE_NGAP_ID`）。SD-Core 是 free5GC 的**旧
分叉且删除了绑定守卫**（`findRanUeByAmfNgapID` 裸全局查找 + `ranUe.Ran = ran` 主动重绑），
源码判定为四栈中**最脆弱**。证据：`evidence/live-sdcore/*.jsonl`。

## tester 适配（本轮新增）

1. **PPID**：同 free5GC（原始 60）。
2. **网络**：`--network kind`，AMF `172.20.0.2`。
3. **解码健壮性**：SD-Core（旧 NGAP 规格）对 `UESecurityCapabilities` 用 32-bit 编码某字段，
   pycrate 报 `bitlen overflow: 32, max 16`；已让 `FakeGNB.send()` 在解码失败时**保留原始
   字节并打印**（`[raw] ...`），不再崩溃，可离线提取泄露材料。

## 结果总表

| 测试 | SD-Core 结果 | 关键点 |
|---|---|---|
| **T01** Path Switch → 密钥泄露 | 🔴🔑 ✅ **CONFIRMED**（+ N3 端点）| 见下；ACK 解码需离线（编码差异）|
| **T06** UE Context Release | 🔴 ✅ **CONFIRMED（受害断连！）** | **命令发往受害真实 gNB → 受害掉线**（与 OAI 相反）|
| **T08** UL RAN Config Transfer（SON）| 🔴 ✅ **CONFIRMED** | AMF `send Downlink Ran Configuration Transfer` 到受害 gNB |
| **T04** NG Reset | 🟢 ✅（符合源码 g01=🟢）| gnb-scoped 处理器，跨 gNB 无效——见下 |
| **p06** PDU Session Resource Notify | 🔴 ✅ **CONFIRMED（全局查找+重绑+SMF）** | 见「新 5」；pcap `sdcore_p06_pdu_notify/` |
| **p09** Handover Notify | 🟢 ✅ **BLOCKED** | per-ran `RanUeFindByRanUeNgapID` → ErrorIndication；pcap `sdcore_p09_handover_notify/` |
| **p16** UL UE-Assoc NRPPa | 🟢 ✅ **BLOCKED** | per-ran 查找失败，无 LMF 转发；pcap `sdcore_p16_ul_nrppa/` |
| **p17** Cell Traffic Trace | 🔴 ✅ **CONFIRMED（静默重绑+trace 状态）** | 全局查找 + `ranUe.Ran=ran`；pcap `sdcore_p17_cell_trace/` |
| **p21** UL RAN Status Transfer | 🟢 ✅ **BLOCKED** | per-ran 查找失败；pcap `sdcore_p21_ul_ran_status/` |

## T06 — UE Context Release：受害断连 🔴 ✅（关键对照）

`ue-release --amf-ue-id <victim> --ran-ue-id 99`：
```
ngap/handler.go:2717  UE Context Release Request   ran_addr: 172.20.0.5   (攻击者)
message/send.go:195   send UE Context Release Command  ran_addr: 172.20.0.3  amf_ue_ngap_id:16071655  (受害真实 gNB!)
```
受害 UE 攻击后 **ping 100% 丢包（断连）**。**SD-Core 把释放命令发往受害的真实 gNB（172.20.0.3），
而非请求方**——这正是「删除守卫」的后果，也是与 **OAI（把命令发回请求方、受害不断连）** 的
决定性差异。**同一条 UE Context Release Request：Open5GS/free5GC 拒绝、OAI 无效、SD-Core
成功断连远端受害**——四栈四结果，正是论文核心对照。

## T01 — Path Switch 密钥泄露 🔴🔑 ✅（+ N3 端点）

SD-Core 处理：
```
ngap/dispatcher.go:180  In case of Xn handover source RAN gNB id:...00000001, target...00001234
ngap/handler.go:3232    handle Path Switch Request   ran_addr: 172.20.0.5  (攻击者)
context/ran_ue.go:156   RanUe[RanUeNgapID: 99] Switch to new Ran[Name: ngap-tester]   (受害重绑到攻击者!)
message/send.go:513     send Path Switch Request Acknowledge   amf_ue_ngap_id:16071653
```
从原始 ACK（离线提取，因 SD-Core 编码差异 pycrate 全解码失败）：
```
SecurityContext (IE 93):  NH = b57e68567c64db4d291d72ec8e7b9d2c2acc1d234a7ee09c224fb5af041ebdf1
PDUSessionResourceSwitchedList (IE 77) transfer: UPF N3 UL 端点 (含 gTPTunnel 地址/TEID)
```
**与 free5GC 一样，SD-Core 的 ACK transfer 非空、连 UPF N3 端点一并泄露**（比 Open5GS 更彻底），
且 `ranUe.Ran = ran` 已把受害重绑到攻击者。

## T08 — SON 盲中继 🔴 ✅

`ul-ran-config-transfer --target-gnb-id 0x1` → SD-Core `send Downlink Ran Configuration
Transfer`（发往受害 gNB 172.20.0.3）→ 目标 UERANSIM gNB 收到 `Unhandled NGAP (24)`。
**SD-Core 无邻居校验地把攻击者 SON 配置中继给受害 gNB**（同 Open5GS/free5GC 🔴）。

## T04 — NG Reset 🟢（符合源码判定 g01=🟢）

复测（含仅 AMF-UE-NGAP-ID 的「脆弱路径」变体）：`NGResetAcknowledge`，AMF 不崩溃，受害 UE
**存活**。源码确认这是**正确的硬化行为**：SD-Core 处理器 `amf/ngap/handler.go` 的
`HandlePartOfNGInterface` 对每个列表项只在**发送方 gNB 自己的** `ran.RanUeList` 内按
AMF-UE-NGAP-ID 查找、或 `ran.RanUeFindByRanUeNgapID`（均 gNB 作用域），故跨 gNB 的受害
（在别的 gNB 上）根本找不到 → 不拆除。→ 与 `SOURCE_VERIFICATION.md` 的 **SD-Core g01=🟢**
一致（Open5GS 才是 g01 🔴 且会崩溃）。**订正**：早前误记为"源码 🔴"，实为 🟢，实测吻合。

## 新 5 builders — SD-Core live（2026-07-22）

前提：kind 上 SD-Core；tester `--network kind --config config/sdcore.json`；受害
`AMF-UE-NGAP-ID` 从 `kubectl logs -n sdcore -l app=amf` 读取（大随机数）。攻击者
`RAN-UE-NGAP-ID=99`。builder 侧：`pdu-notify` 已补齐 SD-Core 强制 IE
`PDUSessionResourceNotifyList`（id 66），否则会被 IE-missing 提前 return。

| 消息 | 源码路径 | live | 证据 |
|---|---|---|---|
| **p06** PDUSessResNotify (30) | 全局 `RanUeFindByAmfUeNgapID` → `ranUe.Ran=ran` → `SendUpdateSmContextN2Info` | 🔴 | 本地 RanUe 缺失仅 WARN → 仍用 AmfUe 命中受害 → SMF 路径；pcap **无 ErrorIndication**（proc `21 30`）|
| **p09** HandoverNotify (11) | **仅** `ran.RanUeFindByRanUeNgapID`（per-ran）| 🟢 | `No RanUe Context[AmfUeNgapID:…]` → ErrorIndication；pcap proc `11 21 9` |
| **p16** UL UE-Assoc NRPPa (50) | per-ran `RanUeFindByRanUeNgapID` | 🟢 | `No UE Context[RanUeNgapID: 99]`，无 LMF 转发；pcap proc `21 50` |
| **p17** CellTrafficTrace (2) | 全局 AmfUe 查找 → `ranUe.Ran=ran` → 写 `Trsr`/TCE | 🔴 | 仅 `handle Cell Traffic Trace`，无 Error；pcap proc `2 21`（无 9）|
| **p21** UL RAN Status (49) | per-ran 查找 | 🟢 | `No UE Context[RanUeNgapID: 99]`；pcap proc `21 49` |

### p06 — 全局查找 + 重绑 + SMF（🔴）

修复 NotifyList 后：
```
RanUe does not exist / No UE Context[RanUeNgapID: 99]     # 攻击者 assoc 上无本地上下文
# 随后仍进入受害 AmfUe 路径（全局 AmfUeNgapID 查找 + ranUe.Ran = ran）:
readAll BinaryDataN1SmMessage failed … amf_ue_ngap_id: AMF_UE_NGAP_ID:<victim>
readAll BinaryDataN2SmInformation failed … ran_addr: <受害 gNB>
```
源码（`amf/ngap/handler.go`）：本地 RanUe 失败只 WARN，不 return；接着
`context.AMF_Self().RanUeFindByAmfUeNgapID` 命中受害，`ranUe.Ran = ran` **主动重绑到攻击者**，
再向 SMF 发 `PDU_RES_NTY`。本轮最小 transfer 使 SMF 回包解析报错，但**安全相关的重绑与
SMF 调用已发生**；pcap 无 ErrorIndication。与 free5GC（同消息被 `ranUe.Ran != ran` 挡住）
形成对照。

### p17 — 静默重绑 + Trace 状态（🔴）

```
handle Cell Traffic Trace   # INFO，无后续 ERROR / ErrorIndication
```
源码：全局 `RanUeFindByAmfUeNgapID` → `ranUe.Ran = ran` → 写入 `ranUe.Trsr` 与 TCE IP
（Debug 级日志）。裸攻击即可把受害 UE 的 serving RAN 指针改到攻击者并污染 trace 状态。

### p09 / p16 / p21 — per-ran 挡住（🟢）

这三条**未**走全局 AmfUe 查找（与 p06/p17/T06 不同）：攻击者 assoc 上 `RAN-UE-NGAP-ID=99`
找不到上下文即停。p09 回 ErrorIndication；p16/p21 仅 ERROR 日志、无跨 gNB 副作用。

**结论（SD-Core new5）**：`p06`/`p17` 证实「删守卫」在**非 Path-Switch / 非 Release** 消息上
仍可跨 gNB 重绑；`p09`/`p16`/`p21` 因实现选用 per-ran 查找而挡住——同一栈内也呈「消息级」
差异，动态验证不可省。

## SD-Core 影响小结

| 能力 | SD-Core |
|---|---|
| 密钥泄露 {NH,NCC} + UPF N3 端点 | 🔴🔑 ✅（同 free5GC，超 Open5GS）|
| **跨 gNB 单 UE 释放（受害断连）** | 🔴 ✅（**四栈中唯一实测断连成功**）|
| **p06 Notify / p17 CellTrace 重绑** | 🔴 ✅（new5；free5GC 同消息全挡）|
| SON/Xn 盲中继 | 🔴 ✅ |
| NG Reset 跨 gNB 拆除 | 🛡 gnb作用域挡住（g01=🟢，符合源码）|
| p09/p16/p21（new5） | 🛡 per-ran 查找挡住 |
| 远程 AMF 崩溃 | 🟢 无该缺陷（仅 Open5GS 有）|

**一句话**：SD-Core（删除守卫的旧 free5GC 分叉）在**跨 gNB UE 上下文类攻击上实测最可利用**——
UE Context Release 能真正断连远端受害（Open5GS/free5GC 拒绝、OAI 无效），Path Switch 连 N3
端点一并泄露；新 5 中 p06/p17 再证静默重绑。印证源码「最不硬化」的判定。
