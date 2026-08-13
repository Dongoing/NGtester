# 四核心网横向对照 — 同一伪造 gNB 攻击、不同实现、不同结果（动态实测）

在同一实验平台（`net-5glab` / kind、UERANSIM、统一 profile 001/01）上，用**同一个
`ngap_tester` 伪造 gNB**对四套开源 5GC 逐一实测。这是本论文的核心证据：**NGAP 标准设计缺陷
（AMF 未把 AMF-UE-NGAP-ID 绑定发起者）是否带来真实安全影响，高度依赖具体实现**——静态源码
标记必须由动态验证收敛。

## 主对照表（✅=实测成立 · 🛡=实测被挡 · ◑=部分/无效果 · ⚪=未实现）

| 攻击 (gNB→AMF) | Open5GS 2.8.0 | free5GC | OAI CN5G | SD-Core | 一句话 |
|---|:--:|:--:|:--:|:--:|---|
| **Path Switch → {NH,NCC} 泄露** | ✅🔑 | ✅🔑 **+N3** | ⚪ 未实现 | ✅🔑 **+N3** | 密钥泄露；free5GC/SD-Core 连 UPF N3 端点也泄 |
| **UE Context Release → 远端断连** | 🛡 拒绝 | 🛡 拒绝 | ◑ 无效果 | ✅ **断连** | **同一攻击四结果**：绑定挡住 / 命令回请求方 / 命令达受害 gNB |
| **InitUE→Release 链**（完整 SR） | ◑→✅ **Reject DL 学 AU** + Rel(learned) | 🛡 不偷 serving / 无 DL | ◑ 学 AU；Command→请求方 | (未复测) | Open5GS Holding+cause 0x09；free5GC 要 integrity；见 `chain-initue-release` |
| **Error Indication → 跨UE释放** | ✅ | 🛡 拒绝 | ⚪ | (未测) | Open5GS 绕过 :179；free5GC 绑定挡住 |
| **NG Reset(部分) → 拆除/崩溃** | ✅🔥 **崩 AMF** | 🛡 存活(g01=🟢) | 🛡 存活(develop镜像实测；源码8e32ecc标🔴) | 🛡 存活(g01=🟢, gnb作用域) | **仅 Open5GS：单包崩溃 AMF（已提 issue）** |
| **Handover Required → 强制迁移** | ✅ 无绑定 | (未测) | (未测) | (未测) | Open5GS 无绑定处理到 target 解析 |
| **RAN Config Update → 假TAI寻呼** | ✅ **截获5G-S-TMSI** | ◑ TAI声称确认 | ◑ 解析 | (未深测) | Open5GS 完整截获寻呼；拓扑信任面 |
| **UL RAN Config Transfer → SON中继** | ✅ | ✅ | ⚪ 不中继 | ✅ | 盲中继注入；OAI 未实现该中继 |
| **p09 Handover Notify（新5）** | 🟡 idle / 🔴 **HO窗 Release→受害gNB** | 🛡 绑定挡住 | ✅🔴 **idle即可 Release→受害gNB** | 🛡 per-ran挡住 | Open5GS 需自开 HO 窗；OAI 无窗即可 |
| **p06 PDU Notify（新5）** | ⚪ 未实现 | 🛡 绑定挡住 | ⚪ stub | ✅🔴 **全局查找+重绑+SMF** | SD-Core 独有（需 NotifyList IE）|
| **p17 Cell Traffic Trace（新5）** | ⚪ 未实现 | 🛡 绑定挡住 | ⚪ stub | ✅🔴 **静默重绑+trace** | SD-Core 独有 |
| **p21 UL RAN Status（新5）** | 🟡 idle / 🔴 **HO窗 DL中继→攻击者** | 🛡 绑定挡住 | 🟡 无 HO target | 🛡 per-ran挡住 | Open5GS：p03 开窗后确认中继 |
| **p16 NRPPa（新5）** | ⚪ 未实现 | 🛡 绑定挡住 | ◑ 解码失败 | 🛡 per-ran挡住 | 无跨栈稳定利用面 |

🔑=升级为机密泄露 · 🔥=远程 DoS 崩溃 · +N3=额外泄露 UPF N3 端点

## 四条关键结论（供论文）

1. **"缺失绑定"是 3GPP 标准层缺陷，但影响强依赖实现。** 同一条 UE Context Release Request：
   - **Open5GS / free5GC**：内联/集中 `ranUe.Ran != ran` 绑定检查 → **拒绝**（回 Error Indication）。
   - **OAI**：有无绑定的全局查找（`amf_ue_id_2_ue_ngap_context`），但把释放命令发回**请求方
     （攻击者）** → **受害不断连**（源码级订正 SOURCE_VERIFICATION 的 OAI 🔴）。
   - **SD-Core**：删除守卫 + 命令发往**受害真实 gNB** → **受害真正断连**。
   → 四栈四结果，证明"动态验证不可省"。补充（2026-07-22）：OAI 上 **Handover Notify (p09)**
   与 T06 相反——Release 发往**受害真实 gNB**，裸攻击即可跨 gNB 释放（见 `RESULTS_oai.md`）。
   再补：Open5GS 的 p09/p21 idle 门控可被 **p03 HandoverRequired（无绑定）自开窗口** 绕过——
   窗口内 p21 中继 PDCP 状态到攻击者、p09 释放受害源 gNB（`open5gs_ho_window_p21_p09/`）。

2. **Path Switch 是唯一跨栈稳定的密钥泄露面（按 3GPP 设计绕过绑定）。** Open5GS/free5GC/SD-Core
   均泄 {NH,NCC}；**free5GC 与 SD-Core 的 ACK transfer 非空、额外泄露 UPF N3 端点**（Open5GS
   2.8.0 的 transfer 为空、受 SMF `handover.prepared` 门控，不泄 N3、也不重定向下行）。OAI 不实现。

3. **Open5GS 的 NG Reset 可被单包崩溃 AMF**（`Assertion gnb->ng_reset_ack`，跨 gNB 触发），
   是本轮新发现的**远程 DoS**，其它三栈无此缺陷。已备好可提交的 issue（`open5gs_issue_ng_reset_crash.md`）。

4. **InitialUE 是「脏改绑」原语，与 Path Switch（保 AU 改绑）对照。** 完整明文 Service Request
   （`builders.service_request_nas`）在 Open5GS/OAI 可诱出 **Service Reject + 5GMM cause** 的
   DownlinkNASTransport，从而暴露**新 AMF-UE-NGAP-ID**，再对 learned AU 发 Release；
   free5GC 不偷 serving 且明文 SR 被 header 检查拒绝、无 DL。脚本：
   `verify_chain_initue_then_release.sh`、`pcap/run_full_sr_probe.sh`。

## 各栈"最硬化 → 最脆弱"排序（就本伪造 gNB 面的实测）

**free5GC ≈ Open5GS（绑定硬化）> OAI（子集+命令回请求方，实际最难利用）> SD-Core（删守卫，最脆弱）**

例外：Open5GS 虽单独 Release 绑定较硬，却**独有 NG Reset 崩溃**，且 InitUE+完整 SR 可
Holding 改绑并学新 AU；free5GC 最均衡（绑定硬化、InitUE 不偷 serving、无崩溃，但 Path Switch 连 N3 泄露）。

## 单一决定性缓解

**N2 IPsec**：有它则任何 NGAP 无法注入，本类攻击全部失效。本研究范围明确限定在（对暴露小站/
实验网/部分专网现实存在的）**无 N2 IPsec** 情形，并在论文显著声明该前提。

## 复现

每栈：`5g-lab/scripts/core.sh up <core>` + `ran.sh up ueransim <core>`（SD-Core 走 kind），
`ngap_tester` 用对应 `config/<core>.json`（SD-Core 加 `--network kind`）。逐测详见
`RESULTS_{open5gs,free5gc,oai,sdcore}.md` 与 `tests/T0*.md`。
