# 受控动态验证 — 测试计划（Open5GS 2.8.0 + UERANSIM）

> **性质声明（授权与范围）**
> 这是一个**防御性安全研究**的受控验证：在**私有实验网 `net-5glab`**（Docker，仅本机）
> 上，复现**源码已确认**的 NGAP 标准设计缺陷（伪造/替换 gNB 在无 N2 IPsec 下伪造上行
> NGAP，AMF 未把 `AMF-UE-NGAP-ID` 绑定到源 gNB），并**测量其真实安全影响**，用于论文
> 证据。所有目标均为本人搭建、拥有完全控制权的实验容器；不针对任何真实/第三方网络。
> 唯一决定性缓解是 **N2 IPsec**——本研究范围明确限定在（对暴露小站/实验网/部分专网现实
> 存在的）无 IPsec 情形，并在论文中显著声明该前提。

本目录记录**每一项测试**：目的、源码依据（file:line）、前置条件、精确命令、预期结果、
判定标准、证据位置、执行状态。实际的**动态执行在独立会话中进行**（见 `RUNBOOK_new_session.md`），
本会话仅负责补全 tester 与固化测试文档。

---

## 1. 威胁模型（一句话）

一个持有**有效、已被接受的 N2/SCTP 关联**（NG Setup 完成、无 N2 IPsec）的伪造 gNB，
伪造上行 NGAP 消息；AMF 按 `AMF-UE-NGAP-ID` 解析 UE 上下文而**不校验发起者身份**
（源 gNB / RAN-UE-NGAP-ID / SCTP），使攻击者得以触及**由另一合法 gNB 服务的远端 UE**、
其他 gNB 或共享核心网状态。

## 2. 被测系统（固定版本）

| 组件 | 值 |
|---|---|
| 核心网 | Open5GS **2.8.0**（容器 `o5gs-amf` @ `172.30.0.10:38412`）|
| 接入侧（受害合法 gNB/UE）| UERANSIM（`ueransim-open5gs-ueransim-gnb-1` / `-ue-1`）|
| 攻击者 | `ngap-tester`（本项目，伪造 gNB，动态 IP，接入 `net-5glab`）|
| 统一 profile | PLMN 001/01，TAC 1，sst=1 sd=010203，DNN internet，IMSI 001010000000001.. |

## 3. 攻击者能力与不需要什么

**需要**：一条到 AMF 的 SCTP/N2 可达路径（实验网内即可）；受害 `AMF-UE-NGAP-ID`（小整数、
可枚举，`sweep` 自动发现，无需事先知道）；一个可猜的 PDU Session ID（PSI=1 近乎通用默认）。
**不需要**：任何密钥、UE 参与、透明容器、先前切换记录（Xn 切换对核心网透明）。

## 4. 源码依据（Open5GS 2.8.0，本机 `openSource/open5gs/src/amf/`）

- `ngap-handler.c:3074` `ran_ue_find_by_amf_ue_ngap_id()` —— Path Switch **仅按
  AMF-UE-NGAP-ID 全局查找**，无源 gNB 绑定（漏洞根因）。
- `ngap-handler.c:3289` `ran_ue_switch_to_gnb()` —— 把受害 UE **重绑到攻击者 gNB**。
- `ngap-handler.c:3309` UE Security Capability 不匹配仅 `ogs_warn`（**非致命**，处理继续）。
- `ngap-handler.c:3361` `amf_sess_find_by_psi()` —— 猜中的 PDU Session ID 必须命中受害
  UE 的真实会话。
- `ngap-build.c:2431-2437` Path Switch ACK 回填 `{NH, NCC}`（SecurityContext IE，id 93）。
- 对照：`ngap-handler.c:179` `ngap_find_ran_ue_by_message_ue_ids()` 对**其它**过程有
  `gnb_id` 绑定检查（Open5GS 已相对上游加固），但 handover 族与 Error Indication 绕过它。

完整跨 4 栈证据见 `../../ngap_scaffold/source_verification/`。

## 5. 测试矩阵

| ID | 测试 | NGAP 消息 | 预期影响 | Open5GS 源判定 | 文档 | 状态 |
|---|---|---|---|:--:|---|---|
| **T01** | Path Switch → 密钥材料泄露 | PATH SWITCH REQUEST | AMF 回 {NH,NCC} 给伪造 gNB | 🔴🔑 CONFIRMED | `tests/T01_*.md` | ✅ 已观测到泄露 |
| **T02** | Path Switch → 下行傍受/中断 | PATH SWITCH REQUEST | 受害 UE 下行 N3 切到攻击者 | 🔴 CONFIRMED | `tests/T02_*.md` | ⏳ 待新会话执行 |
| **T03** | Error Indication → 跨 UE 释放 | ERROR INDICATION | 释放远端受害 UE | 🔴 (g04, 绕过 :179) | `tests/T03_*.md` | ⏳ 待执行 |
| **T04** | NG Reset(部分) → 跨 gNB 拆除 | NG RESET | 拆除他 gNB 上的受害 UE | 🔴 (g01) | `tests/T04_*.md` | ⏳ 待执行 |
| **T05** | Handover Required → 强制迁移 | HANDOVER REQUIRED | 远端 UE 被迫切换/DoS | 🔴 (p03) | `tests/T05_*.md` | ⏳ 待执行 |
| T06 | UE Context Release Request | UE CONTEXT RELEASE REQ | 单包远端断连 | 🟢 Open5GS（SD-Core/OAI 🔴）| `tests/T06_*.md` | ℹ️ Open5GS 上预期不生效（对照项）|
| **T07** | RAN Config Update → 寻呼傍受 | RAN CONFIGURATION UPDATE | 声称受害 TAI → 截获 PAGING(5G-S-TMSI) | 🔴 (g02) | `tests/T07_*.md` | ✅ **CONFIRMED**（截获 3 条，5G-S-TMSI=c000019c）|
| **T08** | UL RAN Config Transfer → SON 注入 | UPLINK RAN CONFIG TRANSFER | 盲中继注入 SON/Xn 到受害 gNB | 🔴 (g09) | `tests/T08_*.md` | ✅ **CONFIRMED**（AMF 盲中继到目标 gNB）|

**第二独立攻击面（拓扑/中继信任缺失，独立于 UE 上下文绑定）**：T07（假 TAI→寻呼傍受）与
T08（SON 盲中继注入）。源码依据见 `SOURCE_VERIFICATION.md` §"Two independent attack surfaces"。

🔑 = 升级为机密泄露。判定图例见 `../../ngap_scaffold/source_verification/SOURCE_VERIFICATION.md`。

## 6. 通用判定原则

- **阳性（漏洞成立）**：AMF 对伪造消息**执行了动作**（切换/释放/迁移），且（对 T01）
  回传了机密材料，或（对 T02）攻击者 sink 收到受害下行、或受害 UE 下行从通变不通。
- **阴性（已绑定/加固）**：AMF 回 `Error Indication`（如 `unknown-local-UE-NGAP-ID`）
  或日志出现 `does not belong` / `No RAN UE Context`，且受害 UE 状态不变。
- **每次执行**都落地：`evidence/<时间戳>/report.md`（人读）+ `evidence.jsonl`（机读）+
  AMF 日志节选。前/后对比（ping、UE 状态）作为影响佐证。

## 7. 复位与安全边界

- 每次攻击后受害 UE 可能被重绑/断连——在实验网内**重新注册**即恢复（`scripts/ran.sh` /
  `scripts/ue.sh`）。不修改任何镜像或持久化数据。
- 仅在 `net-5glab`/本机执行；tester 容器 `--rm` 即用即弃；sink 仅接收不转发。
