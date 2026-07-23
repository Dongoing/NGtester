# Packet-capture evidence — cross-gNB NGAP attacks (for reporting)

## How to run these (terminals + logs) — read once, applies to every `<dir>/HOWTO.md`

Run everything in **Git Bash** (not PowerShell), from `ngap_tester/`. You use **2 windows**:

| terminal | job |
|---|---|
| **T1 — driver** | brings up the core, finds the victim id, runs each `capture_attack.sh` line (blocks ~35 s), verifies. |
| **T2 — live log** *(optional)* | tails the AMF log so you *watch it react* while T1 fires the attack. |

One capture = **one command in T1** (it backgrounds the tcpdump sidecars, fires the attack,
waits 30 s, stops them). T2 is only for watching. **Watch-the-log commands** (`-f` = live;
`sed` strips OAI/Open5GS colour codes; Ctrl-C to stop; drop `-f` + add `| tail -30` for a snapshot):

```bash
# AMF (the main one) — swap the container per core: o5gs-amf | f5gc-amf | oai-amf ; SD-Core: kubectl logs -n sdcore -l app=amf -f
docker logs -f o5gs-amf 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
docker logs -f o5gs-smf 2>&1 | sed 's/\x1b\[[0-9;]*m//g'          # SMF (session/PFCP)
docker logs -f ueransim-open5gs-ueransim-gnb-1                    # legitimate gNB
docker logs -f ueransim-open5gs-ueransim-ue-1                     # victim UE
```

Per-core how-tos: each `<dir>/HOWTO.md` gives the exact core-up + victim-id + capture line for
that one attack. OAI has its own step-by-step file: `OAI_CAPTURE_MANUAL.md`.

---

Each subfolder is one (core, attack). Captures were taken with `../capture_attack.sh`,
which records **three** pcaps per attack and keeps capturing **30 s after** the
attack so the AMF's follow-on operations (SBI to SMF, PFCP to UPF, cleanup, crash)
are included:

| pcap file | taken on | contents |
|---|---|---|
| `amf_ngap_nas_sbi.pcap` | the AMF container's netns | **NGAP + NAS** (SCTP/38412; NAS is carried inside NGAP) **and SBI** (TCP/HTTP-2 to SMF/AUSF/UDM/NRF) — one file |
| `smf_sbi_pfcp.pcap` | the SMF container's netns | **SBI** (nsmf UpdateSMContext from AMF) **and PFCP** (N4, UDP/8805 to UPF) |
| `legit_gnb_n2_n3.pcap` | the legitimate UERANSIM gNB netns | **N2** (SCTP) + **N3 GTP-U** (UDP/2152) |
| `attack.jsonl` | — | machine-readable result of the attack (leaked material etc.) |

Attacker (rogue gNB) source IP is in the `172.30.200.x` range (net-5glab) or
`172.20.0.x` (kind, SD-Core). The legitimate gNB is `172.30.10.11` / `172.20.0.3`.

## How to verify a capture — read once, applies to every `<dir>/HOWTO.md`

Each HOWTO's "Expect" line names an NGAP procedureCode and what it proves. To confirm it,
list the NGAP messages in the AMF pcap (keep `MSYS_NO_PATHCONV=1` in Git Bash or `/cap` gets
mangled), and check the effect:

```bash
D=open5gs_T01_path_switch_key_disclosure      # <- the folder you captured
ls -la pcap/$D/                                # 3 pcaps + attack.jsonl exist and are non-empty
MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD/pcap/$D:/cap" nicolaka/netshoot \
  tshark -r /cap/amf_ngap_nas_sbi.pcap -Y ngap -T fields -e ngap.procedureCode | sort -u
cat pcap/$D/attack.jsonl                        # leaked {NH,NCC} / UPF N3 / result (if any)
```
**procedureCode cheat-sheet:** 21 NGSetup · 25 PathSwitch · 42 UEContextReleaseRequest ·
41 UEContextReleaseCommand · 20 NGReset · 9 ErrorIndication · 12 HandoverRequired ·
48 UplinkRANConfigTransfer · 6 DownlinkRANConfigTransfer · 11 HandoverNotify · 50 UL-NRPPa · 49 UL-RANStatus.

**Effect checks:** victim dropped → `docker exec ueransim-<core>-ueransim-ue-1 sh -c "ping -I
uesimtun0 -c3 -W2 8.8.8.8"` shows 100% loss; AMF crashed (Open5GS T04) → `docker ps -a | grep
o5gs-amf` shows `Exited (134)`. Deeper: `tshark -r /cap/smf_sbi_pfcp.pcap -q -z io,phs` to see
the SBI/PFCP follow-on the 30 s tail captured.

---

## Open5GS 2.8.0 (net-5glab, AMF o5gs-amf @172.30.0.10) — DONE

| dir | attack | victim AMF-UE-NGAP-ID | what the pcaps prove |
|---|---|---|---|
| `open5gs_T01_path_switch_key_disclosure/` | Path Switch (proc 25) | 1 | AMF pcap: NGSetup(21)+PathSwitch(25); **SMF pcap: SBI + PFCP** = AMF→SMF→UPF path-switch update (the follow-on). attack.jsonl has the leaked `{NH,NCC}`. |
| `open5gs_T03_error_indication_release/` | Error Indication (proc 9) | 1 | AMF: NGSetup(21)+ErrorIndication(9); SMF: the release/deactivation follow-on. |
| `open5gs_T04_ng_reset_AMF_CRASH/` | **NG Reset (proc 20) → AMF SIGABRT** | 3 | AMF pcap: NGReset→NGResetAcknowledge; **SMF pcap: PFCP(14)+SBI(33)** = the nsmf UpdateSMContext + PFCP deactivation whose async completion fires the `gnb->ng_reset_ack` assertion. The AMF container `Exited (134)` right after. **This is the evidence for the Open5GS issue.** |
| `open5gs_T05_handover_required/` | Handover Required (proc 12) | 2 | AMF: HandoverRequired(12) located the victim with no binding, then AMF ErrorIndication(9) back (target gNB 0xABCDE unknown). |
| `open5gs_T08_son_inject/` | UL RAN Config Transfer (proc 48) | — | AMF: NGSetup(21)+ULRANCfg(48)+relay; blind SON relay to the target gNB. |
| `open5gs_p06_pdu_notify/` | PDU Session Resource Notify (proc 30) | 1 | AMF: NGSetup(21)+Notify(30); AMF log `Not implemented(proc:30)` — no handler. |
| `open5gs_p09_handover_notify/` | Handover Notify (proc 11) idle | 1 | AMF: NGSetup(21)+HandoverNotify(11)+ErrorIndication(9); no in-progress HO → `Cannot find Source-UE Context`. |
| `open5gs_ho_window_p21_p09/` | **HO-window chain** p03→Ack→p21→p09 | 1 | procs `21,12,13,49,7,11,41`: Required→HO-Req/Ack→**DL RAN Status(7) to attacker**→Notify→**UEContextRelease(41) to victim gNB**; UE→CM-IDLE. |
| `open5gs_p16_ul_nrppa/` | UL UE-Assoc NRPPa (proc 50) | 1 | AMF: NGSetup(21)+NRPPa(50); `Not implemented(proc:50)`. |
| `open5gs_p17_cell_trace/` | Cell Traffic Trace (proc 2) | 1 | AMF: NGSetup(21)+CellTrafficTrace(2); `Not implemented(proc:2)`. |
| `open5gs_p21_ul_ran_status/` | UL RAN Status Transfer (proc 49) idle | 1 | AMF: NGSetup(21)+ULRANStatus(49)+ErrorIndication(9); gated by missing handover target context. See `open5gs_ho_window_p21_p09/` for mid-HO CONFIRMED. |

Exact commands are recorded in each `attack.jsonl` and mirror:
`./capture_attack.sh open5gs_T0X_... o5gs-amf o5gs-smf ueransim-open5gs-ueransim-gnb-1 net-5glab 30 -- <subcommand>` (with `CFG_CORE=open5gs`).

---

## free5GC (net-5glab, AMF f5gc-amf @172.30.0.10) — DONE

| dir | attack | victim AU | what the pcaps prove |
|---|---|---|---|
| `free5gc_T01_path_switch_key_n3_disclosure/` | Path Switch (proc 25) | 2 | AMF: NGSetup(21)+PathSwitch(25); **attack.jsonl leaks NH `63f80bc7…` + UPF N3 endpoint `172.30.20.11:TEID=6`** (free5GC's ACK transfer is non-empty, unlike Open5GS); SMF pcap: SBI + PFCP follow-on. |
| `free5gc_T08_son_inject/` | UL RAN Config Transfer (proc 48) | — | AMF: NGSetup(21)+ULRANCfg(48)+DownlinkRANCfg(6) = blind SON relay to the target gNB. |

## SD-Core (kind, AMF pod @172.20.0.2) — DONE

AMF pcap taken on the **kind node netns `sdcore-control-plane`** (sees the AMF pod's
N2 + all pod SBI/PFCP). Tester used `--network kind`. AMF-UE-NGAP-IDs are large
random ints. SD-Core's Path Switch ACK uses an older NGAP encoding pycrate can't
fully decode (`bitlen overflow 32,max 16`) — the raw bytes hold the leak; the pcap
still shows the NGAP procedures cleanly.

| dir | attack | victim AMF-UE-NGAP-ID | what the pcaps prove |
|---|---|---|---|
| `sdcore_T01_path_switch_key_n3_disclosure/` | Path Switch (proc 25) | 16071646 | AMF: NGSetup(21)+PathSwitch(25) + SBI/PFCP path-switch update (91 KB node capture). Victim rebound to attacker (`ranUe.Ran = ran`); leak in `attack.jsonl` raw. |
| `sdcore_T06_ue_release_victim_disconnect/` | **UE Context Release (proc 42) → victim disconnects** | 16071645 | AMF pcap: our **UEContextReleaseRequest(42)** then the AMF's **UEContextReleaseCommand(41)** sent to the VICTIM's real gNB → victim UE dropped. This is the decisive SD-Core result (Open5GS/free5GC block this; OAI sends the command back to the requester). |
| `sdcore_T08_son_inject/` | UL RAN Config Transfer (proc 48) | — | AMF: ULRANCfg(48)+DownlinkRANCfg(6) = blind SON relay to the target gNB. |

## OAI CN5G — pending → **step-by-step manual: `OAI_CAPTURE_MANUAL.md`**

OAI has no clean cross-gNB success (Path Switch ⚪ not implemented; UE Release
routes the command back to the requester so the victim survives; NG Reset no effect
on the running `develop` image — see `../docs/RESULTS_oai.md`). Capturing OAI's
*negative* behaviour (parses-but-no-effect) is still useful evidence for the
static-vs-dynamic argument. **Run `OAI_CAPTURE_MANUAL.md` yourself** — it has the full
numbered steps (image rebuild → `core.sh up oai` → victim id → 5 captures → verify):
T06 ue-release, T04 ng-reset, and the OAI 🔴 new-builder probes p09 handover-notify /
p16 ul-nrppa / p21 ul-ran-status. Or `SECTION=oai bash run_remaining_captures.sh`.

## free5GC — new5 (2026-07-22)

| dir | attack | result |
|---|---|---|
| `free5gc_p06_pdu_notify/` … `free5gc_p21_ul_ran_status/` | p06/p09/p16/p17/p21 | All → ErrorIndication(9); AMF log `RanUe Context is not in Ran[...]` |

## OAI — new5 (2026-07-22)

| dir | attack | result |
|---|---|---|
| `oai_p06_pdu_notify/` | proc 30 | stub / no effect |
| `oai_p09_handover_notify/` | proc 11 | **Retest 2026-07-22 (replaced)**: Release(41)→victim gNB→CM-IDLE; ~11s later Service Request → AMF `5GMM-DEREGISTERED` rejects (cause 101). Logs+SUMMARY in folder. |
| `oai_p16_ul_nrppa_wrongran/` / `oai_p16_ul_nrppa_realpair/` | proc 50 | OAI ASN.1 decode error (both RAN=99 and RAN=1) |
| `oai_p17_cell_trace/` | proc 2 | stub / no effect |
| `oai_p21_ul_ran_status/` | proc 49 | handler tried DL relay; SCTP assoc 0 missing (no HO target) |

## SD-Core — new5 (2026-07-22)

| dir | attack | result |
|---|---|---|
| `sdcore_p06_pdu_notify/` | proc 30 | **CONFIRMED**: global AmfUe lookup + `ranUe.Ran=ran` + SMF UpdateSmContext; pcap procs `21 30` (no ErrInd). Builder needs NotifyList IE 66. |
| `sdcore_p09_handover_notify/` | proc 11 | BLOCKED: per-ran miss → ErrorIndication; procs `11 21 9` |
| `sdcore_p16_ul_nrppa/` | proc 50 | BLOCKED: `No UE Context[RanUeNgapID: 99]`; procs `21 50` |
| `sdcore_p17_cell_trace/` | proc 2 | **CONFIRMED**: silent rebind + Trsr/TCE; procs `2 21` (no ErrInd) |
| `sdcore_p21_ul_ran_status/` | proc 49 | BLOCKED: per-ran miss; procs `21 49` |

## Summary — captured so far

Open5GS T01–T08 + new5 · free5GC T01/T07/T08 + new5 · OAI new5 (esp. **p09**) ·
SD-Core T01/T06/T08 + **new5 (p06/p17 CONFIRMED)**.
