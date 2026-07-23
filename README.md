# ngap_tester — rogue-gNB NGAP toolkit for cross-gNB attack validation

A tiny Python "gNB" that does **just enough** — SCTP + NG Setup — to be accepted as
an NG-RAN node by a 5G core, then sends **controlled/crafted NGAP messages** to
exercise the cross-gNB NGAP weaknesses source-verified in
`../ngap_scaffold/source_verification/`. **Not** a real gNB stack. **For authorized
lab use only** (private `net-5glab` / kind, cores you own; premise: **no N2 IPsec**).

Decisive mitigation of this threat class = **N2 IPsec**. This toolkit studies the
no-IPsec case.

| piece | tech |
|---|---|
| Transport | `pysctp` (SCTP, **PPID=60**, passed raw — pysctp already `ntohl`s it; free5GC/SD-Core strictly check PPID, Open5GS is lenient) |
| Encoding | `pycrate` NGAP ASN.1 (TS 38.413), APER |
| Runtime | Docker container on lab network(s), targeting AMF N2 |
| Invariant | **Same packets for every core** — only AMF address / docker network changes |

> **Shell.** Run `.sh` scripts in **Git Bash** (not PowerShell). Keep
> `MSYS_NO_PATHCONV=1` before `docker run … -v …` or Git Bash mangles `/cap`-style
> paths. Image `ngap-tester` is built once; rebuild only after editing `ngaptester/`:
> `docker build -t ngap-tester .`

---

## Handoff — read this first (for the next session / LLM)

**Project role.** Sibling of `../ngap_scaffold` (static source audit) and
`../5g-lab` (Open5GS / free5GC / OAI / SD-Core × UERANSIM[/srsRAN/OAI gNB]).
This repo is the **dynamic attacker + evidence**.

**Where truth lives (do not re-derive from case catalogs alone):**

| doc | use |
|---|---|
| `docs/RESULTS_cross_stack.md` | **Headline 4-core matrix** (paper) |
| `docs/RESULTS_{open5gs,free5gc,oai,sdcore}.md` | Per-stack live detail |
| `docs/PROGRESS.md` | Status + open TODOs |
| `pcap/README.md` + `pcap/<dir>/` | Captures + HOWTOs |
| `../ngap_scaffold/source_verification/SOURCE_VERIFICATION.md` | Static flags; **must converge with live** |
| `docs/cases/` | Attack CASE catalog (IE variants); early “Likely/YES” ≠ live verdict |

**Live status snapshot (2026-07-22/23):**

- Classic T01–T08 path: Path Switch / UE Release / Error Ind / NG Reset / HO Required /
  RAN Config Update / SON — done across stacks (see RESULTS).
- **New5 builders live-validated** (p06 / p09 / p16 / p17 / p21):

| msg | Open5GS | free5GC | OAI | SD-Core |
|---|---|---|---|---|
| p06 PDU Notify | ⚪ not impl | 🛡 bind | ⚪ stub | 🔴 rebind+SMF |
| p09 Handover Notify | 🟡 idle block / 🔴 **HO-window Release→victim** | 🛡 bind | 🔴 **idle Release→victim** (+SR Reject) | 🛡 per-ran |
| p16 UL NRPPa | ⚪ not impl | 🛡 bind | ◑ decode fail | 🛡 per-ran |
| p17 Cell Traffic Trace | ⚪ not impl | 🛡 bind | ⚪ stub | 🔴 silent rebind |
| p21 UL RAN Status | 🟡 idle block / 🔴 **HO-window DL→attacker** | 🛡 bind | 🟡 no HO target | 🛡 per-ran |

- Open5GS HO window opened by attacker via unbound `HandoverRequired` (CLI
  `ho-window-inject`). Evidence: `pcap/open5gs_ho_window_p21_p09/`.
- OAI p09 retest evidence: `pcap/oai_p09_handover_notify/` (Release only; no HO Command;
  ~11s later Service Request → Reject cause 101).
- Case catalog / encoders for many other procs exist (`cases_*.py`); **menu “Run CASE by id”
  works**, but most cases are **not** live-validated — treat RESULTS as ground truth.

**Important nuance for next work (p09 × victim RAN):**

- Commercial CN observation (user): after forged HO path, AMF may send
  **HandoverCommand + UEContextRelease** to victim gNB; UERANSIM poorly handles
  HO Command → Service Request may never reach AMF.
- Lab already saw HO Command → UERANSIM `Unhandled successful-outcome` on Open5GS
  HO-window; OAI **idle** p09 sends **Release only** (no HO Command) and SR *does* reach AMF.
- **Not yet retested** with srsRAN / OAI as **victim** gNB. Expect: srsRAN ≈ UERANSIM
  (no inter-gNB N2 HO); OAI gNB has HO Command handlers — best contrast candidate.
  Lab: `../5g-lab/scripts/ran.sh up {ueransim|srsran|oai} <core>`.

**Still open (tester-side):**

- [ ] Menu entry for `ho-window-inject` (CLI-only today).
- [ ] p04 Handover Cancel / g10 Non-UE NRPPa builders (menu still TODO).
- [ ] Victim-RAN contrast for p09 (UERANSIM vs OAI gNB vs srsRAN).
- [ ] File Open5GS NG-Reset crash issue (`docs/open5gs_issue_ng_reset_crash.md`).
- [ ] IPLOOK / Agrand: fill `amf_addr`, attach network, live run.

---

## Quick start — interactive menu

```bash
./menu.sh
```

```
===== core network =====
  1. Open5GS   2. free5GC   3. OAI CN5G   4. SD-Core   5. IPLOOK   6. Agrand   0. exit
select core #: 2                 <- SCTP + NG Setup once

===== [free5GC] packet menu =====
   1. NG Setup (reconnect)
   2. Path Switch Request                  — key {NH,NCC}(+N3)
   3. UE Context Release Request             — remote disconnect (SD-Core)
   4. Error Indication                       — cross-UE release (Open5GS)
   5. NG Reset (partOfNG-Interface)          — teardown / Open5GS AMF crash
   6. Handover Required                      — forced relocation
   7. RAN Configuration Update (+paging)
   8. Uplink RAN Config Transfer (SON)
   9. GTP-U sink
  10. Sweep / discover live victims
  11. Run attack CASE by id                  — docs/cases + cases_*.py
  12. PDU Session Resource Notify            — p06
  13. Handover Notification                  — p09
  14. Uplink UE-assoc NRPPa                  — p16
  15. Cell Traffic Trace                     — p17
  16. Uplink RAN Status Transfer             — p21
  17–18. Handover Cancel / Non-UE NRPPa      — TODO builders
   0. back
```

- NG Setup runs when you pick a core; later packets reuse the association.
- Victim `AMF-UE-NGAP-ID`: type a number, or `sweep` (small/sequential ids only).
- `menu.sh` attaches the container to **both `net-5glab` and `kind`**.
- **`ho-window-inject` is not in the menu** — use CLI (`./run.sh ho-window-inject …`).

## Cores & networks

| # | core | config | network | AMF N2 | victim AMF-UE-NGAP-ID |
|---|---|---|---|---|---|
| 1 | Open5GS 2.8.0 | `config/open5gs.json` | net-5glab | 172.30.0.10 | small sequential → `sweep` OK |
| 2 | free5GC | `config/free5gc.json` | net-5glab | 172.30.0.10 | small (`AU:x` in AMF log) |
| 3 | OAI CN5G | `config/oai.json` | net-5glab | 172.30.0.10 | small (stats table) |
| 4 | SD-Core | `config/sdcore.json` | **kind** | 172.20.0.2 | **large random → kubectl logs** |
| 5 | IPLOOK | `config/iplook.json` | add to `EXTRA_NETS` | fill `amf_addr` | — |
| 6 | Agrand | `config/agrand.json` | add to `EXTRA_NETS` | fill `amf_addr` | — |

Only one of cores 1–3 at a time (shared AMF IP). Switch with
`../5g-lab/scripts/core.sh` + `ran.sh up ueransim <core>`.
If registration fails on WSL2: `../5g-lab/scripts/fix-clock.sh`, then restart gNB/UE.

### Victim id quick oracle

- Open5GS: `docker logs o5gs-amf | grep 'ngap-handler.c:815'`
- free5GC: `docker logs f5gc-amf | grep -oE 'AU:[0-9]+'`
- OAI: periodic stats (`RAN UE NGAP ID | AMF UE NGAP ID`)
- SD-Core: `kubectl logs -n sdcore -l app=amf | grep -oE 'AMF_UE_NGAP_ID:[0-9]+'`

---

## Scriptable CLI

```bash
./run.sh ng-setup
./run.sh path-switch --source-amf-ue-id 1 --teid 0x11111111
./run.sh sweep --attack path-switch --amf-range 1-32
./run.sh ho-window-inject --amf-ue-id 1 --ran-ue-id 99 --mode both
# other cores: CFG=config/<core>.json  (+ --network kind for sdcore)
```

| cmd | NGAP / action | live verdict (summary) |
|---|---|---|
| `ng-setup` | NG SETUP | accepted on all 4 |
| `path-switch --source-amf-ue-id N` | PATH SWITCH | 🔴🔑 Open5GS/free5GC/SD-Core (+N3 on free5GC/SD-Core); ⚪ OAI |
| `ue-release --amf-ue-id N` | UE CONTEXT RELEASE REQ | ✅ SD-Core victim disconnect; 🛡 Open5GS/free5GC; ◑ OAI (cmd→requester) |
| `error-indication --amf-ue-id N` | ERROR INDICATION | ✅ Open5GS; 🛡 free5GC |
| `ng-reset --targets a[:r],...` | NG RESET (partial) | ✅🔥 Open5GS AMF crash; 🛡 others |
| `handover-required --amf-ue-id N` | HANDOVER REQUIRED | ✅ Open5GS no-binding (cond. disclosure) |
| **`ho-window-inject --amf-ue-id N`** | Required→self + Ack + **p21/p09** | ✅ Open5GS: DL status→attacker + Release→victim gNB |
| `pdu-notify --amf-ue-id N` | PDU SESSION RESOURCE NOTIFY (30) | 🔴 SD-Core; 🛡 free5GC; ⚪ Open5GS/OAI |
| `handover-notify --amf-ue-id N` | HANDOVER NOTIFY (11) | 🔴 OAI idle; 🟡/🔴 Open5GS (need HO window); 🛡 free5GC/SD-Core |
| `ul-nrppa --amf-ue-id N` | UL UE-ASSOC NRPPA (50) | no stable exploit surface (bind / not impl / decode fail) |
| `cell-trace --amf-ue-id N` | CELL TRAFFIC TRACE (2) | 🔴 SD-Core; 🛡 free5GC; ⚪ Open5GS/OAI |
| `ul-ran-status --amf-ue-id N` | UL RAN STATUS TRANSFER (49) | 🔴 Open5GS in HO window; else gated/blocked |
| `ran-config-update --tac T --listen S` | RAN CONFIG UPDATE | ✅ Open5GS false-TAI paging |
| `ul-ran-config-transfer --target-gnb-id G` | UL RAN CONFIG TRANSFER | 🔴 SON relay Open5GS/free5GC/SD-Core; ⚪ OAI |
| `gtpu-sink --duration N` | UDP/2152 receiver | T02 sink (no NG Setup needed) |
| `sweep --attack X --amf-range LO-HI` | enumerate ids | small ids only |

`ho-window-inject` modes: `--mode both|p21|p09` (default `both`). Target gNB id defaults
to the tester’s own `gnb_id` so AMF sends Handover Request back to the attacker.

Capture helper (3 pcaps + 30 s tail):

```bash
CFG_CORE=oai ./capture_attack.sh oai_p09_handover_notify \
  oai-amf oai-smf ueransim-oai-ueransim-gnb-1 net-5glab 30 -- \
  handover-notify --amf-ue-id 1 --ran-ue-id 99
```

## Offline validation (no SCTP / no AMF)

```bash
python validate_builders.py     # encode + round-trip builders -> ALL OK
python -m ngaptester.cases      # list catalogued CASE ids
```

---

## Layout (what to edit)

```
ngap_tester/
  ngaptester/
    builders.py      # NGAP PDU encoders (incl. new5 + HO Ack helper)
    cli.py           # subcommands (incl. ho-window-inject)
    menu.py          # interactive menu
    cases_*.py       # CASE presets (IE variants); not all live-tested
    decode.py / ngap.py / gnb.py / ...
  config/*.json      # per-core AMF addr, gnb_id, TAC/NCI, ...
  docs/              # RESULTS_*, PROGRESS, cases/, issue draft
  pcap/              # evidence (see pcap/README.md)
  capture_attack.sh  menu.sh  run.sh  validate_builders.py
```

Source-of-truth for **static** vulnerability flags:
`../ngap_scaffold/source_verification/` — live RESULTS override “Likely” case notes.

---

## Documentation map

- **`docs/RESULTS_cross_stack.md`** — 4-core comparison (start here for paper claims).
- `docs/RESULTS_{open5gs,free5gc,oai,sdcore}.md` — per-stack live results + caveats.
- `docs/PROGRESS.md` — rolling status / TODOs.
- `docs/00_TEST_PLAN.md` — threat model & early test plan.
- `docs/cases/` + `docs/ATTACK_CASES.md` — CASE catalog (IE combos); verify against RESULTS.
- `docs/open5gs_issue_ng_reset_crash.md` — draft crash report (+ `make_ngreset_pcap.py`).
- `pcap/README.md` — capture index; per-folder `HOWTO.md` / `SUMMARY.txt` where present.
- Evidence JSONL: `evidence/live-{open5gs,free5gc,oai,sdcore}/` (when used).

---

## Status checklist

- [x] SCTP + NG Setup on all 4 cores (PPID fix for free5GC/SD-Core).
- [x] Classic builders + GTP-U sink + sweep + interactive menu (6 cores).
- [x] Live-validated classic attacks (see RESULTS).
- [x] New5 builders: p06 / p09 / p16 / p17 / p21 + offline validate.
- [x] Live new5 across 4 cores; Open5GS `ho-window-inject` for p09/p21.
- [x] OAI p09 retest (Release→victim; SR Reject) with full evidence folder.
- [x] Attack CASE catalog (`cases_*.py`, ~39 primitives) + menu “run by id”.
- [ ] Menu wiring for `ho-window-inject`.
- [ ] p04 / g10 builders.
- [ ] p09 victim-RAN contrast (UERANSIM vs OAI gNB vs srsRAN).
- [ ] File Open5GS NG-Reset issue.
- [ ] IPLOOK / Agrand live.
