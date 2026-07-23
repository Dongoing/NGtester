# OAI CN5G — packet-capture manual

Capture the OAI evidence. **Run everything in Git Bash** (not PowerShell), from the
`ngap_tester/` folder. Each capture writes 3 pcaps (AMF = NGAP+NAS+SBI, SMF = SBI+PFCP,
gNB = N2+N3) and keeps capturing 30 s after the attack, via `./capture_attack.sh`.

> Why OAI = mostly *negative* evidence: OAI implements a subset and routes replies back to
> the *requester*, so cross-gNB attacks that hit other stacks don't take effect here — that's
> the point (static-🔴 ≠ dynamically-exploitable; see `../docs/RESULTS_oai.md`).

---

## Terminals you'll use

Open **2 Git Bash windows** (a 3rd is optional). All in `ngap_tester/`.

| terminal | job | busy? |
|---|---|---|
| **T1 — driver** | runs setup + each `capture_attack.sh` line + verify. Blocks ~35 s per capture. | main |
| **T2 — live log** | `docker logs -f oai-amf` so you *watch the AMF react* while T1 fires. Optional but recommended. | just tails |
| **T3 — UE state** | (optional) check the victim UE / ping. | idle |

The capture itself is **one command in T1** — it starts the tcpdump sidecars in the
background, fires the attack, waits 30 s, and stops them. You do **not** need a separate
terminal for the capture; T2/T3 are only for *watching*.

```bash
# in every terminal, first:
cd "D:/03_博士期间/自己的成果/04_论文/21_gNB/ngap_tester"
```

---

## Log-watching commands (T2) — pick the NF you care about

`-f` = follow (live). OAI colourises logs; the `sed` strips the colour codes.

```bash
docker logs -f oai-amf 2>&1 | sed 's/\x1b\[[0-9;]*m//g'     # AMF (NGAP/NAS/SBI) — main one to watch
docker logs -f oai-smf 2>&1 | sed 's/\x1b\[[0-9;]*m//g'     # SMF (session/PFCP)
docker logs -f ueransim-oai-ueransim-gnb-1                  # legitimate gNB
docker logs -f ueransim-oai-ueransim-ue-1                   # victim UE
```
Snapshot instead of live: drop `-f` and add `| tail -30`. Stop a live tail with **Ctrl-C**.

---

## Step 1 — bring up OAI + RAN (T1)

```bash
cd ../5g-lab
./scripts/core.sh down free5gc 2>/dev/null; ./scripts/core.sh down open5gs 2>/dev/null  # one docker core at a time
./scripts/core.sh up oai
./scripts/ran.sh up ueransim oai
cd ../ngap_tester
# if the UE won't register (WSL2 clock jump): ../5g-lab/scripts/fix-clock.sh
```
Image note: it's built once and reused — you normally do NOT rebuild. `docker images -q
ngap-tester` should print an id; only `docker build -t ngap-tester .` if it's empty or you
edited `ngaptester/`.

## Step 2 — register the victim UE + read its AMF-UE-NGAP-ID (T1)

The UE takes ~15 s to bring up `uesimtun0`. OAI prints a stats table with the id as `0x0N`.
```bash
docker restart ueransim-oai-ueransim-ue-1; sleep 15
docker exec ueransim-oai-ueransim-ue-1 sh -c "ping -I uesimtun0 -c1 -W2 8.8.8.8 >/dev/null && echo UE_ACTIVE"
V=$(docker logs oai-amf 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep '5GMM-REGISTERED' | tail -1 | grep -oE '0x0[0-9a-f]' | head -1)
V=$((16#${V#0x})); echo "victim AMF-UE-NGAP-ID=$V"
```
(empty `V` → UE not registered yet; wait / restart it.)

Now, if you want to watch: start `docker logs -f oai-amf …` in **T2** before firing.

## Step 3 — run the captures (T1)

Re-register the UE (`docker restart …ue-1; sleep 15`) and re-read `V` between destructive ones.

**3a. T06 UE Context Release** — expect victim SURVIVES (command routed to requester)
```bash
CFG_CORE=oai ./capture_attack.sh oai_T06_ue_release_no_effect \
    oai-amf oai-smf ueransim-oai-ueransim-gnb-1 net-5glab 30 \
    -- ue-release --amf-ue-id $V --ran-ue-id 99
```
**3b. T04 NG Reset** — expect NO teardown, NO crash (contrast Open5GS)
```bash
CFG_CORE=oai ./capture_attack.sh oai_T04_ng_reset_no_effect \
    oai-amf oai-smf ueransim-oai-ueransim-gnb-1 net-5glab 30 -- ng-reset --targets $V
```
**3c. p09 Handover Notify** (OAI 🔴 probe — proc 11)
```bash
CFG_CORE=oai ./capture_attack.sh oai_p09_handover_notify \
    oai-amf oai-smf ueransim-oai-ueransim-gnb-1 net-5glab 30 \
    -- handover-notify --amf-ue-id $V --ran-ue-id 99
```
**3d. p16 Uplink UE-assoc NRPPa** (OAI 🔴 probe — proc 50)
```bash
CFG_CORE=oai ./capture_attack.sh oai_p16_ul_nrppa \
    oai-amf oai-smf ueransim-oai-ueransim-gnb-1 net-5glab 30 \
    -- ul-nrppa --amf-ue-id $V --ran-ue-id 99
```
**3e. p21 Uplink RAN Status Transfer** (OAI 🔴 probe — proc 49; gated by an in-progress handover)
```bash
CFG_CORE=oai ./capture_attack.sh oai_p21_ul_ran_status \
    oai-amf oai-smf ueransim-oai-ueransim-gnb-1 net-5glab 30 \
    -- ul-ran-status --amf-ue-id $V --ran-ue-id 99
```

While each runs, T2 (`docker logs -f oai-amf`) shows the handler line (e.g. `Handle UE
Context Release Request`, `Received NGReset`, etc.). The tester's own output in T1 shows the
reply (e.g. `UEContextReleaseCommand`).

## Step 4 — verify a capture (T1)

Remember `MSYS_NO_PATHCONV=1` before `docker run … -v …` in Git Bash, or `/cap` gets mangled.
```bash
D=oai_T06_ue_release_no_effect      # any oai_* folder
ls -la pcap/$D/                      # amf_ngap_nas_sbi.pcap, smf_sbi_pfcp.pcap, legit_gnb_n2_n3.pcap, attack.jsonl
MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD/pcap/$D:/cap" nicolaka/netshoot \
  tshark -r /cap/amf_ngap_nas_sbi.pcap -Y ngap -T fields -e ngap.procedureCode | sort -u
# check victim survived (negative attacks): should still ping
docker exec ueransim-oai-ueransim-ue-1 sh -c "ping -I uesimtun0 -c3 -W2 8.8.8.8 | tail -1"
```
procedureCode cheat-sheet: 21 NGSetup · 42 UEContextReleaseRequest · 41 UEContextReleaseCommand ·
20 NGReset · 11 HandoverNotify · 50 UplinkUEAssocNRPPa · 49 UplinkRANStatusTransfer.

## Step 5 — restore
```bash
docker restart ueransim-oai-ueransim-ue-1
```

---

## One-shot alternative
`run_remaining_captures.sh` does 3a–3e automatically (re-registers the UE between them):
```bash
SECTION=oai bash run_remaining_captures.sh
```
Still one T1 terminal; open T2 (`docker logs -f oai-amf …`) alongside if you want to watch.
