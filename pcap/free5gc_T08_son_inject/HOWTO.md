# free5GC — Uplink RAN Config Transfer → SON/Xn blind relay (T08)

Git Bash, from `ngap_tester/`. Terminals / live logs / how to verify: see [`../README.md`](../README.md).
Non-destructive. Target = the legit UERANSIM gNB, gNB-id **1**.

**1. Core + RAN**
```bash
( cd ../5g-lab && ./scripts/core.sh up free5gc && ./scripts/ran.sh up ueransim free5gc )
# flaky? ../5g-lab/scripts/fix-clock.sh then restart gNB, UE
```
**2. Capture + fire**
```bash
CFG_CORE=free5gc ./capture_attack.sh free5gc_T08_son_inject \
    f5gc-amf f5gc-smf ueransim-free5gc-ueransim-gnb-1 net-5glab 30 \
    -- ul-ran-config-transfer --target-gnb-id 0x1
```
**Expect:** NGAP **21 + 48 + 6** in `amf_ngap_nas_sbi.pcap`; free5GC logs the relay explicitly
(`docker logs f5gc-amf | grep -i 'Send Downlink Ran Configuration Transfer'`).
**Restore:** none (non-destructive).
