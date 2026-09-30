#!/usr/bin/env bash
# One-shot SD-Core T06 capture + decode (Command dst / PFCP / AMF logs).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
DIR=sdcore_T06_ue_release_victim_disconnect
ABS="$(pwd)/pcap/$DIR"
mkdir -p "$ABS"
GNB=ueransim-sdcore-ueransim-gnb-1
GNB_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$GNB")
V=$(kubectl logs -n sdcore -l app=amf --tail=300 2>&1 \
    | grep -oE 'AMF_UE_NGAP_ID:[0-9]+' | tail -1 | grep -oE '[0-9]+')
echo "V=$V GNB_IP=$GNB_IP"
export AMF_FILTER='sctp or (udp port 8805) or (udp port 2152) or (tcp portrange 8000-9100) or (tcp port 29518)'
CFG_CORE=sdcore ./capture_attack.sh "$DIR" sdcore-control-plane - "$GNB" kind 20 \
  -- ue-release --amf-ue-id "$V" --ran-ue-id 99
echo "=== AMF log markers ==="
kubectl logs -n sdcore -l app=amf --tail=100 2>&1 \
  | grep -iE 'UE Context Release|send UE Context|RanUe|Error Indication|deactivate|No RanUe' \
  | tail -40
echo "=== pcap listing ==="
ls -la "$ABS"
echo "=== NGAP 41/42 src/dst ==="
MSYS_NO_PATHCONV=1 docker run --rm -v "$ABS:/cap" nicolaka/netshoot \
  tshark -r /cap/amf_ngap_nas_sbi.pcap \
  -Y 'ngap.procedureCode==41 or ngap.procedureCode==42' \
  -T fields -e frame.number -e ip.src -e ip.dst -e ngap.procedureCode \
  -e ngap.AMF_UE_NGAP_ID -e ngap.RAN_UE_NGAP_ID 2>/dev/null || true
echo "=== PFCP SessMod (54) count ==="
MSYS_NO_PATHCONV=1 docker run --rm -v "$ABS:/cap" nicolaka/netshoot \
  tshark -r /cap/amf_ngap_nas_sbi.pcap -Y 'pfcp.msg_type==54' \
  -T fields -e frame.number 2>/dev/null | wc -l
echo "expected victim gNB IP=$GNB_IP"
