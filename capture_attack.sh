#!/usr/bin/env bash
# Capture COMPLETE evidence for one attack: at the AMF we grab NGAP+NAS(SCTP) AND
# SBI(TCP HTTP/2) in one pcap; at the SMF we grab SBI + PFCP(N4, udp/8805); at the
# legit gNB we grab N2(SCTP) + N3 GTP-U(udp/2152). Captures keep running for
# POST seconds AFTER the attack so the AMF's follow-on operations are recorded.
#
#   ./capture_attack.sh <dir> <amf_ctr> <smf_ctr> <gnb_ctr> <net> <post_s> -- <tester args...>
#   ./capture_attack.sh open5gs_T01_path_switch o5gs-amf o5gs-smf \
#       ueransim-open5gs-ueransim-gnb-1 net-5glab 30 -- path-switch --source-amf-ue-id 1
#
# amf_ctr may be a k8s node container (SD-Core: sdcore-control-plane) — it shares
# the netns that sees the AMF pod's N2. Pass "-" for smf/gnb to skip that capture.
set -uo pipefail
cd "$(dirname "$0")"

DIR="$1"; AMF="$2"; SMF="$3"; GNB="$4"; NET="$5"; POST="$6"; shift 6
[ "${1:-}" = "--" ] && shift
CFG_CORE="${CFG_CORE:-open5gs}"        # which config/<core>.json for the tester
IMG="${IMG:-ngap-tester}"
OUT="pcap/$DIR"; mkdir -p "$OUT"
ABS="$(pwd)/$OUT"

log(){ echo -e "\033[1;36m[cap]\033[0m $*"; }

# filters: AMF/SMF want NGAP(sctp)+SBI(tcp)+PFCP(udp 8805)+GTP-U(udp 2152); gNB N2+N3.
# On a k8s node netns (SD-Core) plain "tcp" also grabs the API server/etcd — set
# AMF_FILTER to scope SBI to the 5GC ports instead.
F_NODE="${AMF_FILTER:-sctp or tcp or (udp port 8805) or (udp port 2152)}"
F_GNB='sctp or (udp port 2152)'

start_cap(){ # name container filter file
  local n="$1" c="$2" f="$3" out="$4"
  [ "$c" = "-" ] && return 0
  docker inspect "$c" >/dev/null 2>&1 || { log "skip $n ($c not found)"; return 0; }
  docker rm -f "cap-$n" >/dev/null 2>&1 || true
  MSYS_NO_PATHCONV=1 docker run -d --name "cap-$n" --net "container:$c" \
    -v "$ABS:/cap" nicolaka/netshoot \
    tcpdump -i any -s0 -U -w "/cap/$out" $f >/dev/null 2>&1 \
    && log "capturing $n on $c -> $out" || log "! failed to start $n cap"
}

stop_cap(){ for n in amf smf gnb; do docker rm -f "cap-$n" >/dev/null 2>&1 || true; done; }

trap stop_cap EXIT

log "=== $DIR ==="
start_cap amf "$AMF" "$F_NODE" "amf_ngap_nas_sbi.pcap"
start_cap smf "$SMF" "$F_NODE" "smf_sbi_pfcp.pcap"
start_cap gnb "$GNB" "$F_GNB" "legit_gnb_n2_n3.pcap"
sleep 3

log "firing attack: $*"
MSYS_NO_PATHCONV=1 docker run --rm --network "$NET" -v "$ABS:/evidence" \
  "$IMG" --config "config/$CFG_CORE.json" --evidence /evidence/attack.jsonl "$@" 2>&1 \
  | sed 's/^/    /'

log "attack sent; capturing AMF follow-on for ${POST}s ..."
sleep "$POST"
stop_cap
trap - EXIT

log "captured files:"
ls -la "$OUT"/*.pcap 2>/dev/null | awk '{print "    "$5" bytes  "$NF}'
# quick NGAP sanity on the AMF pcap
if [ -f "$OUT/amf_ngap_nas_sbi.pcap" ]; then
  procs=$(MSYS_NO_PATHCONV=1 docker run --rm -v "$ABS:/cap" nicolaka/netshoot \
    tshark -r /cap/amf_ngap_nas_sbi.pcap -Y ngap -T fields -e ngap.procedureCode 2>/dev/null | sort -u | tr '\n' ' ')
  log "AMF pcap NGAP procedureCodes: ${procs:-<none>}  (21=NGSetup,25=PathSwitch,41=UECtxtRel,20=NGReset,9=ErrInd,12=HOReqd,48=ULRANCfg)"
fi
log "done: $OUT"
