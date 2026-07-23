#!/usr/bin/env bash
# Interactive rogue-gNB console. Launches the ngap-tester container attached to
# BOTH docker networks used by the lab (net-5glab for Open5GS/free5GC/OAI @
# 172.30.0.10, and kind for SD-Core @172.20.0.2), so a single menu can target any
# core. IPLOOK/Agrand: if they live on another network, add it to EXTRA_NETS.
#
#   ./menu.sh
#
set -uo pipefail
cd "$(dirname "$0")"

IMG="${IMG:-ngap-tester}"
PRIMARY_NET="${PRIMARY_NET:-net-5glab}"
EXTRA_NETS="${EXTRA_NETS:-kind}"   # space-separated; add IPLOOK/Agrand nets here
NAME="ngap-tester-menu"

if [ -z "$(docker images -q "$IMG" 2>/dev/null)" ] || [ "${REBUILD:-0}" = "1" ]; then
  echo "[build] $IMG"; docker build -t "$IMG" .
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true

# Create (not run) so we can attach extra networks before starting; override the
# entrypoint to launch the interactive menu module.
MSYS_NO_PATHCONV=1 docker create -it --name "$NAME" --network "$PRIMARY_NET" \
  -v "$(pwd)/evidence:/evidence" \
  --entrypoint python "$IMG" -m ngaptester.menu >/dev/null

for net in $EXTRA_NETS; do
  docker network connect "$net" "$NAME" 2>/dev/null \
    && echo "[net] attached $net" \
    || echo "[net] skip $net (not present)"
done

# -ai = attach + interactive; the menu reads from stdin
docker start -ai "$NAME"
docker rm -f "$NAME" >/dev/null 2>&1 || true
