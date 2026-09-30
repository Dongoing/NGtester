#!/usr/bin/env bash
# Build once, then run the tester on the lab network against the AMF.
#   ./run.sh ng-setup
#   ./run.sh error-indication --amf-ue-id 1 --ran-ue-id 1
#   ./run.sh sweep --attack error-indication --amf-range 1-64
set -euo pipefail
cd "$(dirname "$0")"

NET="${NET:-net-5glab}"
IMG="${IMG:-ngap-tester}"
CFG="${CFG:-config/open5gs.json}"

if [ -z "$(docker images -q "$IMG" 2>/dev/null)" ] || [ "${REBUILD:-0}" = "1" ]; then
  echo "[build] $IMG"
  docker build -t "$IMG" .
fi

# MSYS_NO_PATHCONV: keep Git Bash from mangling the --config path on Windows.
MSYS_NO_PATHCONV=1 docker run --rm --network "$NET" "$IMG" --config "$CFG" "$@"
