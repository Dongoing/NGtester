#!/bin/sh
# Probe clock stability inside a running core container (jump > 1.4s in 1s window).
prev=$(date +%s%N); j=0
for i in $(seq 1 "${1:-20}"); do
  sleep 1
  now=$(date +%s%N)
  d=$(( (now - prev) / 1000000 ))
  if [ "$d" -gt 1400 ]; then
    echo "jump ${d}ms @${i}s"
    j=1
  fi
  prev=$now
done
[ "$j" -eq 0 ] && echo "CLOCK STABLE"
