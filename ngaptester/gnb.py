"""FakeGNB — connect over SCTP, complete NG Setup, then send arbitrary NGAP."""
from __future__ import annotations

import socket

from . import ngap, builders
from .sctp_conn import SctpNgap


class FakeGNB:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.conn = SctpNgap(cfg["amf_addr"], int(cfg.get("amf_port", 38412)),
                             cfg.get("bind_ip"))

    def connect(self):
        self.conn.connect()

    def ng_setup(self):
        self.conn.send(ngap.encode(builders.ng_setup_request(self.cfg)))
        return ngap.decode(self.conn.recv())

    def send(self, val, wait: bool = True):
        """Encode+send an NGAP PDU value. Optionally wait for a reply (tolerant
        of timeout — many attack messages get no direct reply to us)."""
        self.conn.send(ngap.encode(val))
        self.last_reply_raw = None
        if not wait:
            return None
        try:
            raw = self.conn.recv()
        except (socket.timeout, OSError):
            return None
        self.last_reply_raw = raw
        try:
            return ngap.decode(raw)
        except Exception as e:
            # Some stacks (e.g. SD-Core, an older free5gc fork) encode replies our
            # pycrate NGAP spec can't fully parse. Keep the raw bytes so the caller
            # can still record/inspect them instead of crashing.
            self.last_decode_error = repr(e)
            print(f"[warn] reply decode failed ({e}); raw kept ({len(raw)} bytes)")
            print(f"[raw] {raw.hex()}")
            return None

    def listen(self, duration: float, handler):
        """Keep the association open and decode NGAP the AMF pushes to us (e.g.
        PAGING fanned out to a TAI we claimed). Calls handler(pdu_val) per message
        until `duration` seconds elapse. Tolerant of decode errors / idle timeouts."""
        import time
        self.conn.sk.settimeout(1.0)
        end = time.monotonic() + duration
        while time.monotonic() < end:
            try:
                raw = self.conn.recv()
            except (socket.timeout, OSError):
                continue
            if not raw:
                continue
            try:
                handler(ngap.decode(raw))
            except Exception:
                continue

    def close(self):
        self.conn.close()
