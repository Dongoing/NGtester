"""SCTP transport for NGAP. Sends with PPID=60 (NGAP), as the AMF requires.

pysctp is only importable on Linux (needs libsctp); the codec/builders don't
depend on this module, so they stay testable on any host.
"""
from __future__ import annotations

import socket

try:
    import sctp  # pysctp
except ImportError:  # pragma: no cover
    sctp = None

NGAP_PPID = 60


def detect_src_ip(dst_ip: str, dst_port: int = 38412) -> str | None:
    """Source IPv4 the kernel would use to reach dst (UDP trick; no packets sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst_ip, dst_port))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


class SctpNgap:
    def __init__(self, dst_ip: str, dst_port: int = 38412, bind_ip: str | None = None,
                 timeout: float = 5.0):
        if sctp is None:
            raise RuntimeError("pysctp not available — run inside the docker image")
        self.dst = (dst_ip, dst_port)
        # Unbound Linux SCTP INITs advertise *all* local addresses (multi-homing).
        # Commercial AMFs (Huawei) often drop that. UERANSIM binds a single ngapIp
        # — do the same: explicit bind_ip, or the route's source IP.
        if bind_ip in (None, "", "auto", "null"):
            bind_ip = detect_src_ip(dst_ip, dst_port)
        self.bind_ip = bind_ip
        self.sk = sctp.sctpsocket_tcp(socket.AF_INET)
        if bind_ip:
            self.sk.bind((bind_ip, 0))
        self.sk.settimeout(timeout)

    def connect(self):
        self.sk.connect(self.dst)

    def send(self, data: bytes):
        # pysctp's sctp_send() already applies ntohl() to ppid internally, so pass
        # the raw NGAP PPID (60). free5gc strictly checks PPID==60 and discards
        # otherwise (Open5GS is lenient); double-swapping here breaks free5gc.
        self.sk.sctp_send(data, ppid=NGAP_PPID)

    def recv(self, n: int = 65535) -> bytes:
        return self.sk.recv(n)

    def close(self):
        try:
            self.sk.close()
        except Exception:
            pass
