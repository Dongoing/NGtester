"""NGAP APER codec + helpers, built on pycrate's TS 38.413 ASN.1.

Pure encode/decode — imports only pycrate, so it can be exercised on any host
without SCTP. Transport lives in sctp_conn.py.
"""
from __future__ import annotations

from pycrate_asn1dir import NGAP

_PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
_IEs = NGAP.NGAP_IEs


def encode(val) -> bytes:
    """APER-encode an NGAP PDU value (as produced by the builders)."""
    _PDU.set_val(val)
    return _PDU.to_aper()


def decode(data: bytes):
    """APER-decode bytes into an NGAP PDU value tuple."""
    _PDU.from_aper(data)
    return _PDU.get_val()


def encode_transfer(typename: str, val) -> bytes:
    """APER-encode a nested *-Transfer type (e.g. PathSwitchRequestTransfer),
    which NGAP carries as an OCTET STRING inside the outer PDU."""
    t = getattr(_IEs, typename)
    t.set_val(val)
    return t.to_aper()


def decode_transfer(typename: str, data: bytes):
    """APER-decode a nested *-Transfer type back into a value."""
    t = getattr(_IEs, typename)
    t.from_aper(bytes(data))
    return t.get_val()


def summarize(val) -> str:
    """One-line human description: '<class>/<procedureCode> <MessageType>'."""
    pdu_class, body = val[0], val[1]
    proc = body.get("procedureCode")
    msg_type = body.get("value", (None,))[0]
    return f"{pdu_class}/proc={proc} {msg_type}"


def message_type(val) -> str:
    """The concrete message type name, e.g. 'NGSetupResponse'."""
    return val[1].get("value", (None,))[0]


def get_ies(val) -> dict:
    """Return {protocol-IE-id: value} for the message's protocolIEs list."""
    body = val[1].get("value", (None, {}))[1]
    out = {}
    for ie in body.get("protocolIEs", []):
        out[ie["id"]] = ie.get("value")
    return out
