"""Offline validation: encode + round-trip every builder, and self-test the ACK
leak extractor (no SCTP / no AMF needed).

pycrate rejects wrong IE ids / open-type names / value shapes, so this catches
structural mistakes on the host before we go near the AMF.
"""
from binascii import hexlify

from pycrate_asn1dir import NGAP

from ngaptester import ngap, builders as B, decode

CFG = {"mcc": "001", "mnc": "01", "tac": 1, "sst": 1, "sd": "010203",
       "gnb_id": 4660, "gnb_id_len": 32, "nci": 0x11, "ran_node_name": "ngap-tester"}

cases = {
    "NGSetupRequest": B.ng_setup_request(CFG),
    "UEContextReleaseRequest": B.ue_context_release_request(1, 1),
    "ErrorIndication(UE)": B.error_indication(1, 1),
    "NGReset(partial)": B.ng_reset_partial([(1, 1), (2, 2)]),
    "PathSwitchRequest": B.path_switch_request(1, 99, CFG, pdu_sessions=[1],
                                               attacker_ip="172.30.200.99",
                                               teid=0xdeadbeef),
    "HandoverRequired": B.handover_required(1, 99, CFG, target_gnb_id=0xABCDE),
    "RANConfigurationUpdate": B.ran_configuration_update(CFG, tac=1),
    "UplinkRANConfigurationTransfer": B.uplink_ran_configuration_transfer(
        CFG, target_gnb_id=0xABCDE),
    "PDUSessionResourceNotify": B.pdu_session_resource_notify(1, 99),
    "HandoverNotify": B.handover_notify(1, 99, CFG),
    "UplinkUEAssociatedNRPPaTransport": B.uplink_ue_associated_nrppa_transport(1, 99),
    "CellTrafficTrace": B.cell_traffic_trace(1, 99, CFG, tce_ip="172.30.200.9"),
    "UplinkRANStatusTransfer": B.uplink_ran_status_transfer(1, 99),
}

ok = True
for name, val in cases.items():
    try:
        data = ngap.encode(val)
        back = ngap.decode(data)
        assert ngap.message_type(back) == ngap.message_type(val), \
            f"{ngap.message_type(back)} != {ngap.message_type(val)}"
        print(f"[OK]  {name:26s} {len(data):3d} bytes  {hexlify(data).decode()[:40]}...")
    except Exception as e:
        ok = False
        print(f"[ERR] {name:26s} {type(e).__name__}: {e}")


def _self_test_leak():
    """Synthesize the Open5GS PathSwitchRequestAcknowledge shape and confirm we
    recover NH/NCC + UPF N3 TEID from it."""
    xfer = ngap.encode_transfer("PathSwitchRequestAcknowledgeTransfer",
                                {"uL-NGU-UP-TNLInformation": ("gTPTunnel",
                                 {"transportLayerAddress": B.ip_to_bits("10.45.0.1"),
                                  "gTP-TEID": b"\xde\xad\xbe\xef"})})
    nh = bytes(range(32))
    ack = ("successfulOutcome", {"procedureCode": 25, "criticality": "reject",
           "value": ("PathSwitchRequestAcknowledge", {"protocolIEs": [
               {"id": 10, "criticality": "ignore", "value": ("AMF-UE-NGAP-ID", 7)},
               {"id": 85, "criticality": "ignore", "value": ("RAN-UE-NGAP-ID", 99)},
               {"id": 77, "criticality": "ignore",
                "value": ("PDUSessionResourceSwitchedList",
                          [{"pDUSessionID": 1,
                            "pathSwitchRequestAcknowledgeTransfer": xfer}])},
               {"id": 93, "criticality": "ignore",
                "value": ("SecurityContext",
                          {"nextHopChainingCount": 5,
                           "nextHopNH": (int.from_bytes(nh, "big"), 256)})},
           ]})})
    leak = decode.path_switch_ack_leak(ngap.decode(ngap.encode(ack)))
    assert leak["ncc"] == 5 and leak["nh"] == nh.hex()
    s = leak["sessions"][0]
    assert s["upf_n3_ip"] == "10.45.0.1" and s["upf_n3_teid"] == "deadbeef"
    print("[OK]  ack-leak-extractor          NH/NCC + UPF N3 TEID recovered")


def _self_test_paging():
    """Synthesize a PAGING (as the AMF would fan out to a claimed TAI) and confirm
    paging_info() recovers the victim 5G-S-TMSI."""
    paging = ("initiatingMessage", {"procedureCode": 24, "criticality": "ignore",
        "value": ("Paging", {"protocolIEs": [
            {"id": 115, "criticality": "ignore",
             "value": ("UEPagingIdentity", ("fiveG-S-TMSI", {
                 "aMFSetID": (0x155, 10), "aMFPointer": (0x1f, 6),
                 "fiveG-TMSI": b"\x12\x34\x56\x78"}))},
            {"id": 103, "criticality": "ignore",
             "value": ("TAIListForPaging", [
                 {"tAI": {"pLMNIdentity": B.encode_plmn("001", "01"),
                          "tAC": (1).to_bytes(3, "big")}}])},
        ]})})
    info = decode.paging_info(ngap.decode(ngap.encode(paging)))
    assert info["fiveg_tmsi"] == "12345678", info
    assert info["tais"] == ["000001"], info
    print("[OK]  paging-extractor            5G-S-TMSI + TAI recovered")


try:
    _self_test_leak()
except Exception as e:
    ok = False
    print(f"[ERR] ack-leak-extractor          {type(e).__name__}: {e}")

try:
    _self_test_paging()
except Exception as e:
    ok = False
    print(f"[ERR] paging-extractor            {type(e).__name__}: {e}")

print("\nALL OK" if ok else "\nSOME FAILED")
