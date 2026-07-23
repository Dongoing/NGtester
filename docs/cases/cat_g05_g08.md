# Attack case catalogue — g05, g06, g07, g08 (overload + PWS, non-UE-associated)

All four are **non-UE-associated NGAP Class 2** procedures with **no AMF-UE-NGAP-ID /
RAN-UE-NGAP-ID** and **no response message**. The confirmed UE-context lookup flaw is
therefore irrelevant. They split into two families:

- **g05 OVERLOAD START / g06 OVERLOAD STOP** are spec-direction **AMF → NG-RAN**. A rogue
  gNB sending them *toward the AMF* is reverse-direction and should be rejected/ignored —
  encoded here to test that. The real cross-boundary risk is second-order: a gNB induces
  AMF overload so the trusted AMF fans OVERLOAD START/STOP out to legitimate gNBs
  (confused-deputy throttling / oscillation). These cases exercise the encoder + the
  reverse-direction acceptance probe; the induced-overload path is a load-generation test,
  not a single PDU.
- **g07 PWS RESTART INDICATION / g08 PWS FAILURE INDICATION** are spec-direction
  **NG-RAN → AMF**. The shared weakness is whether the AMF **binds the message's
  GlobalRANNodeID and the asserted Cell/TAI/Emergency-Area scope to the sending SCTP
  association / NG Setup identity**. If not, one rogue gNB asserts PWS restart/failure for
  cells and areas served by *other* gNBs, and the AMF relays a trusted event to
  CBCF/PWS-IWF and back out to victim gNBs.

| proc | message | procCode | msg crit | key IEs (id) |
|---|---|---|---|---|
| g05 | OverloadStart | 22 | ignore | AMFOverloadResponse=OverloadResponse (2, reject, O); AMFTrafficLoadReductionIndication (9, ignore, O); OverloadStartNSSAIList (49, ignore, O) |
| g06 | OverloadStop | 23 | reject | *(empty IE set)* |
| g07 | PWSRestartIndication | 34 | reject | CellIDListForRestart (16, reject, M); GlobalRANNodeID (27, reject, M); TAIListForRestart (104, reject, M); EmergencyAreaIDListForRestart (23, reject, O) |
| g08 | PWSFailureIndication | 33 | reject | PWSFailedCellIDList (81, reject, M); GlobalRANNodeID (27, reject, M) |

## Case table

| case-id | message | description | distinguishing IE values | missing validation | impact / cross-boundary | confidence | builder |
|---|---|---|---|---|---|---|---|
| g05-a | OverloadStart | Minimal reverse-direction OVERLOAD START toward AMF; only the key OverloadResponse IE | OverloadResponse = `overloadAction: reject-non-emergency-mo-dt` | AMF lacks procedure-direction validation (accepts an AMF→NG-RAN procedure from a gNB) and mutates overload state | Direct: none if rejected. If accepted → AMF overload state poisoned; potential fan-out to legitimate gNBs | Low (spoof should fail); Likely for induced 2nd-order | NEW `overload_start(cfg, overload_action="reject-non-emergency-mo-dt")` |
| g05-b | OverloadStart | Aggressive throttle variant — max control-plane suppression | OverloadResponse = `reject-rrc-cr-signalling`; TrafficLoadReductionIndication = `85` | as g05-a; plus no bound on attacker-asserted reduction % | If the AMF (mis)applies / re-fans the action → severe control-plane throttle at legitimate gNBs, remote-UE RRC/NAS denial | Impl-dependent | NEW `overload_start(cfg, overload_action="reject-rrc-cr-signalling", traffic_reduction=85)` |
| g05-c | OverloadStart | Slice-scoped overload targeting the victim S-NSSAI | OverloadStartNSSAIList = [ sliceOverloadList=[S-NSSAI sst=1/sd=010203], sliceOverloadResponse=`permit-emergency-…-only` ]; TrafficLoadReductionIndication = `50` | AMF lets one gNB's slice load / assertion influence slice overload policy network-wide without attribution | Remote UEs on other gNBs using the same S-NSSAI throttled/denied (cross-slice blast radius) | Impl-dependent | NEW `overload_start(cfg, overload_action="permit-emergency-sessions-and-mobile-terminated-services-only", traffic_reduction=50, nssai_slices=[(1,"010203")])` |
| g06-a | OverloadStop | Empty reverse-direction OVERLOAD STOP toward AMF | *(no IEs)* | AMF lacks procedure-direction validation; clears/oscillates global overload state from a gNB-originated stop | If accepted → one gNB drives OVERLOAD START/STOP churn → admission-control instability at legitimate gNBs | Low (spoof should fail); Speculative for oscillation | NEW `overload_stop(cfg)` |
| g07-a | PWSRestartIndication | Cross-area false PWS restart; victim cells/TAIs under attacker's OWN gNB id | CellIDListForRestart = nR-CGIList [nci `0xABCDE`, `0xABCDF`]; TAIListForRestart = [tac `2`, tac `3`]; GlobalRANNodeID = self (`0x1234`) | AMF does not verify Cell/TAI list belongs to the sending NG-RAN node | Malicious gNB → AMF → **CBCF/PWS-IWF → legitimate victim gNBs**: false warning reload for cells the sender doesn't serve | Likely / impl-dependent | NEW `pws_restart_indication(cfg, cell_ncis=(0xABCDE,0xABCDF), tacs=(2,3))` |
| g07-b | PWSRestartIndication | GlobalRANNodeID impersonation of a victim gNB | GlobalRANNodeID = forged victim `0x9999`; cell nci `0xABCDE`; tac `2` | AMF does not bind body GlobalRANNodeID to the NG Setup identity of the SCTP association | Restart attributed to victim gNB; CBCF/PWS-IWF state + logs poisoned for a gNB that never sent it | Likely / impl-dependent | NEW `pws_restart_indication(cfg, cell_ncis=(0xABCDE,), tacs=(2,), reporting_gnb_id=0x9999)` |
| g07-c | PWSRestartIndication | Emergency-area scope expansion | adds EmergencyAreaIDListForRestart = [`00 00 2a`, `00 00 2b`]; cell `0xABCDE`; tac `2` | AMF/CBCF do not validate emergency-area-to-gNB authorization | Widens reload blast radius to emergency areas the attacker does not own | Impl-dependent | NEW `pws_restart_indication(cfg, cell_ncis=(0xABCDE,), tacs=(2,), emergency_area_ids=[b"\x00\x00\x2a", b"\x00\x00\x2b"])` |
| g08-a | PWSFailureIndication | Forged victim-cell PWS failure under attacker's OWN gNB id | PWSFailedCellIDList = nR-CGIList [nci `0xABCDE`, `0xABCDF`]; GlobalRANNodeID = self (`0x1234`) | AMF does not verify failed-cell ownership vs the sending association | Malicious gNB → AMF → **CBCF/PWS-IWF**: victim cells marked failed → false alarms, retries, corrupted public-warning delivery state | Likely / impl-dependent | NEW `pws_failure_indication(cfg, failed_ncis=(0xABCDE,0xABCDF))` |
| g08-b | PWSFailureIndication | GlobalRANNodeID impersonation — failure attributed to victim gNB | GlobalRANNodeID = forged victim `0x9999`; failed nci `0xABCDE` | AMF trusts body GlobalRANNodeID instead of NG Setup identity of the association | Cross-gNB identity confusion; failure logged against a gNB that sent nothing | Likely / impl-dependent | NEW `pws_failure_indication(cfg, failed_ncis=(0xABCDE,), reporting_gnb_id=0x9999)` |
| g08-c | PWSFailureIndication | Amplification via large failed-cell list from one association | PWSFailedCellIDList = 8 NR-CGIs (`0xAB000..0xAB007`); GlobalRANNodeID = self | AMF/CBCF accept + remediate attacker-asserted failure state with no per-source rate limit / dedup | One gNB → PWS retry/reload fan-out + CBCF/PWS-IWF transaction load toward many legitimate gNBs (control-plane DoS) | Likely | NEW `pws_failure_indication(cfg, failed_ncis=tuple(0xAB000+i for i in range(8)))` |

**Verdict note (from the g05/g06 analyses):** direct gNB-originated OVERLOAD START/STOP is
*not* the real finding — it is the wrong direction and a compliant AMF rejects/ignores it
(g05 Finding D, g06 Finding 3). We still implement the encoder + a reverse-direction case so
the harness can confirm the AMF's rejection behaviour; the substantive risk is the
induced/second-order overload fan-out (a load test, not a single PDU). The PWS cases (g07/g08)
are the genuine single-PDU cross-boundary primitives here.

## NEW builders (defined in `ngaptester/cases_g05_g08.py`, not builders.py)

- **g05** `overload_start(cfg, *, overload_action="reject-non-emergency-mo-dt",
  traffic_reduction=None, nssai_slices=None)` — procedureCode **22**, msg criticality ignore.
  IEs: AMFOverloadResponse (id 2, reject) = OverloadResponse CHOICE `("overloadAction",
  <ENUM>)`; AMFTrafficLoadReductionIndication (id 9, ignore) = INTEGER(1..99);
  OverloadStartNSSAIList (id 49, ignore) = SEQUENCE OF OverloadStartNSSAIItem
  { sliceOverloadList = SEQUENCE OF { s-NSSAI }, sliceOverloadResponse OPTIONAL,
  sliceTrafficLoadReductionIndication OPTIONAL }.
- **g06** `overload_stop(cfg)` — procedureCode **23**, msg criticality reject; **empty**
  protocolIEs list.
- **g07** `pws_restart_indication(cfg, *, cell_ncis, tacs, reporting_gnb_id=None,
  emergency_area_ids=None)` — procedureCode **34**, msg criticality reject. IEs:
  CellIDListForRestart (id 16, reject) = CHOICE `("nR-CGIListforRestart", [NR-CGI…])`;
  GlobalRANNodeID (id 27, reject); TAIListForRestart (id 104, reject) = SEQUENCE OF TAI;
  EmergencyAreaIDListForRestart (id 23, reject, optional) = SEQUENCE OF EmergencyAreaID
  (OCTET STRING(3)).
- **g08** `pws_failure_indication(cfg, *, failed_ncis, reporting_gnb_id=None)` —
  procedureCode **33**, msg criticality reject. IEs: PWSFailedCellIDList (id 81, reject) =
  CHOICE `("nR-CGI-PWSFailedList", [NR-CGI…])`; GlobalRANNodeID (id 27, reject).

`reporting_gnb_id=None` uses the attacker's own gNB id (`cfg["gnb_id"]`); passing a distinct
value forges a victim GlobalRANNodeID for the impersonation cases (g07-b, g08-b).

## Validate

```
python -c "from ngaptester.cases_g05_g08 import CASES,CFG; from ngaptester import ngap; [ngap.encode(c['build'](CFG)) for c in CASES]; print('ALL ENCODE OK', len(CASES))"
# -> ALL ENCODE OK 10
```
