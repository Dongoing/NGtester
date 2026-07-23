# NGAP encoder test-case catalogue — chunk p15–p18

Source analysis: `ngap_scaffold/output/batch22_firstpriority/pXX_*_response.txt`
(section *"## 4. Candidate Attack Table"*). Builders: `ngaptester/cases_p15_p18.py`
(p16/p17 reuse `builders.py`; p15/p18 are NEW shapes defined locally, verified
against `openSource/.../ngap-r16.7.0/38413-g70.asn`).

Threat model: rogue-but-NG-Setup-accepted gNB forges a victim `AMF-UE-NGAP-ID` on
a UE-associated Class 2 message; the AMF is presumed to select the UE context by
`AMF-UE-NGAP-ID` alone, without binding to `RAN-UE-NGAP-ID`, source gNB, or SCTP
association (confused-deputy).

| case-id | message | description | distinguishing IE values | missing validation | impact / cross-boundary | confidence | builder |
|---|---|---|---|---|---|---|---|
| p15-a | LocationReportingFailureIndication | Remote UE current-location sabotage | AMF-UE-NGAP-ID=victim, RAN-UE-NGAP-ID=stale, Cause=`radioNetwork/unspecified` | AMF lookup by AMF-UE-NGAP-ID only; no RAN-ID / source-gNB / pending-transaction binding | AMF aborts victim's pending Location Reporting Control; cross-gNB → cross-NF (LCS/GMLC) DoS of location | Likely (under stated flaw) | NEW `location_reporting_failure_indication(amf,ran,cause)` — procCode 17; IEs 10/85/15 |
| p15-b | LocationReportingFailureIndication | Emergency / lawful / high-priority location degradation | same, Cause=`misc/unspecified` | same; insufficient correlation with priority/emergency transaction | current location reported as failed → stale/failed LCS result; cross-UE + cross-NF | Implementation-dependent | NEW (same, Cause varied) |
| p15-c | LocationReportingFailureIndication | Location-reporting transaction churn (enumeration) | AMF-UE-NGAP-ID enumerated (+0x11), RAN=0xDEAD, Cause=`protocol/unspecified` | processes failure before verifying serving gNB / transaction state | AMF lookup/log/timer-cleanup load; shared control-plane pressure | Implementation-dependent | NEW (same, IDs varied) |
| p15-d | LocationReportingFailureIndication | Poison future-location state (speculative) | AMF=victim, RAN=stale, Cause=`nas/unspecified` | accepts unsolicited failure and stores durable per-UE failure flag | later location requests skipped/downgraded; cross-UE, persistent | Speculative | NEW (same, Cause varied) |
| p16-a | UplinkUEAssociatedNRPPaTransport | Cross-UE NRPPa payload injection into victim LMF session | AMF=victim, RAN=stale, RoutingID=`00 01`, NRPPa-PDU=16-byte plausible payload | AMF fails to bind AMF-UE-NGAP-ID to source gNB + RAN-ID; LMF trusts AMF-relayed association | attacker payload enters LMF processing as victim-associated NRPPa; cross-UE + cross-NF | Likely (if RoutingID/session accepted) | existing `B.uplink_ue_associated_nrppa_transport` (routing_id, nrppa_pdu) |
| p16-b | UplinkUEAssociatedNRPPaTransport | Victim positioning-session abort/desync | RoutingID=`00 01`, NRPPa-PDU=`ff ff ff ff` (error-like) | AMF misbinding + weak LMF state-machine validation | victim positioning transaction fails/inconsistent; legit response dropped as stale | Implementation-dependent | existing (payload varied) |
| p16-c | UplinkUEAssociatedNRPPaTransport | AMF/LMF NRPPa relay DoS (enumeration flood) | AMF enumerated (+0x22), RAN=0xBEEF, RoutingID=`13 37`, NRPPa-PDU=`00` | no per-gNB rate limit; AMF relays before source validation | AMF/LMF CPU/queue/log/decode load; shared-NF degradation | Likely | existing (IDs/payload varied) |
| p16-d | UplinkUEAssociatedNRPPaTransport | Indirect legitimate-gNB stimulation | RoutingID=`00 02`, NRPPa-PDU=`20 00 00 01` (provoke LMF follow-up) | AMF hides malicious origin; LMF sends trusted downlink to victim's serving gNB | Downlink UE-Associated NRPPa Transport lands at another legit gNB; cross-gNB | Speculative→impl-dependent | existing (payload varied) |
| p17-a | CellTrafficTrace | Remote UE trace redirection / metadata exfiltration | AMF=victim, NGRANTraceID=`aa*8`, TCE-IP=`10.66.6.66` (attacker sink) | no source-gNB/RAN-ID binding; AMF accepts RAN-supplied TCE IP for victim context | victim trace state points at attacker TCE; cross-UE privacy + OAM abuse | Impl-dependent; high value | existing `B.cell_traffic_trace` (trace_id, tce_ip) |
| p17-b | CellTrafficTrace | TCE/OAM reflection / flooding | AMF enumerated (+0x33), RAN=0xCAFE, TraceID=`bb*8`, TCE-IP=`10.66.6.66` | accepts forged UE assoc + attacker TCE without rate limiting | AMF/OAM trace-state alloc + outbound traffic to attacker TCE; cross-NF DoS | Likely (if AMF forwards/records) | existing (IDs varied, same TCE) |
| p17-c | CellTrafficTrace | Trace-state desync / false remote-UE attribution | AMF=victim, TraceID=`c0ffee..99`, NG-RAN CGI nci=0x999 (≠ cfg 17) | missing CGI-to-gNB validation; missing trace-lifecycle validation | victim trace misattributed to a cell it never visited; cross-UE integrity | Likely (vulnerable bookkeeping) | existing (trace_id, nci varied) |
| p18-a | UEInformationTransfer | **Negative control** — FiveG-S-TMSI-keyed, AMF-UE-NGAP-ID flaw unreachable | FiveG-S-TMSI (AMFSetID=1, AMFPointer=0, 5G-TMSI=`00 00 00 01`) | n/a — message not keyed by AMF-UE-NGAP-ID (keyed by FiveG-S-TMSI, id 26) | expect reject/ignore; no victim-context change | Likely negative | NEW `ue_information_transfer(tmsi,...)` — procCode 56; IE 26 |
| p18-b | UEInformationTransfer | **Negative control** + extra-IE / wrong-direction parse path | FiveG-S-TMSI (set=7, ptr=2, TMSI=`0a0b0c0d`) + NB-IoT-UEPriority=255 | none specific; generic parser/error-handling only | parser/error-handling load at volume only; no cross-UE effect | Impl-dependent | NEW (adds IE 210) |

## NEW builders (not in builders.py — local to cases_p15_p18.py)

- **`location_reporting_failure_indication(amf_ue_id, ran_ue_id, cause)`** — procedureCode **17**, EP criticality `ignore`. IEs: `id-AMF-UE-NGAP-ID` (10, reject), `id-RAN-UE-NGAP-ID` (85, reject), `id-Cause` (15, ignore). All mandatory. No container/NAS payload → trivially forgeable.
- **`ue_information_transfer(tmsi, amf_set_id, amf_pointer, nb_iot_priority=None)`** — procedureCode **56**, EP criticality `reject`. IEs: `id-FiveG-S-TMSI` (26, reject, mandatory) = AMFSetID(BIT 10)+AMFPointer(BIT 6)+5G-TMSI(OCTET 4); optional `id-NB-IoT-UEPriority` (210, ignore, INTEGER 0..255).

## Note on p18 (why it is a negative finding)

The p18 analysis and the ASN.1 agree: `UEInformationTransfer` is **not** a normal
connected-mode UE-associated message keyed by `AMF-UE-NGAP-ID`. In 38413-g70.asn its
mandatory key is `id-FiveG-S-TMSI` (id 26); the remaining IEs (NB-IoT-UEPriority,
UERadioCapability, S-NSSAI, AllowedNSSAI, UE-DifferentiationInfo) are optional and none
is `AMF-UE-NGAP-ID` / `RAN-UE-NGAP-ID`. The Retrieve-UE-Information family operates
*before* NG-connection setup (CP-CIoT / NB-IoT), so the confirmed AMF-UE-NGAP-ID-only
lookup flaw cannot be reached. p18 cases are therefore negative controls: valid,
unsolicited PDUs used to confirm the AMF rejects/ignores them and performs no
victim-context lookup and no SMF/UPF side-effects.

## Validation

```
python -c "from ngaptester.cases_p15_p18 import CASES,CFG; from ngaptester import ngap; [ngap.encode(c['build'](CFG)) for c in CASES]; print('ALL ENCODE OK', len(CASES))"
# -> ALL ENCODE OK 13
```
