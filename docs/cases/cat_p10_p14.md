# NGAP cross-gNB test cases — p10..p14 (report / indication messages)

Scope: five UE-associated NG-RAN -> AMF messages that carry mostly opaque
containers / reports. All locate the victim UE by `AMF-UE-NGAP-ID` alone; the
attack primitive is the AMF's (assumed) missing binding of that id to the
`RAN-UE-NGAP-ID`, serving gNB, and SCTP association. Source analysis:
`ngap_scaffold/output/batch22_firstpriority/p1{0..4}_*_response.txt`.

Builders live in `ngaptester/cases_p10_p14.py` (all NEW; `builders.py` untouched).
Opaque containers (`UERadioCapability`, `secondaryRATDataUsageReportTransfer`)
use minimal valid placeholder OCTET STRINGs — the aim is to exercise the sender
binding, not to carry meaningful payloads.

## Procedure codes / IE ids (TS 38.413, ngap-r16.7.0 / 38413-g70.asn)

| Message | procCode | Mandatory IEs (id: type [criticality]) | Optional IEs used |
|---|---|---|---|
| HandoverSuccess | 61 | 10 AMF-UE-NGAP-ID[reject], 85 RAN-UE-NGAP-ID[reject] | — |
| RRCInactiveTransitionReport | 37 | 10[reject], 85[reject], 92 RRCState[ignore], 121 UserLocationInformation[ignore] | — |
| UERadioCapabilityInfoIndication | 44 | 10[reject], 85[reject], 117 UERadioCapability[ignore] | 118 UERadioCapabilityForPaging[ignore] |
| SecondaryRATDataUsageReport | 52 | 10[ignore], 85[ignore], 142 PDUSessionResourceSecondaryRATUsageList[ignore] | 143 HandoverFlag[ignore], 121 UserLocationInformation[ignore] |
| LocationReport | 18 | 10[reject], 85[reject], 121 UserLocationInformation[ignore], 33 LocationReportingRequestType[ignore] | 116 UEPresenceInAreaOfInterestList[ignore] |

## Case table

| case-id | message | description | distinguishing IE values | missing validation | impact / cross-boundary | confidence | builder (NEW) + params |
|---|---|---|---|---|---|---|---|
| p10-a | HandoverSuccess | Inbound gNB->AMF HANDOVER SUCCESS negative/direction test | `AMF-UE-NGAP-ID`=victim, `RAN-UE-NGAP-ID`=attacker | Direction/procedure validation; inbound-handler absence; UE-context binding | Standard verdict **NO** — secure AMF rejects/ignores (wrong direction). Only a non-standard AMF that treats it as early target-success would release remote CHO/DAPS resources (cross-gNB, speculative) | Low (negative test) | `handover_success(amf_ue_id, ran_ue_id)` — procCode 61 |
| p11-a | RRCInactiveTransitionReport | Forge RRC State = CONNECTED for remote victim | `RRCState`=`connected`, `AMF-UE-NGAP-ID`=victim, ULI=cfg cell | AMF binds `AMF-UE-NGAP-ID` to RAN id / serving gNB / SCTP | **YES** — corrupts remote UE reachability/paging state (Finding A) | Likely | `rrc_inactive_transition_report(V_AMF,V_RAN,cfg,rrc_state="connected")` — procCode 37 |
| p11-b | RRCInactiveTransitionReport | RRC State = INACTIVE + spoofed remote-cell ULI | `RRCState`=`inactive`, ULI nci=`0x999` | Same + reported CGI/TAI not checked against reporting gNB | **YES** — ULI poisoning + RRC flip for UE at another gNB (Finding B) | Likely | `rrc_inactive_transition_report(...,rrc_state="inactive",nci=0x999)` |
| p12-a | UERadioCapabilityInfoIndication | Overwrite victim's stored UE Radio Capability | `UERadioCapability`=`00` (opaque placeholder) | Same missing binding; capability accepted from non-serving gNB | **YES** — persistent capability poisoning; AMF ships poison to real gNB -> degraded/failed remote service (Finding A) | Likely | `ue_radio_capability_info_indication(V_AMF,V_RAN,ue_radio_capability=b"\x00")` — procCode 44 |
| p12-b | UERadioCapabilityInfoIndication | Capability poison + forged paging capability | adds `UERadioCapabilityForPaging`={NR:`00`} | Same; optional paging-cap IE stored & reused | **YES** — later PAGING for idle victim uses poisoned paging capability (Finding B) | Impl-dependent / high value | `ue_radio_capability_info_indication(...,include_paging_cap=True)` |
| p13-a | SecondaryRATDataUsageReport | Fabricated secondary-RAT usage for victim PDU session | `PDUSessionResourceSecondaryRATUsageList`=[session 1, opaque transfer] | AMF binding; SMF trusts AMF-forwarded N2 SM info | **YES** — AMF confused deputy forwards to victim SMF/CHF -> charging/CDR corruption (Finding A) | Likely | `secondary_rat_data_usage_report(V_AMF,V_RAN,cfg,pdu_sessions=(1,))` — procCode 52 |
| p13-b | SecondaryRATDataUsageReport | Multi-session usage + HandoverFlag + forged ULI | sessions `(1,2)`, `HandoverFlag`=`handover-preparation`, ULI present | Same; per-session/slice charging state not validated | **YES** — per-PDU-session / cross-slice charging pollution (Findings A/C/D) | Likely / impl-dependent | `secondary_rat_data_usage_report(...,pdu_sessions=(1,2),handover_flag=True,include_uli=True)` |
| p14-a | LocationReport | Spoof remote victim's AMF-stored location | ULI nci=`0x999`, `LocationReportingRequestType`={eventType=`direct`, reportArea=`cell`} | AMF binding; reported CGI/TAI not tied to reporting gNB | **YES** — cross-gNB location spoofing of AMF UE state (Finding A) | Likely | `location_report(V_AMF,V_RAN,cfg,nci=0x999,event_type="direct")` — procCode 18 |
| p14-b | LocationReport | Forged Area-of-Interest presence for remote victim | `UEPresenceInAreaOfInterestList`=[{refId 1, `uEPresence`=`in`}], eventType=`ue-presence-in-area-of-interest` | AMF does not validate against active Location Reporting Control / AOI request state | **YES** — false AOI enter event escapes to LCS/exposure consumers (Finding B) | Likely if AOI implemented | `location_report(...,event_type="ue-presence-in-area-of-interest",aoi_presence="in")` |

## Notes

- **p10 is a negative case** and deliberately retained: the analysis verdict is
  *no security impact* for HANDOVER SUCCESS as a NG-RAN -> AMF message (wrong
  direction; the real cross-boundary target is a forged HANDOVER NOTIFY, already
  covered by `builders.handover_notify`). p10-a serves as a direction-confusion
  probe to confirm the AMF rejects the inbound message.
- Victim ids in `CASES` are placeholders: `V_AMF=2` (enumerated/observed victim
  `AMF-UE-NGAP-ID`), `V_RAN=0xBADC0DE` (attacker-chosen `RAN-UE-NGAP-ID` that a
  correct AMF would reject). Swap in observed values at run time.
- Criticality per IE follows the .asn (note `RRCState`, `UERadioCapability`,
  and the SecondaryRAT ids are `ignore` in the ASN.1, not `reject`).

## Validation

```
python -c "from ngaptester.cases_p10_p14 import CASES,CFG; from ngaptester import ngap; [ngap.encode(c['build'](CFG)) for c in CASES]; print('ALL ENCODE OK', len(CASES))"
# -> ALL ENCODE OK 9
```
