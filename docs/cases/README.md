# Attack case catalog — index

Every NGAP message's "Candidate Attack Table" (from `ngap_scaffold/output/**`) enumerated
as concrete, encodable **cases** (one per distinct IE-value combination). See
`../ATTACK_CASES.md` for the model; **`DISTINCT_PRIMITIVES.md` for the deduplicated
authoritative list**. Code lives in `ngaptester/cases_<chunk>.py`; run/list with
`python -m ngaptester.cases`. After dedup (removing scale/cosmetic/negative rows):
**39 distinct primitives across 24 messages** (down from 110 raw presets).

| chunk catalog | messages | kept primitives | new builders (procCode; some now unused after dedup) |
|---|---|---|---|
| `cat_p01_p04.md` | p01 PathSwitch, p02 UEContextReleaseReq, p03 HandoverRequired, p04 HandoverCancel | 11 | handover_cancel(10) + 2 wrappers |
| `cat_p05_p09.md` | p05 PDUSessResModifyInd, p06 PDUSessResNotify, p09 HandoverNotify (p07/p08 dropped=NAS negatives) | 6 | pdu_session_resource_modify_indication(27) [p07/p08 encoders kept unused] |
| `cat_p10_p14.md` | p11 RRCInactiveTransition, p12 UERadioCapInfoInd, p13 SecondaryRATDataUsage, p14 LocationReport (p10 dropped) | 4 | rrc_inactive_transition_report(37), ue_radio_capability_info_indication(44), secondary_rat_data_usage_report(52), location_report(18) |
| `cat_p15_p18.md` | p15 LocationReportingFailureInd, p16 UplinkUEAssocNRPPa, p17 CellTrafficTrace (p18 dropped) | 3 | location_reporting_failure_indication(17) |
| `cat_p19_p22.md` | p19 RANCPRelocationInd, p21 UplinkRANStatusTransfer, p22 UplinkRANEarlyStatusTransfer (p20 dropped) | 3 | ran_cp_relocation_indication(57), uplink_ran_early_status_transfer(62) |
| `cat_g01_g04.md` | g01 NGReset, g02 RANConfigUpdate, g03 NGSetup, g04 ErrorIndication | 7 | ng_reset_full |
| `cat_g05_g08.md` | g07 PWSRestartInd, g08 PWSFailureInd (g05/g06 dropped=reverse-direction) | 2 | pws_restart_indication(34), pws_failure_indication(33) |
| `cat_g09_g11.md` | g09 UplinkRANConfigTransfer, g10 UplinkNonUEAssocNRPPa, g11 UplinkRIMInfoTransfer | 3 | uplink_non_ue_associated_nrppa_transport(47), uplink_rim_information_transfer(53) |

The `cat_*.md` narratives still describe the full row set (for reference); only the deduped
presets remain in the `cases_*.py` code.

Each `cat_*.md` row = one case with: case-id (`<msg><letter>`), message, description, the
distinguishing IE values, missing-validation exploited, impact/cross-boundary, confidence,
and which builder+params realize it. Cases already live-confirmed with pcap evidence
(Path Switch, UE Release, Error Indication, NG Reset, Handover Required, RAN Config Update,
SON relay — see `../../pcap/` and `../RESULTS_*.md`) are the strongest rows; the rest are
untested variants, many gated (need an in-progress handover / registered target gNB / idle
victim) — the catalog records each case's confidence + precondition.

**Notes carried up from the analysis:** p18 (UEInformationTransfer) and p19 (RANCPRelocationInd)
are keyed by 5G-S-TMSI, not AMF-UE-NGAP-ID — the AMF-UE-NGAP-ID confused-deputy flaw is
structurally unreachable there (negative controls). p20 / g05 / g06 are downlink/reverse-
direction procedures; a gNB→AMF send is a compliance/direction probe (expect reject).
