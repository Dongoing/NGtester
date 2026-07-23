# NGAP encoder test-case catalogue — chunk p19–p22

Source analysis: `ngap_scaffold/output/batch22_firstpriority/pXX_*_response.txt`
(section *"## 4. Candidate Attack Table"*). Builders: `ngaptester/cases_p19_p22.py`
(p21 reuses `builders.py`; p19/p20/p22 are NEW shapes defined locally, verified
against `openSource/.../ngap-r16.7.0/38413-g70.asn` and pycrate NGAP).

Threat model: rogue-but-NG-Setup-accepted gNB forges a victim UE identifier on a
UE-associated Class 2 message; the AMF is presumed to select the UE context from
that identifier alone, without binding to `RAN-UE-NGAP-ID`, source gNB, or SCTP
association / handover transaction (confused-deputy). **Caveat by message:** p19 is
NOT keyed by `AMF-UE-NGAP-ID` (keyed by `FiveG-S-TMSI`); p20 is a downlink-only
(AMF→gNB) procedure, so a gNB→AMF send is a reverse-direction probe; p21/p22 are
handover-time procedures whose strong impact is *conditional on an active N2 / DAPS
handover window* for the victim.

| case-id | message | description | distinguishing IE values | missing validation | impact / cross-boundary | confidence | builder |
|---|---|---|---|---|---|---|---|
| p19-a | RANCPRelocationIndication | False CP relocation of a remote NB-IoT UE (confused-deputy relocation) | FiveG-S-TMSI=victim (set=1,ptr=0,TMSI=`01020304`), RAN-UE-NGAP-ID=`0x4242` (rogue), EUTRA-CGI/TAI attacker-claimed, UL-CP-SecurityInformation MAC/Count=0 | AMF resolves UE by forged 5G-S-TMSI; no proof of real RRC re-establishment, no source-gNB/SCTP binding, NAS-MAC not verified | AMF re-points victim's UE-assoc NG connection to rogue node; old legit ng-eNB gets AMF CP Relocation / release → cross-gNB CP hijack + remote-UE DoS | Likely under stated flaw (CP-CIoT only) | NEW `ran_cp_relocation_indication(cfg, ran_ue_id)` — procCode 57 |
| p19-b | RANCPRelocationIndication | Remote-UE DoS via old-context release, bogus NAS security | same, RAN=`0x4243`, UL-CP-SecurityInformation MAC=`0xDEAD` Count=7 | AMF acts on relocation before verifying UL-NAS-MAC/Count against the UE's NAS context | old node releases/desyncs victim context even if hijack later fails; cross-gNB | Likely | NEW (same, `mac`/`count` varied) |
| p19-c | RANCPRelocationIndication | Enumeration / relocation storm across UE contexts | different victim 5G-TMSI=`0a0b0c0d`, RAN=`0x4244` | no per-gNB rate limit; per-UE state allocated before validating relocation eligibility | fan confused-deputy relocation + spurious AMF CP Relocation to many legit nodes; shared-CP load | Implementation-dependent | NEW (same, `tmsi` varied) |
| p20-a | ConnectionEstablishmentIndication | Reverse-direction CEI probe (direction-validation test) | AMF-UE-NGAP-ID=`0x0001` (victim), RAN-UE-NGAP-ID=`0x4242` (rogue), no optional IEs | AMF dispatcher may not reject a downlink-only procedure arriving uplink; if it resolves by AMF-UE-NGAP-ID it may rebind/leak | if accepted: serving-gNB rebind → downlink control-plane blackhole of remote UE; else clean reject | Speculative / non-standard | NEW `connection_establishment_indication(amf, ran)` — procCode 65 |
| p20-b | ConnectionEstablishmentIndication | Reverse-direction CEI carrying UERadioCapability | same IDs + UERadioCapability=`00 01 02 03` (OCTET STRING) | permissive AMF may parse/store attacker-supplied UE context from a wrong-direction msg | tests whether attacker can seed victim UE context / observe confused-deputy parse path | Speculative | NEW (same, `ue_radio_capability` set) |
| p21-a | UplinkRANStatusTransfer | Forged PDCP status relay during victim's active N2 handover | AMF=`0x0001`, RAN=`0x4242`, RANStatusTransfer container: DRB-ID=1, UL/DL COUNT (PDCP-SN18/HFN)=0 | AMF looks up by AMF-UE-NGAP-ID only; no RAN-ID / source-gNB / handover-state binding | AMF relays DOWNLINK RAN STATUS TRANSFER (forged PDCP SN/HFN) to legit target gNB → remote-UE handover packet loss/failure; cross-gNB | Likely, conditional on active handover | existing `B.uplink_ran_status_transfer(amf, ran, drb_id)` — procCode 49 |
| p21-b | UplinkRANStatusTransfer | Race / overwrite of legitimate status transfer | same, DRB-ID=2 | no "accept-once" / procedure-phase enforcement at AMF or target | forged status overwrites/conflicts with real source-gNB status for the handover; cross-gNB | Implementation-dependent | existing (`drb_id` varied) |
| p22-a | UplinkRANEarlyStatusTransfer | False early PDCP status injection during DAPS/early-forwarding handover | AMF=`0x0001`, RAN=`0x4242`, EarlyStatusTransfer container: first-dl-count, DRB-ID=1, DL COUNT=0 | AMF relays without source-gNB / prepared-handover binding | AMF relays DOWNLINK RAN EARLY STATUS TRANSFER (forged early status) to legit target gNB → remote-UE DAPS blackhole/loss; cross-gNB | Likely under stated flaw; needs active DAPS handover | NEW `uplink_ran_early_status_transfer(amf, ran)` — procCode 62 |
| p22-b | UplinkRANEarlyStatusTransfer | Race / overwrite early status with non-zero COUNT | same, DL COUNT PDCP-SN18=100000, HFN=42 | weak duplicate / sequence validation on early-status relay | clobbers target's early-forwarding state after real source status arrives; cross-gNB | Implementation-dependent | NEW (`pdcp_sn`/`hfn` varied) |

## NEW builders (not in builders.py — local to cases_p19_p22.py)

- **`ran_cp_relocation_indication(cfg, ran_ue_id, *, tmsi, cell_id, tac, mac, count)`** — procedureCode **57**, EP criticality `reject`. IEs (all mandatory): `id-RAN-UE-NGAP-ID` (85, reject); `id-FiveG-S-TMSI` (26, reject) = AMFSetID(BIT 10)+AMFPointer(BIT 6)+5G-TMSI(OCTET 4); `id-EUTRA-CGI` (25, ignore) = PLMN + EUTRACellIdentity(BIT 28); `id-TAI` (213, ignore) = PLMN + TAC(3 oct); `id-UL-CP-SecurityInformation` (211, reject) = UL-NAS-MAC(BIT 16)+UL-NAS-Count(BIT 5). **Note: no AMF-UE-NGAP-ID in this procedure** — victim is resolved by the forged 5G-S-TMSI (NB-IoT CP-CIoT relocation).
- **`connection_establishment_indication(amf_ue_id, ran_ue_id, *, ue_radio_capability=None)`** — procedureCode **65**, EP criticality `reject`. IEs: `id-AMF-UE-NGAP-ID` (10, reject, M), `id-RAN-UE-NGAP-ID` (85, reject, M), optional `id-UERadioCapability` (117, ignore, OCTET STRING). **Spec direction is AMF→gNB (downlink)**; sending it gNB→AMF is a reverse-direction probe (see note).
- **`uplink_ran_early_status_transfer(amf_ue_id, ran_ue_id, *, drb_id=1, pdcp_sn=0, hfn=0)`** — procedureCode **62**, EP criticality `reject`. IEs (all mandatory): `id-AMF-UE-NGAP-ID` (10, reject), `id-RAN-UE-NGAP-ID` (85, reject), `id-EarlyStatusTransfer-TransparentContainer` (268, reject). Container = `procedureStage` CHOICE `first-dl-count` → FirstDLCount → `dRBsSubjectToEarlyStatusTransfer` list of {DRB-ID, firstDLCOUNT: DRBStatusDL `dRBStatusDL18` {dL-COUNTValue: {pDCP-SN18, hFN-PDCP-SN18}}}. Directly parallels p21's RANStatusTransfer container (DAPS/early-forwarding sibling).

## Notes on the two conditional / weak verdicts

- **p20 (ConnectionEstablishmentIndication) is not a direct attacker-send in standard NGAP.** TS 38.410/38.413 define it AMF→NG-RAN (it delivers UE Radio Capability downlink). The high-value real attack is *induced*: a prior forged uplink UE-associated message makes the AMF emit CEI (with victim context / UE Radio Capability) toward the rogue gNB — a confused-deputy *disclosure*. Our offline encoder can only emit the PDU itself, so p20-a/-b are encoded as **reverse-direction probes** to test dispatcher direction-validation and any AMF-UE-NGAP-ID-keyed rebind. Treat a clean reject as the expected (secure) outcome.
- **p19 is keyed by FiveG-S-TMSI, not AMF-UE-NGAP-ID**, and is scoped to NB-IoT Control Plane CIoT 5GS Optimisation re-establishment (AMF CP Relocation applies to ng-eNB). The defensible finding is *false control-plane relocation / remote-UE DoS* (confused deputy toward the old legit node), **not** generic UPF/N3 path hijack — the analysis explicitly downgrades any GTP-U redirection claim to speculative for this procedure.
- **p21/p22 impact is conditional on an active handover** (N2 for p21, DAPS/early-forwarding for p22); outside a prepared-handover window a correct target/AMF should drop the relayed status. Both are otherwise identical confused-deputy PDCP-status-poisoning primitives distinguished only by the transparent-container type.

## Validation

```
python -c "from ngaptester.cases_p19_p22 import CASES,CFG; from ngaptester import ngap; [ngap.encode(c['build'](CFG)) for c in CASES]; print('ALL ENCODE OK', len(CASES))"
# -> ALL ENCODE OK 9
```
