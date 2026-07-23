# Attack case catalogue — g09, g10, g11 (non-UE-associated relay surface)

All three are **non-UE-associated NGAP Class 2** procedures with **no AMF-UE-NGAP-ID /
RAN-UE-NGAP-ID**. The UE-context lookup flaw is therefore irrelevant; the shared
weakness is the **AMF-as-confused-deputy relay**: a rogue but NG-Setup-accepted gNB
supplies a *claimed source RAN node ID* and an attacker-chosen payload, and the AMF
forwards it to a different legitimate gNB (g09/g11) or to the LMF (g10) **without binding
the claimed source to the sending SCTP association / NG Setup identity**.

| proc | message | procCode | msg crit | key IEs (id) |
|---|---|---|---|---|
| g09 | UplinkRANConfigurationTransfer | 48 | ignore | SONConfigurationTransfer (99) |
| g10 | UplinkNonUEAssociatedNRPPaTransport | 47 | ignore | RoutingID (89, reject), NRPPa-PDU (46, reject) |
| g11 | UplinkRIMInformationTransfer | 53 | ignore | RIMInformationTransfer (175, ignore) |

## Case table

| case-id | message | description | distinguishing IE values | missing validation | impact / cross-boundary | confidence | builder |
|---|---|---|---|---|---|---|---|
| g09-a | UplinkRANConfigurationTransfer | Baseline cross-gNB SON/Xn config injection; AMF blind-relays SONConfigurationTransfer to a victim target gNB | target gNB-ID `0x9999`, source gNB-ID = self (`0x1234`/cfg), SON = xn-TNL-configuration-info request | AMF does not check source/target are real neighbours; victim trusts AMF-relayed SON | Malicious gNB → AMF → **legitimate victim gNB**: SON/neighbour poisoning, Xn setup attempts | Likely | EXISTING `B.uplink_ran_configuration_transfer(cfg, target_gnb_id=0x9999, source_gnb_id=cfg["gnb_id"])` |
| g09-b | UplinkRANConfigurationTransfer | Source RAN node ID spoofing: claimed source = another legitimate gNB | source gNB-ID `0x1234`, target gNB-ID `0x9999` | AMF does not bind `sourceRANNodeID` to NG-Setup identity of the SCTP association | Poisons neighbour relation **between two legitimate gNBs**; false attribution in logs/alarms | Likely→speculative (impl-dependent) | EXISTING `B.uplink_ran_configuration_transfer(cfg, target_gnb_id=0x9999, source_gnb_id=0x1234)` |
| g09-c | UplinkRANConfigurationTransfer | Claimed foreign TAI: selectedTAI carries a victim TAC the rogue gNB does not own | tac `99`, target gNB-ID `0x7777`, spoofed source `0x1234` | AMF/target do not enforce PLMN/TAC/topology constraints on relay | Cross-tracking-area relay toward a gNB in another TA | Impl-dependent | EXISTING `B.uplink_ran_configuration_transfer(cfg, target_gnb_id=0x7777, source_gnb_id=0x1234, tac=99)` |
| g10-a | UplinkNonUEAssociatedNRPPaTransport | Baseline forged non-UE NRPPa injection to LMF via AMF confused deputy | RoutingID `00 01`, NRPPa-PDU `00` (opaque placeholder) | AMF relays opaque NRPPa without source authorization; LMF trusts AMF-relayed content | Malicious gNB → AMF → **LMF**: positioning/TRP/assistance-state poisoning affecting remote UEs | Likely (impl-dependent) | NEW `uplink_non_ue_associated_nrppa_transport(cfg, routing_id=b"\x00\x01", nrppa_pdu=b"\x00")` |
| g10-b | UplinkNonUEAssociatedNRPPaTransport | Routing ID abuse to reach an unintended LMF / tenant / positioning domain | RoutingID `ff fe` | AMF does not bind Routing ID to source gNB / SCTP association / PLMN-slice-TAI | Cross-LMF / cross-tenant positioning injection | Impl-dependent | NEW `uplink_non_ue_associated_nrppa_transport(cfg, routing_id=b"\xff\xfe", nrppa_pdu=b"\x00")` |
| g10-c | UplinkNonUEAssociatedNRPPaTransport | TRP/cell-spoofing payload variant: larger attacker-chosen NRPPa-PDU (forged TRP/assistance data placeholder) | RoutingID `00 01`, NRPPa-PDU = 32-byte `de ad be ef …` | LMF does not verify reporting gNB owns referenced NR-CGI / TRP ID | LMF state for **another legitimate gNB's cells** poisoned; wrong location for remote UEs | Likely if LMF weak | NEW `uplink_non_ue_associated_nrppa_transport(cfg, routing_id=b"\x00\x01", nrppa_pdu=b"\xde\xad\xbe\xef"*8)` |
| g11-a | UplinkRIMInformationTransfer | Forged RIM interference report to victim gNB; AMF relays fabricated RIMInformation | target gNB-ID `0x9999`, source = self, RIM = `rs-detected`, gNBSetID 0 | AMF does not verify source/target authorization; target does not corroborate RIM vs radio evidence | Malicious gNB → AMF → **victim gNB**: unnecessary RRM/interference mitigation, scheduling back-off | Likely (radio effect impl-dependent) | NEW `uplink_rim_information_transfer(cfg, target_gnb_id=0x9999, source_gnb_id=cfg["gnb_id"])` |
| g11-b | UplinkRIMInformationTransfer | Source RAN node ID spoofing: claimed source = trusted neighbour gNB | source gNB-ID `0x1234`, target `0x9999` | AMF does not bind `sourceRANNodeID` (RIM) to NG-Setup identity → bypass victim RIM-peer allowlist | Cross-gNB trust/policy bypass, attribution confusion | Likely if source not rebound | NEW `uplink_rim_information_transfer(cfg, target_gnb_id=0x9999, source_gnb_id=0x1234)` |
| g11-c | UplinkRIMInformationTransfer | Multi-target RIM spray variant: second victim + rs-disappeared state, spoofed source | target `0x7777`, source `0x1234`, gNBSetID `0x3FFFFF`, RIM = `rs-disappeared` | AMF allows one source gNB to address arbitrary targets; no per-source fan-out limit | One rogue gNB churns RRM/mitigation state on **many legitimate gNBs** | Likely (control-plane load) | NEW `uplink_rim_information_transfer(cfg, target_gnb_id=0x7777, source_gnb_id=0x1234, gnb_set_id=0x3FFFFF, rs_detection="rs-disappeared")` |

## NEW builders (defined in `ngaptester/cases_g09_g11.py`, not builders.py)

- **g10** `uplink_non_ue_associated_nrppa_transport(cfg, *, routing_id, nrppa_pdu)` —
  procedureCode **47**, msg criticality ignore; IEs: RoutingID (id 89, reject, OCTET STRING),
  NRPPa-PDU (id 46, reject, OCTET STRING).
- **g11** `uplink_rim_information_transfer(cfg, *, target_gnb_id, source_gnb_id, tac,
  gnb_set_id, rs_detection)` — procedureCode **53**, msg criticality ignore; sole IE
  RIMInformationTransfer (id 175, ignore) = SEQUENCE{ targetRANNodeID-RIM{globalRANNodeID,
  selectedTAI}, sourceRANNodeID{globalRANNodeID, selectedTAI}, rIMInformation{targetgNBSetID
  BIT STRING(22), rIM-RSDetection ENUM{rs-detected,rs-disappeared}} }.

## Validate

```
python -c "from ngaptester.cases_g09_g11 import CASES,CFG; from ngaptester import ngap; [ngap.encode(c['build'](CFG)) for c in CASES]; print('ALL ENCODE OK', len(CASES))"
# -> ALL ENCODE OK 9
```
