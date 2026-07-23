# Attack-case catalogue: g01-g04

Cross-gNB NGAP interface-management / error procedures. Each case = one distinct
IE-value combination drawn from the "Candidate Attack Table" (section 4) of the
matching analysis in
`ngap_scaffold/output/batch11_secondpriority/g0X_*_response.txt`.

Builders live in `ngaptester/builders.py`; cases and the four new wrappers live in
`ngaptester/cases_g01_g04.py` (builders.py is not modified). Realize a case with
`ngaptester.cases_g01_g04.CASES[i]["build"](CFG)` then `ngap.encode(...)`.

Shared attacker-asserted constants (`cases_g01_g04.py`): `VICTIM_TAC=7`,
`VICTIM_GNB_ID=0x00A1B2`, `TARGET_GNB_ID=0x00C3D4`, `FOREIGN_MCC/MNC=460/00`,
`VICTIM_SST/SD=2/0a0b0c`, `VICTIM_AMF_UE_ID=12345`, `VICTIM_RAN_UE_ID=6789`.

---

## g01 — NG RESET (procedureCode 20, Class 1)

Vulnerable surface: AMF resolves the `partOfNG-Interface` UE list by a global
`AMF-UE-NGAP-ID` lookup instead of verifying each pair belongs to the sending
SCTP association / gNB, so one rogue gNB tears down UEs on other gNBs.

| case | description | distinguishing IE values | missing validation | impact / cross-boundary | confidence | builder + params |
|------|-------------|--------------------------|--------------------|-------------------------|------------|------------------|
| g01-a | Cross-gNB partial reset of a victim UE | `ResetType = partOfNG-Interface`; item = (AMF-UE-ID 12345, RAN-UE-ID 6789) | No pair-to-association binding | Releases a UE served by another gNB; AMF confused deputy | Likely / impl-dependent | `B.ng_reset_partial([(12345,6789)])` |
| g01-b | AMF-UE-ID-only path | partial-list item **omits** `rAN-UE-NGAP-ID` (only AMF-UE-ID 12345) | Handler forced onto unbound global AMF-UE-ID route (free5gc-family) | Remote UE release without knowing RAN-side id | Likely if unsafe lookup reused | `B.ng_reset_partial([(12345,None)])` |
| g01-c | Bogus RAN-UE-NGAP-ID | AMF-UE-ID 12345 paired with arbitrary RAN-UE-ID 999999 (mismatch) | `RAN-UE-NGAP-ID` ignored, no pair match | Low-effort enumeration; victim release despite wrong RAN id | Likely if global lookup reused | `B.ng_reset_partial([(12345,999999)])` |
| g01-d | Whole NG-Interface reset | `ResetType = nG-Interface (ResetAll = reset-all)` | Full-reset scope not bound to sending association | AMF-wide UE teardown if scope escapes association | Speculative, high impact | `ng_reset_full()` *(new wrapper)* |
| g01-e | Large multi-victim list (churn + ACK oracle) | 8 items, each AMF-UE-ID only (12345..12352) | No per-gNB rate limit / max-list; verbose ACK | Multi-UE DoS; ACK/diagnostics reveal which IDs exist | Likely (resource) / speculative (oracle) | `B.ng_reset_partial([(12345+i,None) for i in range(8)])` |

## g02 — RAN CONFIGURATION UPDATE (procedureCode 35, Class 1)

Vulnerable surface: AMF stores the node's `SupportedTAList` / `GlobalRANNodeID`
without checking a provisioned inventory, poisoning TA/PLMN/slice topology used
for paging routing (analysis file g02 is truncated; rows mirror the g03 TA/ID
attack classes for the update procedure).

| case | description | distinguishing IE values | missing validation | impact / cross-boundary | confidence | builder + params |
|------|-------------|--------------------------|--------------------|-------------------------|------------|------------------|
| g02-a | Claim victim TAC | `SupportedTAList` TAC = 7 (not served) | No per-gNB TAC authorization vs inventory | Victim-TA paging fans out to rogue gNB (interception) | Likely / impl-dependent | `B.ran_configuration_update(cfg, tac=7)` |
| g02-b | False PLMN | SupportedTAList under foreign `PLMNIdentity` (mcc/mnc 460/00) | No PLMN authorization check | Cross-PLMN topology poisoning | Impl-dependent | `B.ran_configuration_update(_cfg(cfg,mcc="460",mnc="00"), tac=7)` |
| g02-c | Slice poisoning | `TAISliceSupportList` S-NSSAI = SST 2 / SD 0a0b0c | No S-NSSAI authorization per RAN node | False slice coverage; slice-paging amplification | Impl-dependent | `B.ran_configuration_update(_cfg(cfg,sst=2,sd="0a0b0c"), tac=7)` |
| g02-d | Global RAN Node ID collision | update carries `GlobalRANNodeID` (id 27) = 0x00A1B2 | No unique authenticated ID-to-association binding | Re-binds AMF RAN-node table entry of a legitimate gNB | High impact, impl-dependent | `ran_config_update_with_gnbid(cfg, gnb_id=0x00A1B2, tac=7)` *(new wrapper)* |

## g03 — NG SETUP REQUEST (procedureCode 21, Class 1)

Vulnerable surface: NG Setup is the AMF's trust anchor for a RAN node. Accepting
unverified RAN identity / TA / PLMN / slice claims lets later trusted AMF actions
(paging, handover routing) be misdirected or amplified. Not UE-associated.

| case | description | distinguishing IE values | missing validation | impact / cross-boundary | confidence | builder + params |
|------|-------------|--------------------------|--------------------|-------------------------|------------|------------------|
| g03-a | Supported-TA paging attraction | `SupportedTAList` TAC = 7 | No TAC/PLMN/S-NSSAI vs provisioned inventory | Rogue gNB added to paging target set for victim TA | Likely / impl-dependent | `B.ng_setup_request(_cfg(cfg,tac=7))` |
| g03-b | Global RAN Node ID collision | `GlobalRANNodeID` gNB-ID = 0x00A1B2 (a legit gNB) | No unique authenticated ID binding | RAN-node table alias -> cross-gNB DoS / misdelivery | High impact, impl-dependent | `B.ng_setup_request(_cfg(cfg,gnb_id=0x00A1B2))` |
| g03-c | False / foreign PLMN | GlobalRANNodeID + SupportedTAList PLMN = 460/00 | No PLMN authorization | Cross-PLMN topology / admission confusion | Impl-dependent | `B.ng_setup_request(_cfg(cfg,mcc="460",mnc="00"))` |
| g03-d | Slice availability poisoning | SupportedTAList S-NSSAI = SST 2 / SD 0a0b0c | No S-NSSAI authorization per node | Poisoned slice capability map; false coverage | Impl-dependent | `B.ng_setup_request(_cfg(cfg,sst=2,sd="0a0b0c"))` |
| g03-e | Handover-target misrouting | `GlobalRANNodeID` gNB-ID = 0x00C3D4 (spoof target) | AMF routes handover by spoofed ID | HANDOVER REQUEST for a UE sent to attacker | Speculative to likely | `B.ng_setup_request(_cfg(cfg,gnb_id=0x00C3D4))` |
| g03-f | UE Retention Information desync | spoof gNB-ID 0x00A1B2 + `UERetentionInformation=ues-retained` (id 147) | Restart/retention not bound to authenticated gNB | Incorrect retain/clear of a legit gNB's UE contexts | Impl-dependent | `ng_setup_with_retention(_cfg(cfg,gnb_id=0x00A1B2))` *(new wrapper)* |
| g03-g | Fake-RAN resource exhaustion | inflated `SupportedTAList` (16 TAC items) | No max TA-list / rate limit; expensive validation | AMF CPU/mem/index growth; setup churn | Likely | `ng_setup_large_talist(cfg, n=16)` *(new wrapper)* |

## g04 — ERROR INDICATION (procedureCode 9, Class 2)

Vulnerable surface: AMF locates the UE by `AMF-UE-NGAP-ID` with no source-gNB
binding and (weakly) treats ERROR INDICATION as a release/abort trigger, so a
forged error releases or aborts a UE served by another gNB.

| case | description | distinguishing IE values | missing validation | impact / cross-boundary | confidence | builder + params |
|------|-------------|--------------------------|--------------------|-------------------------|------------|------------------|
| g04-a | Forged UE-associated error -> remote release | `AMF-UE-ID 12345` + `RAN-UE-ID 6789` + Cause(radioNetwork/unspecified) | No pair/association binding; release-on-error | AMF sends UE CONTEXT RELEASE to legit gNB; victim drops | Likely / impl-dependent | `B.error_indication(12345,6789)` |
| g04-b | Cross-UE release by AMF-UE-ID alone | `AMF-UE-ID 12345`, **no** RAN-UE-NGAP-ID | RAN-UE-ID not required/matched | Remote UE release without RAN-side id | Likely if unsafe lookup reused | `B.error_indication(12345,None)` |
| g04-c | Abort victim in-progress transaction | Cause = `protocol / message-not-compatible-with-receiver-state` | No procedure-state / offending-msg correlation | Victim's setup/modify/handover transaction fails | Impl-dependent | `B.error_indication(12345,6789,cause=("protocol","message-not-compatible-with-receiver-state"))` |
| g04-d | Non-UE-associated error flooding | **no** UE IDs; Cause(misc/unspecified) only | No per-association rate limit; expensive log path | AMF CPU/log/queue pressure -> shared degradation | Likely (resource) | `B.error_indication(None,None,cause=("misc","unspecified"))` |
| g04-e | Bogus / invalid IDs sweep | `AMF-UE-ID 0xFFFFFFFF` + `RAN-UE-ID 0xFFFFFFFF`, Cause(protocol/unspecified) | Weak negative-lookup / verbose logging | Lookup/log pressure; ID-existence oracle | Low to impl-dependent | `B.error_indication(4294967295,4294967295,cause=("protocol","unspecified"))` |

---

## New builders added in `cases_g01_g04.py`
- `ng_reset_full(cause)` — NGReset with `ResetType = ("nG-Interface","reset-all")` (g01-d).
- `ran_config_update_with_gnbid(cfg, *, gnb_id, tac, ran_node_name)` — RANConfigurationUpdate + `GlobalRANNodeID` IE 27 (g02-d).
- `ng_setup_with_retention(cfg)` — NGSetupRequest + `UERetentionInformation` IE 147 = ues-retained (g03-f).
- `ng_setup_large_talist(cfg, n)` — NGSetupRequest with an n-entry SupportedTAList (g03-g).

## Validation
```
python -c "from ngaptester.cases_g01_g04 import CASES,CFG; from ngaptester import ngap; [ngap.encode(c['build'](CFG)) for c in CASES]; print('ALL ENCODE OK', len(CASES))"
# ALL ENCODE OK 21   (all 21 cases also APER round-trip to the expected message type)
```
