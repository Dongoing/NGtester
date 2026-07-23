# Distinct attack primitives (deduplicated)

The per-message "Candidate Attack Table" rows were collapsed to **distinct attack
effects**. Removed (per "same effect ⇒ not a separate case"):
- **scale / enumeration / churn / exhaustion** rows — same packet sent repeatedly (a
  *mode* of a primitive, not a new packet);
- **cosmetic** rows — differ only by a Cause / non-behavioural IE;
- **negatives** — dropped entirely: NAS-integrity-bound (p07 UplinkNASTransport, p08
  NASNonDeliveryIndication — a rogue gNB can't forge an accepted NAS-PDU), reverse-
  direction AMF→gNB procedures (p10 HandoverSuccess, p20 ConnectionEstablishmentInd,
  g05 OverloadStart, g06 OverloadStop), and 5G-S-TMSI-keyed messages where the
  AMF-UE-NGAP-ID confused-deputy flaw is structurally unreachable (p18 UEInformationTransfer).

Result: **110 presets → 39 distinct primitives** across 24 messages (`python -m ngaptester.cases`).
Grouped by effect class:

| effect class | primitives (case-id : message) |
|---|---|
| **N3 user-plane hijack** (intercept / blackhole) | `p01-a` PathSwitch redirect · `p01-b` PathSwitch blackhole · `p05-a` ModifyInd redirect · `p05-b` ModifyInd blackhole |
| **Cross-gNB UE release / teardown** | `p02-a` UEContextRelease · `p02-b` UECtxtRel selective-PDU · `g04-a` ErrorIndication release · `g01-a` NGReset partial teardown |
| **Remote AMF crash (DoS)** | `g01-b` NGReset AMF-UE-ID-only → Open5GS SIGABRT |
| **Full NG-interface reset** | `g01-d` NGReset ResetAll |
| **UE-context serving-node rebind** | `p01-c` PathSwitch misbinding · `p09-a` HandoverNotify rebind |
| **Forced relocation / handover manipulation** | `p03-a` HandoverRequired forced-HO · `p03-b` HO-state lock · `p03-d` attacker-target redirect · `p04-a` HandoverCancel · `p19-a` RANCPRelocationInd |
| **PDCP-status poisoning** (handover-gated) | `p21-a` UplinkRANStatusTransfer · `p22-a` UplinkRANEarlyStatusTransfer |
| **PDU-session / QoS disruption** | `p01-d` PathSwitch failed-list · `p05-e` ModifyInd QoS-desync · `p06-a` PDUSessResNotify false-notify |
| **State / metadata poisoning** | `p01-f` & `p05-f` location(ULI) · `p11-a` RRCInactive reachability · `p12-a` UERadioCap poison · `p13-a` SecondaryRAT charging · `p14-a` LocationReport spoof · `p15-a` LocReportFailure sabotage |
| **False-TAI → paging interception** | `g02-a` RANConfigUpdate · `g03-a` NGSetup |
| **Global RAN Node ID collision** (identity hijack) | `g03-b` NGSetup |
| **Blind relay injection** (confused deputy) | `g09-a` SON/Xn · `g10-a` non-UE NRPPa · `g11-a` RIM · `p16-a` UE-assoc NRPPa · `p17-a` CellTrafficTrace redirect |
| **PWS / warning-system corruption** | `g07-a` PWSRestartInd · `g08-a` PWSFailureInd |

**39 primitives / 13 effect classes.** Confidence + preconditions are in each
`cat_<chunk>.md`. The strongest (live-confirmed with pcap evidence in `../../pcap/`):
N3 hijack (Path Switch), cross-gNB release (UE Release / Error Indication), the NG-Reset
AMF crash, forced relocation, false-TAI paging, and blind SON relay. The rest are
source-flagged but untested and often gated (in-progress handover, registered target gNB,
idle victim) — marked accordingly.

> The full 110-row enumeration (including scale/cosmetic/negative variants) is preserved in
> git history / the per-chunk `cat_*.md` narrative; only the deduped presets remain in code.
