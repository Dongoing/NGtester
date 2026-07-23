# (Ready-to-submit GitHub issue for open5gs/open5gs)

> Copy everything below the line into a new issue at
> https://github.com/open5gs/open5gs/issues/new . Suggested labels: `Type:Security`.
> Attach `evidence/crash-ngreset/ngreset.pcap` (generate with `python make_ngreset_pcap.py`).

---

**Title:** `[Bug]: AMF - remote crash (assertion \`gnb->ng_reset_ack\`) on a cross-gNB NG RESET (Part of NG Interface)`

## Open5GS Release, Revision, or Tag

v2.8.0

## Summary

A single, unauthenticated **NG RESET** (`ResetType = partOfNG-Interface`) that lists an
`AMF-UE-NGAP-ID` **belonging to a UE served by a *different* gNB** aborts the AMF with

```
FATAL: amf_nsmf_pdusession_handle_update_sm_context:
       Assertion `gnb->ng_reset_ack' failed. (../src/amf/nsmf-handler.c:928)
```

The whole `open5gs-amfd` process dies (`SIGABRT`), so this is a remote DoS affecting **every
UE on the AMF**, not just the referenced one. It only requires that the referenced UE has an
active PDU session (so the session release is asynchronous). No security context, no NAS, and
no ownership of the victim UE is needed — only an accepted NG association (i.e. an N2 link
without IPsec) and a small, enumerable `AMF-UE-NGAP-ID`.

## Steps to reproduce

1. Bring up the AMF with at least one UE registered **and with an active PDU session**
   through a legitimate gNB (call the UE's id `AMF-UE-NGAP-ID = V`; e.g. UERANSIM UE, `V=2`).
2. From a **second** gNB association (any NG-Setup-accepted peer — in the lab a small Python
   fake gNB over SCTP/PPID 60), send one NG RESET:
   - `Cause`: `misc / om-intervention`
   - `ResetType`: `partOfNG-Interface`, one item `{ AMF-UE-NGAP-ID = V, RAN-UE-NGAP-ID = 99 }`
   - Exact APER bytes (22): `00140012000002000f40018600580006400160020063`
     (this is `AMF-UE-NGAP-ID=2`; change the last IE to your `V`)
3. The AMF replies with `NGResetAcknowledge`, then aborts a few milliseconds later when the
   victim's SMF `UpdateSMContext` (session release) completes.

pcap attached (`ngreset.pcap`), dissects as `NGAP / NGReset / partOfNG-Interface`.

## Logs

```
07/10 ..: [amf] INFO: NGReset (../src/amf/ngap-handler.c:4867)
07/10 ..: [amf] INFO:     NGAP_ResetType_PR_partOfNG_Interface (../src/amf/ngap-handler.c:4952)
07/10 ..: [amf] INFO: [Removed] Number of gNBs is now 1 (../src/amf/context.c:1305)
07/10 ..: [amf] INFO: [Removed] Number of gNB-UEs is now 0 (../src/amf/context.c:2939)
07/10 ..: [amf] FATAL: amf_nsmf_pdusession_handle_update_sm_context:
                 Assertion `gnb->ng_reset_ack' failed. (../src/amf/nsmf-handler.c:928)
07/10 ..: [core] FATAL: backtrace() returned 8 addresses (../lib/core/ogs-abort.c:37)
    open5gs-amfd(+0xba8d)
    libogscore.so.2(ogs_fsm_dispatch+0x119)
    ...
/open5gs_init.sh: line 86: 8 Aborted   open5gs-amfd
```
Container/process exit status: `134` (128 + SIGABRT).

## Root cause (code flow)

The `partOfNG-Interface` reset loop resolves the referenced UE with an **unbound global
lookup** and never checks that the UE belongs to the gNB that sent the reset:

`src/amf/ngap-handler.c` (NG Reset handler):
```c
ran_ue = ran_ue_find_by_amf_ue_ngap_id(amf_ue_ngap_id);   // :5217  (no gnb_id binding)
...
ran_ue->part_of_ng_reset_requested = true;                // :5243
...
amf_sbi_send_deactivate_all_sessions(
    ran_ue, amf_ue, AMF_REMOVE_S1_CONTEXT_BY_RESET_PARTIAL, ...);   // :5258 (async if a PDU session is active)
...
gnb->ng_reset_ack = ogs_ngap_build_ng_reset_ack(partOfNG_Interface);   // :5181 — stored on the SENDER gNB
```

When the referenced UE has an active PDU session, the release is asynchronous, so its `ran_ue`
survives the handler; the SENDER's `ng_reset_ack` is sent and cleared normally. Later the
session-release completion runs:

`src/amf/nsmf-handler.c`, `amf_nsmf_pdusession_handle_update_sm_context()`,
state `AMF_REMOVE_S1_CONTEXT_BY_RESET_PARTIAL`:
```c
gnb = amf_gnb_find_by_id(ran_ue->gnb_id);   // :911 — the VICTIM's OWNING gNB, not the sender
...
ran_ue_remove(ran_ue);                       // :915
if (gnb) {
    ogs_list_for_each(&gnb->ran_ue_list, iter) { if (iter->part_of_ng_reset_requested) return OGS_OK; }
    ogs_assert(gnb->ng_reset_ack);           // :928/930  <-- ABORTS
    ...
}
```

`gnb` here is resolved from the **victim's** `ran_ue->gnb_id`, i.e. the legitimate owning gNB —
which never sent an NG Reset, so its `ng_reset_ack` is `NULL` and the assertion fires. In the
normal (non-cross-gNB) case sender == owner, so the field is set and the bug is masked. The
missing `ran_ue->gnb_id != gnb->id` check at `:5217` is what lets sender ≠ owner and drives the
completion path onto the wrong gNB.

## Expected behaviour

An NG Reset from gNB A that references a UE owned by gNB B should be rejected/ignored for that
UE (per the ownership binding already enforced elsewhere, e.g. the `ran_ue->gnb_id != gnb->id`
check used by `UEContextReleaseRequest`), and in no case should it be able to abort the AMF.

## Observed behaviour

The AMF processes the cross-gNB reset, tears down the remote UE's session, and then aborts on
the `ogs_assert(gnb->ng_reset_ack)` in the async release path — crashing the whole AMF.

## Suggested fix

1. **Bind the reset to the sender** in the `partOfNG-Interface` loop — after
   `ran_ue_find_by_amf_ue_ngap_id()` (`ngap-handler.c:5217`), skip entries where
   `ran_ue->gnb_id != gnb->id` (mirroring the inlined check in
   `ngap_handle_ue_context_release_request`). This fixes both the crash and the cross-gNB
   teardown.
2. **Defensive**: in `nsmf-handler.c` (`:928/930`), guard the send instead of asserting —
   `if (gnb->ng_reset_ack) { ngap_send_to_gnb(...); gnb->ng_reset_ack = NULL; }` — so a NULL
   ack buffer can never abort the process.

## Environment / notes

- Reproduced on Open5GS **v2.8.0** (Docker) + UERANSIM, in an isolated lab, as part of
  authorized defensive research into NGAP robustness under a rogue-gNB (no-N2-IPsec) model.
- N2 IPsec prevents the injection entirely; this report is about AMF **robustness** — a single
  malformed/hostile NGAP message should never `abort()` the AMF regardless of the transport
  assumption.
- Related hardening already present at `ngap-handler.c` (`ran_ue->gnb_id != gnb->id`, the
  central `ngap_find_ran_ue_by_message_ue_ids()` guard) is simply not applied on this path.
