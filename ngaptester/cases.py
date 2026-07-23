"""Unified attack-case registry.

Each NGAP message from the analysis (`ngap_scaffold/output/**/pXX|gXX_*_response.txt`)
has a "Candidate Attack Table" listing several CASES — one per distinct IE-value
combination. Those are catalogued in `docs/cases/cat_*.md` and realized as encoders
in the per-chunk modules `cases_p01_p04.py`, `cases_p05_p09.py`, … `cases_g09_g11.py`,
each exposing a `CASES` list of `{"id","msg","desc","build": lambda cfg -> pdu}`.

This module aggregates whatever chunk modules are present (missing/failed chunks are
skipped gracefully) into one `ALL_CASES` list, and lets you look up / encode / send a
case by id. Wire it into the menu or run from the CLI:

    python -m ngaptester.cases                 # list every case id
    python -m ngaptester.cases <case-id> ...   # encode named case(s), print bytes
"""
from __future__ import annotations

import importlib

from . import ngap

# per-chunk modules produced by the case-catalog pass; extend as more are added.
_CHUNKS = [
    "cases_p01_p04", "cases_p05_p09", "cases_p10_p14", "cases_p15_p18",
    "cases_p19_p22", "cases_g01_g04", "cases_g05_g08", "cases_g09_g11",
]

DEFAULT_CFG = {"mcc": "001", "mnc": "01", "tac": 1, "sst": 1, "sd": "010203",
               "gnb_id": 4660, "gnb_id_len": 32, "nci": 17}


def _load():
    cases = []
    loaded, missing = [], []
    for name in _CHUNKS:
        try:
            mod = importlib.import_module(f".{name}", __package__)
        except Exception as e:  # chunk not implemented yet / failed to import
            missing.append((name, repr(e)))
            continue
        for c in getattr(mod, "CASES", []):
            cases.append(c)
        loaded.append(name)
    return cases, loaded, missing


ALL_CASES, _LOADED, _MISSING = _load()
BY_ID = {c["id"]: c for c in ALL_CASES}


def build(case_id: str, cfg: dict | None = None):
    """Return the pycrate PDU value for a case id."""
    c = BY_ID[case_id]
    return c["build"](cfg or DEFAULT_CFG)


def encode(case_id: str, cfg: dict | None = None) -> bytes:
    return ngap.encode(build(case_id, cfg))


def summary() -> str:
    lines = [f"{len(ALL_CASES)} cases from {len(_LOADED)} chunk(s)"]
    if _MISSING:
        lines.append("missing chunks: " + ", ".join(n for n, _ in _MISSING))
    return "\n".join(lines)


def _main(argv):
    if not argv:
        print(summary())
        for c in ALL_CASES:
            print(f"  {c['id']:10s} {c.get('msg',''):32s} {c.get('desc','')}")
        return
    for cid in argv:
        try:
            b = encode(cid)
            print(f"[OK]  {cid:10s} {len(b):3d} bytes  {b.hex()[:48]}...")
        except KeyError:
            print(f"[ERR] {cid}: no such case id")
        except Exception as e:
            print(f"[ERR] {cid}: {type(e).__name__}: {e}")


if __name__ == "__main__":
    import sys
    _main(sys.argv[1:])
