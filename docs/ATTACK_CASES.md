# Attack case catalog — one message, many cases

## Why cases

Each NGAP procedure (p01–p22 UE-associated, g01–g11 non-UE-associated) was analyzed by
the LLM pipeline; the output lives in
`ngap_scaffold/output/batch22_firstpriority/pXX_*_response.txt` and
`ngap_scaffold/output/batch11_secondpriority/gXX_*_response.txt`. **Section "## 4.
Candidate Attack Table" of each response enumerates several attack variants for that one
message** — e.g. Path Switch has ~6 (DL-redirect, blackhole, UE-context misbinding,
failed-list injection, control-plane churn, location poisoning).

The variants differ by **which IEs are set and to what values** (attacker IP vs a dead IP;
present vs absent Failed-to-Setup list; a forged UserLocationInformation; etc.). Per the
research goal: **if any IE value differs, it is a distinct case, and each case needs a
concrete encoder** so we can send exactly that variant and observe its effect.

## Model: builder + preset

Most cases are the *same message* with *different IE values*, so we don't need a separate
builder per case — we need:

1. **One encoder per message** (`ngaptester/builders.py`, extended by the per-chunk
   `cases_*.py` modules for messages not already there), parameterized over the
   attacker-controlled IEs.
2. **One preset per case** — a `{"id", "msg", "desc", "build": lambda cfg -> pdu}` entry
   that calls the message's builder with the case's specific IE values.

Layout:
- `docs/cases/cat_<chunk>.md` — the human catalog: every case row with its distinguishing
  IE values, the missing validation it exploits, impact, cross-boundary, confidence, and
  which builder+params realize it.
- `ngaptester/cases_<chunk>.py` — the code: any new builders for that chunk's messages + a
  `CASES` list of presets. Each `build(cfg)` returns a pycrate PDU that `ngap.encode()` accepts.
- `ngaptester/cases.py` — aggregates all present chunk modules into `ALL_CASES` + `BY_ID`,
  and encodes/sends a case by id. Missing/failed chunks are skipped gracefully.

Chunks: `cases_p01_p04`, `cases_p05_p09`, `cases_p10_p14`, `cases_p15_p18`, `cases_p19_p22`,
`cases_g01_g04`, `cases_g05_g08`, `cases_g09_g11`.

## Case-id scheme

`<msg><letter>` — the message tag from the input filename plus a per-case letter, e.g.
`p01-a` (Path Switch DL-redirect), `p01-b` (blackhole), `g01-b` (NG Reset AMF-UE-ID-only path).
Ids are stable so the catalog, the code, and captured evidence can cross-reference.

## Using cases

```bash
python -m ngaptester.cases                 # list every case id (msg + description)
python -m ngaptester.cases p01-a p01-b      # encode named cases, print byte lengths/hex (offline)
python validate_builders.py                 # round-trips the core builders (extend with cases if desired)
```

To fire a case live, the menu can gain a "run case by id" entry that does NG Setup then
`gnb.send(cases.build(id, gnb.cfg))`. Capture it with `capture_attack.sh` like any packet.

## Coverage vs. the 4-core results

The confirmed live cases (Path Switch, UE Release, Error Indication, NG Reset, Handover
Required, RAN Config Update, SON relay) map to the strongest catalog cases and already have
pcap evidence (`pcap/`, `RESULTS_*.md`). The remaining catalogued cases are the *untested*
variants — many are source-flagged but gated (need an in-progress handover, a registered
target gNB, or an idle victim). The catalog marks each case's confidence and precondition so
the next test pass can prioritize.

## Note on completeness

The per-chunk modules are produced by a parallel case-catalog pass; if a chunk is missing
from `ngaptester/cases.py`'s summary, its module wasn't generated (e.g. a subtask was
interrupted) — re-run that chunk. `cases.py` tolerates missing chunks so partial progress is
always usable.
