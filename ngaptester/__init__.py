"""ngaptester — a minimal fake-gNB NGAP packet sender for 5GC security testing.

Not a gNB stack: it only does enough (SCTP + NG Setup) to be accepted as an
NG-RAN node, then sends controlled/crafted NGAP messages to exercise the
cross-gNB attacks confirmed by source review. For authorized lab use only.
"""
