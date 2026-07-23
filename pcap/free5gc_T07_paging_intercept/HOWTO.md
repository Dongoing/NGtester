# free5GC — False-TAI RAN Config Update → Paging intercept (T07)

## Why this was harder than Open5GS

1. **Cross-gNB Error Indication does not idle the UE** (bound to sending RAN).
2. Idle path needs **Path Switch → UEContextReleaseRequest(+PDU list) → ReleaseCommand → Complete**.
   Earlier runs exited before Complete → Buff/NOCP / N2 detach incomplete.
3. Lab **eUPF (`edgecomllc/eupf`) has no Downlink Data Notification** (GitHub #139/#140),
   so UPF→SMF→AMF paging on MT data never fires. Trigger paging with
   `Namf_Communication N1N2MessageTransfer` once UE is CM-IDLE (returns
   `ATTEMPTING_TO_REACH_UE`). Lab NRF `oauth: false` so curl can call AMF without token.

## Attack chain (captured)

1. Rogue A: `RAN CONFIGURATION UPDATE` TAC=1 → Acknowledge (false TAI).
2. Rogue B: `chain-ps-release` (Path Switch ACK + Release Request w/ PDU sess 1 + Complete).
3. N1N2MessageTransfer for `imsi-001010000000001` → AMF **Send Paging to TAI**.
4. Rogue A intercepts **PAGING / 5G-S-TMSI** (fan-out also hits legit gNB).

## Expect in `amf_ngap_nas_sbi.pcap`

| procCode | meaning |
|---|---|
| 21 | NG Setup |
| 35 | RAN Configuration Update / Ack |
| 25 | Path Switch Request / Ack |
| 42 / 41 | UE Context Release Request / Command+Complete |
| **24** | **Paging** to legit `172.30.200.0` **and** rogue claimer `172.30.200.2` |

```bash
docker run --rm -v "$PWD/pcap/free5gc_T07_paging_intercept:/cap" nicolaka/netshoot \
  tshark -r /cap/amf_ngap_nas_sbi.pcap -Y 'ngap.procedureCode==24' \
  -T fields -e frame.number -e ip.dst
```

Evidence: `attack.jsonl` / `attacker_stdout.txt` (4× `5G-S-TMSI=03f8:00:00000001`);
`chain.jsonl` / `chain_stdout.txt` = idle handshake (Path Switch → Release Complete).
