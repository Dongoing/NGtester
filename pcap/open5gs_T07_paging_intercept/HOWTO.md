# Open5GS — False-TAI RAN Config Update → Paging intercept (T07)

Git Bash / PowerShell from `ngap_tester/`. See [`../README.md`](../README.md).

**Attack chain**
1. Rogue gNB: `RAN CONFIGURATION UPDATE` claims victim TAC → AMF ACK (no coverage check).
2. Rogue (other assoc): `ERROR INDICATION` → AMF local-releases victim → **CM-IDLE**, still **GMM-REGISTERED**.
3. MT downlink (UPF ping UE IP) → AMF pages by TAI fan-out.
4. Rogue intercepts `PAGING` carrying **5G-S-TMSI**.

**Expect in `amf_ngap_nas_sbi.pcap`**
| procCode | meaning |
|---|---|
| 21 | NG Setup (legit + rogue) |
| 35 | RAN Configuration Update / Acknowledge |
| 9 | Error Indication |
| **24** | **Paging** — same 5G-S-TMSI to **legit gNB and rogue** |

Verify fan-out (two distinct `ip.dst` for proc 24):
```bash
docker run --rm -v "$PWD/pcap/open5gs_T07_paging_intercept:/cap" nicolaka/netshoot \
  tshark -r /cap/amf_ngap_nas_sbi.pcap -Y 'ngap.procedureCode==24' \
  -T fields -e frame.number -e ip.dst
```

**Captured artifacts**
- `amf_ngap_nas_sbi.pcap` — N2 + SBI
- `smf_sbi_pfcp.pcap` — SBI + PFCP
- `legit_gnb_n2_n3.pcap` — victim gNB also receives Paging (24)
- `upf_n3_n6.pcap` — MT ICMP trigger
- `attack.jsonl` / `attacker_stdout.txt` — intercepted 5G-S-TMSI
