# real-amf —— UERANSIM 合法 gNB+UE，连华为 AMF

现场参数已写入 `real-amf.env`（PLMN 460/08，AMF `14.66.2.5`，绑定 `13.254.241.142`）。
**完整操作见 `../操作手册_华为AMF.md`。黑盒抓包 + 按编号 1–16 一条一条做。**

```
测试机 Ubuntu
  UERANSIM nr-gnb  ──NGAP/SCTP──┐
  UERANSIM nr-ue   ──RLS(UDP)───┤
  ngap_tester      ──NGAP/SCTP──┤
                                ▼
                      华为 AMF 14.66.2.5:38412
```

```bash
./deploy/real-amf/run-gnb.sh    # 终端 A
./deploy/real-amf/run-ue.sh     # 终端 B
```

合法 gNB-ID=1；流氓 ngap_tester 的 gNB-ID=4660。华为 AMF-UE-NGAP-ID **每次随机**，不要 sweep。
