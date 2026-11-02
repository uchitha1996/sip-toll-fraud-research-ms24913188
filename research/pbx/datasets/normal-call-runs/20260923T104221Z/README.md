# Normal answered-call control — 2026-09-23

- PBX: Raspberry Pi Asterisk 20.6.0 at 172.16.200.81.
- User-triggered scenarios: NC01 1001→1002 and NC02 1002→1001; both were answered and hung up after a few seconds.
- Ground truth is recorded in `scenario_ground_truth.csv` from two new Asterisk CDR rows. Labels were assigned from the deliberate test procedure and ANSWERED CDRs, independently of detector predictions.
- `cdr_before.csv` and `cdr_after.csv` preserve the call-record boundary. NC01 billsec=8; NC02 billsec=5.
- `normal_calls.pcap` captures 50 UDP/5060 packets on `wlan0`, including SIP authentication details. Keep this PCAP restricted to the lab.
- `sip_packets_normal.csv` extracts 42 SIP packet rows with timestamps, method, status, source/destination, Call-ID and SIP users; it does not contain Authorization headers.
- The two answered calls have INVITE 200 OK, ACK and BYE traffic. A 401 challenge followed by successful authentication is normal SIP behaviour; the capture also has REGISTER 401 followed by REGISTER 200.
- A read-only check using the frozen V3 rules copied in `datasets/runs/20260923T094044Z/stage_detector_v3.py` classified all nine REGISTER/INVITE request events as NORMAL (no attack alert).
- These nine requests are correlated with only two normal calls. This small control set cannot establish a production false-positive rate.
- This normal-call evidence differs from the V3/V4 scripted bursts, whose requests all received 401 and did not become calls.
- PCAP SHA-256: f9ebf51d780fa0673658a69bd3a90a73edb6ec427611176030901e47a76c8c18.
