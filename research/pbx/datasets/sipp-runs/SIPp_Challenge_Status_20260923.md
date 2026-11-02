# SIPp challenge audit — 23 September 2026

**Scope:** SIPp runs on the Raspberry Pi against Asterisk over 127.0.0.1:5060. This is a different generator from the Python baseline, but NOT a separate host or network source. Every scenario has a PCAP, extracted SIP CSV, independent one-row scenario label, SIPp console, and pre/post CDR.

| Scenario and evidence directory | Intentional traffic | Frozen V3 result |
| --- | --- | --- |
| `threshold-20260923T110540Z/options-4` | Four OPTIONS to four distinct targets; four SIP 401 responses | Missed reconnaissance: no alert |
| `threshold-20260923T110540Z/options-5` | Five OPTIONS to five distinct targets; five SIP 401 responses | Reconnaissance alert on fifth request; TTD 0.442467 s |
| `threshold-20260923T110646Z/auth-10` | Ten wrong-password REGISTER dialogs at ~3/s; 20 REGISTER requests and 20 SIP 401 responses | Authentication alert on tenth REGISTER request (fifth failed-password dialog); TTD 1.334717 s (401 decision time) |
| `slow-20260923T110803Z/auth-10-slow` | Ten wrong-password dialogs spaced ~3 s apart; 20 requests and 20 SIP 401 responses | Missed: no alert; at most eight REGISTER requests fit a 10 s window |

- Asterisk `/var/log/asterisk/full` independently recorded exactly ten **Failed to authenticate** entries for each authentication run. Extracts are saved beside each run as `asterisk_failed_auth_evidence.txt`.
- `sip_transactions.csv` separates the initial CSeq 1 challenge (401) from the wrong-password CSeq 2 rejection (401): ten of each per authentication run.
- The frozen V3 rule counts **both** 401 responses as failed authentication. It therefore reaches a threshold of ten after only five truly failed-password dialogs. A normal 401 challenge can later be followed by 200 OK, as verified in the earlier normal-call control. This is a method limitation to fix before final claims.
- All four challenge runs produced zero new CDRs. No successful calls, compromise, or toll fraud were generated.
- Excluded smoke attempts: `smoke-auth-20260923T110157Z` used a malformed Authorization header and timed out; `smoke-auth-fixed-20260923T110344Z` succeeded but its tcpdump file was empty due a capture-stop race. The corrected captured single-dialog run `smoke-auth-captured-20260923T110436Z` is evidence of scenario repair, not part of the four challenge outcomes.
- Every included run now has `replay_v3_timeline.csv` and `replay_v3_summary.json`, produced by `scripts/replay_v3_capture.py` using the exact frozen rule functions from `datasets/runs/20260923T094044Z/stage_detector_v3.py`. Each summary records the original PCAP hash, source-code hash, request counts, independent scenario label, first alert and CDR difference. The small selected cases are boundary evidence, not a population-wide accuracy estimate.

**Next:** collect additional varied authenticated normal traffic; implement protocol-aware differentiation of challenge versus failed digest and a longer behavioural window; evaluate the same frozen four cases plus independent held-out scenarios. A genuinely separate network host remains necessary for that deployment claim.
