# SIPp tests from a separate Raspberry Pi — 24 September 2026

## What changed

The SIPp generator was moved to its own Raspberry Pi (`Sipp-generator`, `172.16.200.68`). It sent UDP SIP traffic across the Wi-Fi LAN to Asterisk 20.6.0 on `Astrix-lab` (`172.16.200.81:5060`). The earlier Raspberry Pi SIPp tests used loopback on one host; this session is a genuine second-source-host test. SIPp 3.7.3 and its dependencies run from the generator user's home directory, without a system-wide package installation.

One initial OPTIONS smoke request was captured at the Asterisk Pi: source `172.16.200.68`, destination `172.16.200.81`, followed by a SIP 401 reply in the opposite direction. This smoke test is separate from the four labelled cases below.

## Frozen V3 results on the network captures

| Labelled test | Captured Asterisk exchange | First V3 alert | New call records |
| --- | --- | --- | ---: |
| Four distinct OPTIONS targets (scan) | 4 requests, 4 SIP 401 replies | None: below the five-target threshold | 0 |
| Five distinct OPTIONS targets (scan) | 5 requests, 5 SIP 401 replies | RECONNAISSANCE on request 5, 7.821911 s from first request | 0 |
| Ten fast wrong-password REGISTER dialogs | 20 requests, 20 SIP 401 replies | AUTHENTICATION_ATTACK on request 10, 1.391449 s from first request | 0 |
| Ten slow wrong-password REGISTER dialogs | 20 requests, 20 SIP 401 replies | None | 0 |

Each run has an independent scenario label, a separate nonempty PCAP, extracted SIP fields, a copy of its SIPp XML, SIPp exit codes, Asterisk call-record snapshots, packet-count verification, and a replay timeline/summary from the **archived frozen V3** detector. All four captures passed checks for expected source and destination IPs, packet counts, replies and SIPp exit codes. Asterisk independently logged **10 failed authentications** in each REGISTER run.

For both authentication runs, packet inspection found ten initial REGISTER requests with CSeq 1 and no digest username, then ten CSeq 2 REGISTER requests with digest username `1001`. Asterisk returned 401 to both requests in each dialog. V3 counts both 401s as failures: its fast-run alert after request 10 represents only **five actual wrong-password rejections**. The slow run was missed by the 10-second window despite ten wrong passwords overall.

The 7.82-second OPTIONS detection time includes starting SIPp separately for each target. Its difference from the earlier 0.44-second same-host test should **not** be interpreted as network latency. None of the selected cases produced an answered call, account compromise or outbound toll fraud. Four chosen cases are boundary checks, not an overall precision, recall or false-alert estimate.

## Evidence and reproducibility

- Asterisk Pi session folder: `/home/astrix/sip-fraud-research/datasets/sipp-remote-runs/20260924T062325Z/`.
- Four case directories: `options-4`, `options-5`, `auth-10-fast`, and `auth-10-slow`. The one-request smoke is in `smoke-options-1`.
- Each `capture_verification.json` stores the PCAP SHA-256 and counts; `replay_v3_summary.json` stores the PCAP, extracted CSV and frozen detector hashes and the first alert.
- Runner: `/home/astrix/sip-fraud-research/scripts/run_remote_sipp_challenges.py`. Replay: `/home/astrix/sip-fraud-research/scripts/replay_v3_capture.py`. Frozen detector: `/home/astrix/sip-fraud-research/datasets/runs/20260923T094044Z/stage_detector_v3.py`.
- The generator received XML files with SHA-256 values matching the Asterisk Pi originals. The raw PCAPs and call records remain restricted on the Asterisk Pi because SIP authentication and call details may be present.

## Next research step

Keep V3 fixed as the comparison baseline. Build a candidate rule that treats the first 401 as a normal digest challenge and counts a failed password only after a rejected authenticated REGISTER. Test a longer window on the archived slow capture and fresh, varied successful normal registrations and calls. Then compare the candidate against V3 on new held-out cases from the separate generator, recording detection time, false alerts, CPU and memory. A controlled, authorized successful outbound-call scenario is still needed before claiming detection of actual toll fraud.
