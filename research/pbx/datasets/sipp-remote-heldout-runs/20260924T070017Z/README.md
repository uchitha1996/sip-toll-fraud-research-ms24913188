# Protocol-aware SIP candidate: development and fresh validation

**Date:** 24 September 2026  
**Research question:** Can we count real password rejections and detect slower behaviour more faithfully than frozen V3?

## The rule in plain language

When a phone first contacts Asterisk, `401` can mean “please authenticate.” A failed password also produces `401`. The candidate matches replies to requests by SIP Call-ID **and CSeq number**. It ignores a first challenge, ignores a challenge marked *stale*, waits one second for a successful retry, then counts an unresolved rejection of a request carrying a digest username. It alerts after **ten counted rejections by one source within 60 seconds**. Other stage thresholds are inherited from V3. It is a deterministic offline candidate; it does not establish the full adaptive architecture or ML claim.

The candidate was frozen **before** the extension `1002` traffic was generated. Candidate SHA-256: `e23ffd00ef931c23b1e2a4e9b0fccb6731d57025f94dbdc3a9045a75de825004`. Frozen V3 SHA-256: `579cdc61a40d1a0c8e340fc24109bb7097ed3de60296d5e58bbbee5d437d5d6a`. The predetermined cases and rule are in `Candidate_V5_Method_20260924.md`.

## Results from saved development captures

| Captured scenario | Frozen V3 | Candidate V5 | What it shows |
| --- | --- | --- | --- |
| Two answered internal calls with a stale `401` and successful REGISTER retries | No alert | No alert; ignored stale challenge, saw two REGISTER 200 responses | Small real normal control; only two calls |
| Four distinct OPTIONS targets from separate Pi | No alert | No alert | Below scan threshold |
| Five distinct OPTIONS targets from separate Pi | Reconnaissance at 7.821911 s | Reconnaissance at 7.821911 s | Same scan rule |
| Ten fast wrong-password dialogs from separate Pi | Authentication at 1.391449 s (after five actual failures) | Authentication at 4.106329 s (after ten counted failures) | More accurate counting increases detection delay |
| Ten slow wrong-password dialogs from separate Pi | No alert | Authentication at 46.850273 s | Sixty-second window catches this selected slow sequence |

The older loopback authentication captures end too soon after the last response to observe a full one-second retry window. Candidate V5 leaves **3 of 10** fast and **1 of 10** slow attempted rejections unresolved there and raises no alert on those two archived PCAPs. Those negative replays are an observation-limit result, not evidence that the attempts were legitimate. Asterisk's separate logs recorded ten failures per attack run.

## Fresh cases reserved before generating traffic

Both tests ran from SIPp 3.7.3 on `172.16.200.68` to Asterisk on `172.16.200.81:5060`. The SIP identity was changed to extension `1002` before test generation. The runner, XML and candidate source hashes were recorded before replay. Each separate PCAP passed the source/destination, SIP 401 count, SIPp exit and Asterisk failure-log checks.

| Fresh labelled attack | Asterisk evidence | Frozen V3 | Frozen candidate V5 |
| --- | --- | --- | --- |
| Ten `1002` wrong-password dialogs, paced by separate SIPp starts | 20 REGISTER requests, 20 SIP 401 replies, **10** logged password failures | Alert at request 10, **7.160520 s**, after only five real failures | Alert after all ten confirmed failures, **19.926539 s** |
| Six `1002` wrong-password dialogs, fast | 12 REGISTER requests, 12 SIP 401 replies, **6** logged password failures | Alert at request 10, **1.356189 s**, after five real failures | **No alert**: six is below its threshold of ten |

**Both fresh cases produced zero new call records.** Asterisk stayed active and the ordinary `1002` phone contact remained listed. These packets demonstrate rejected logins, not successful account compromise, outbound calling or actual toll fraud. The new cases still share the same source IP, Wi-Fi network, Asterisk PBX and SIPp XML pattern as development traffic; changing user and pacing is a limited holdout, not independent real-world generalization.

The candidate's alert requires the tenth rejected password and an additional one-second observation. It may therefore be too late for a burst with fewer attempts. No evidence here measures whether either alert preceded a real fraudulent call.

## Normal-control attempt and practical next step

An 180-second passive capture of the connected softphone recorded 13 UDP packets but **zero decoded SIP messages**, so it was excluded from detector evaluation. No fresh successful normal REGISTERs were fabricated or counted. The earlier two answered calls are still the only observed real normal-call control.

Before changing thresholds, capture several **new successful normal registrations and answered calls** from actual softphones. Then test the 1-second retry rule and any additional fast-attack threshold on new traffic from different times and users. Report missed short attacks, alert delay, false alerts, CPU and memory. The selected cases here do not support a population precision, recall, F1 or false-alert rate.

## Evidence locations on the Asterisk Pi

- Development candidate timelines and summaries: `/home/astrix/sip-fraud-research/datasets/candidate-v5-runs/20260924_development/`.
- Fresh test PCAPs, independent labels, Asterisk logs, SIPp logs and frozen V3 results: `/home/astrix/sip-fraud-research/datasets/sipp-remote-heldout-runs/20260924T070017Z/`.
- Candidate replays on those exact fresh PCAPs: `/home/astrix/sip-fraud-research/datasets/candidate-v5-runs/20260924_heldout/`.
- Unused passive normal capture: `/home/astrix/sip-fraud-research/datasets/normal-registration-runs/20260924T065629Z/`.

Raw PCAPs and detailed call records stay on the Asterisk Pi with restricted access. Published candidate files contain code, method and aggregate findings, with no SIP Authorization values or passwords.
