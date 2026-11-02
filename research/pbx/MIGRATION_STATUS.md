# SIP Fraud Research - Raspberry Pi Migration Status

Last updated: 2026-09-23

## Current platform
- Host: Astrix-lab
- OS: Debian 13 / Raspberry Pi OS 64-bit
- Architecture: aarch64
- PBX: Asterisk 20.6.0
- PBX IP: 172.16.200.81
- SIP transport: UDP/5060
- Extensions: 1001 and 1002
- CDR: /var/log/asterisk/cdr-csv/Master.csv

## Verified current state
- Asterisk service is running.
- 1001 -> 1002 test call succeeded.
- 1002 -> 1001 test call succeeded.
- CDR CSV is recording answered calls.
- Raspberry Pi Connect is available.
- Remote Desktop Commander device is online.

## Azure baseline being reproduced
- Azure PBX was 10.0.0.4, Ubuntu 24.04, Asterisk 20.6.0.
- SIPp generator was 10.0.0.6.
- Azure projects: ~/sip-fraud-detector and ~/sip-fraud-research.

- Azure detector used /var/log/asterisk/full plus CDR.
- Stage dataset fields: source_ip, first_seen, last_seen, OPTIONS, INVITE, REGISTER, unique targets, no-endpoint, failed-auth, stage, risk, reason.
- Rules included repeated REGISTER/auth failures, OPTIONS/unknown-endpoint reconnaissance, and INVITE/fraud-burst detection.
- V3 evaluation used a 10-second window and produced precision, recall, F1, false-positive rate and time-to-detect.

## Current migration stage
1. Research directory and detector scripts - DONE for V3/V4.
2. Asterisk full logging and CDR - ENABLED.
3. tcpdump, tshark, and SIPp - INSTALLED (baseline uses Python, not SIPp).
4. V3 controlled pipeline - 11 Pi runs preserved and audited.
5. V4 challenge experiment - preserved; scenario summary corrected separately.
6. Next - varied independent scenarios, real authorised calls, CDR integration, and adaptive evaluation.

## 2026-09-23 migration validation results

### V3 baseline replication on Raspberry Pi
- Run: datasets/runs/20260923T075916Z
- Ground-truth events: 50 (51 CSV lines including header)
- SIP packet CSV: 100 packet rows (101 lines including header)
- Binary precision: 1.0000
- Binary recall: 0.7111
- Binary F1: 0.8312
- False-positive rate: 0.0000
- Reconnaissance TTD: 1.603398 s
- Authentication-attack TTD: 2.256960 s
- Fraud-burst TTD: 0.723106 s
- Event-level confusion matrix/metrics match the previous Azure V3 baseline.

### V4 robustness replication on Raspberry Pi
- Run: datasets/robustness-runs/20260923T080910Z
- Ground-truth events: 68 (69 CSV lines including header)
- SIP packet CSV: 136 packet rows (137 lines including header)
- Binary precision: 1.0000
- Binary recall: 0.0577
- Binary F1: 0.1091
- False-positive rate: 0.0000
- Threshold-reaching TTD: recon 1.603098 s; auth 2.256846 s; fraud 0.803202 s
- V4 event-level metrics match the previous Azure robustness baseline.

## Tooling restored
- tcpdump installed and usable without sudo through capabilities.
- tshark installed.
- SIPp built from source at /home/astrix/sipp/build/sipp with TLS/PCAP support.
- SIPp lab scenarios recreated under /home/astrix/sipp-lab.
- /var/log/asterisk/full enabled and readable.
- CDR extractor and SIP-log parser recreated.

## Asterisk CLI access
The socket permission issue was fixed; non-sudo Asterisk CLI access is verified.

## 2026-09-23 11-run Raspberry Pi validation
- Asterisk CLI permission fix verified: /var/run/asterisk/asterisk.ctl = root:astrix 0660.
- Direct non-sudo Asterisk CLI access now works from Remote Desktop Commander.
- Total V3 validation runs on Raspberry Pi: 11.
- All 11 runs produced identical binary metrics:
  - precision = 1.0000
  - recall = 0.7111
  - F1 = 0.8312
  - false-positive rate = 0.0000
- Aggregate Raspberry Pi TTD:
  - RECONNAISSANCE mean 1.603013 s, median 1.603028 s, min 1.602694 s, max 1.603469 s, stdev 0.000258 s
  - AUTHENTICATION_ATTACK mean 2.256883 s, median 2.256960 s, min 2.255990 s, max 2.257431 s, stdev 0.000446 s
  - FRAUD_BURST mean 0.722849 s, median 0.722895 s, min 0.722517 s, max 0.723190 s, stdev 0.000207 s
- Previous Azure 11-run aggregate used mean TTD approximately:
  - RECONNAISSANCE 1.8647 s
  - AUTHENTICATION_ATTACK 2.2866 s
  - FRAUD_BURST 0.8244 s
- Raspberry Pi migration is functionally validated for the V3 detector pipeline and produces the same event-level metrics, with slightly lower TTD in this controlled local-loopback setup.


## 2026-09-23 evidence audit and interpretation
- All 11 V3 runs have distinct ground-truth CSV, packet CSV, PCAP, and timeline content; each has 50 labelled SIP requests, 50 responses, and 50 event predictions.
- All captured V3 requests, including the 20 external-destination INVITEs, received SIP 401. The V4 run also has 401 responses for every request. These are controlled unauthenticated SIP probes; no successful compromise, outbound call, or billed toll fraud is demonstrated.
- The V3 Python generator sent loopback UDP to real Asterisk and did not use SIPp. Its delays are fixed (0.90/0.40/0.25/0.18 seconds by scenario), so the same event-level confusion counts in every run are expected. The small time-to-detect differences reflect runtime jitter, not varied attack rates.
- Binary V3 confusion per run: TP=32, FP=0, FN=13, TN=5. The zero false-positive rate applies to only five labelled baseline controls per run; these are unauthenticated REGISTERs, not successful normal registrations.
- V4 defines 12 scenarios and 68 events. The original Pi scenario summary merged adjacent identical attack labels and listed only 10 scenarios. The original output is preserved. The corrected source, timeline, and 12-row summary are saved under datasets/robustness-runs/20260923T080910Z with filenames ending _corrected.
- Corrected V4 scenario outcomes: 3 of 8 labelled attack scenarios detected (IDs 4, 8, 12); 4 of 4 labelled normal/control scenarios had no attack alert. The event-level binary metrics are unchanged (precision 1.0000, recall 0.0577, F1 0.1091, FPR 0). Controls also received 401 responses and are limited evidence of benign real-world traffic.
- Thesis wording should distinguish prior Azure results from these Pi runs, and describe the present FRAUD_BURST label as an external-INVITE probe, not confirmed successful fraud.

## Next experiment
Design separately identified normal authenticated calls and controlled attack scenarios, vary rates and entities, capture independent labels/PCAP/CDR per scenario, then compare the frozen V3/V4 rules against a refined detector on unseen runs.


## 2026-09-23 successful normal-call control
- Both 1001 and 1002 were registered before capture. The user placed 1001→1002 and 1002→1001; both calls were answered.
- Evidence: datasets/normal-call-runs/20260923T104221Z/ (README, scenario ground truth, pre/post CDR, raw PCAP, extracted SIP CSV).
- The two new ANSWERED CDRs recorded 8 s and 5 s billsec; the capture has INVITE 200 OK, ACK and BYE for both calls.
- The run collected 50 UDP packets and 42 decoded SIP packets. A normal REGISTER challenge (401) was followed by successful 200 OK responses.
- The archived frozen V3 rules classified nine REGISTER/INVITE request events from these two calls as NORMAL, with zero attack alerts. The nine requests are correlated; this is a two-call control, not a production false-positive-rate estimate.
- Next: more varied benign scenarios and a separate network-source SIPp challenge with labelled scenarios; keep original baseline and normal-control evidence unchanged.


## 2026-09-23 SIPp boundary and slow-attack challenge
- Full audit: datasets/sipp-runs/SIPp_Challenge_Status_20260923.md. The four archived runs each contain raw PCAP, scenario label, source XML, extracted packets, CDR snapshots, and replay_v3_timeline.csv / replay_v3_summary.json.
- SIPp was run on this Pi over loopback, not from another LAN machine. OPTIONS at 4 targets: no V3 alert; 5 targets: RECONNAISSANCE at fifth request, TTD 0.442467 s.
- Ten wrong-password dialogs at ~3/s: AUTHENTICATION_ATTACK at the tenth REGISTER request, TTD 1.334717 s. Ten dialogs spaced ~3 s apart: no alert. Asterisk logged 10 failed-auth entries per auth scenario. No new CDRs in any scenario.
- V3 incorrectly counts the initial 401 authentication challenge and final 401 wrong-password rejection as two failures per dialog; the fifth actual wrong password reaches its nominal 10-failure threshold.
- The existing normal-call capture demonstrates that a benign 401 can later be followed by 200 OK. Next work is protocol-aware failure counting, longer-window comparison, and a genuine separate-host SIPp test.


## 2026-09-24 genuine separate-host SIPp validation
- Full evidence and limits: `datasets/sipp-remote-runs/20260924T062325Z/README.md`. The generator (`172.16.200.68`, SIPp 3.7.3) sent real LAN traffic to Asterisk (`172.16.200.81:5060`); a one-OPTIONS smoke capture confirmed both source and return IPs.
- Four new independent labelled captures: 4 OPTIONS targets -> no alert; 5 targets -> RECONNAISSANCE on fifth request, 7.821911 s; ten fast wrong-password dialogs -> AUTHENTICATION_ATTACK on tenth REGISTER request, 1.391449 s; ten slow dialogs -> no alert.
- For both authentication runs, the captures contain 10 initial CSeq 1 challenges plus 10 CSeq 2 authenticated requests; Asterisk logged 10 real failed authentications each. V3 counts both 401s, so the fast alert follows five real password failures. All four runs created zero CDRs.
- Frozen V3 was replayed without modification; each case preserves its source XML, raw PCAP, selected SIP fields, scenario label, SIPp exit codes, packet verification, and replay timeline and summary. Selected cases are boundary checks, not broad precision/recall or confirmed fraud.
- Next: develop protocol-aware counting plus longer-window candidate, increase successful normal-call controls, and compare on fresh held-out separate-host traffic. Do not compare 7.82 s and the loopback 0.44 s as network latency because the OPTIONS pacing differed.


## 2026-09-24 protocol-aware V5 development and limited holdout
- Full comparison: `datasets/sipp-remote-heldout-runs/20260924T070017Z/README.md`. Predetermined rule and source hash: `datasets/candidate-v5-runs/Candidate_V5_Method_20260924.md`. Candidate source SHA-256 `e23ffd00ef931c23b1e2a4e9b0fccb6731d57025f94dbdc3a9045a75de825004`; frozen V3 unchanged.
- Rule: match REGISTER reply using Call-ID+CSeq+method+addresses; ignore initial unauthenticated and stale 401; count a rejected digest after a one-second retry grace; alert on ten counted rejections by one source within 60 seconds.
- Development: two answered normal calls had no V5 alert; network ten-fast V3 1.391449 s vs candidate 4.106329 s; network ten-slow V3 missed vs candidate 46.850273 s. Old loopback captures ended too soon for full one-second retry observation, leaving some rejections unresolved.
- Reserved fresh cases used wrong password for extension 1002 from generator 172.16.200.68. Ten paced dialogs: 10 Asterisk auth-log failures, V3 7.160520 s, candidate 19.926539 s. Six fast dialogs: 6 logged failures, V3 1.356189 s, candidate no alert due fixed ten-rejection threshold. Both captured valid 401 replies and zero CDRs.
- Passive phone capture `datasets/normal-registration-runs/20260924T065629Z/` had 13 UDP packets but zero decoded SIP, and is excluded. Real normal registration controls and successful toll-call progression remain to be collected; no population accuracy or production false-alert claim follows from these selected cases.

## 2026-09-30 registered F01-F12 evaluation checkpoint
- A registered 12-scenario set is now complete: 6 benign/control and 6 attack scenarios.
- Fresh real-phone negatives: F01, F02, F06. All produced answered CDR evidence and no V3/V5/V6 alert.
- Scripted benign controls include F03 same-target OPTIONS, F04 authorized emulated call, and F05 credential-recovery-plus-call.
- Attack cases include F07/F08 reconnaissance, F09/F10 authentication-only (including slow), and F11/F12 simulated credential-abuse progression with isolated LAN calls.
- Canonical aggregation: datasets/f-series-evaluation/20260930T094922Z/.
- Scenario-level binary results on this small registered lab set:
  - V3: TP=4 FP=2 TN=4 FN=2; precision/recall/F1=0.667; FPR=0.333.
  - V5: TP=5 FP=1 TN=5 FN=1; precision/recall/F1=0.833; FPR=0.167.
  - V6: TP=6 FP=1 TN=5 FN=0; precision=0.857, recall=1.000, F1=0.923, FPR=0.167.
- V6 expected-stage outcome was correct in 11/12 scenarios.
- The remaining V6 challenge is F05: six confirmed rejections followed by a valid registration and authorized call is observationally similar to F11 and is intentionally retained as a false-alert challenge.
- F03 demonstrates why target diversity matters: V3/V5 alert on repeated benign OPTIONS to one target, while V6 does not.
- These 12 scenarios are controlled lab evidence, not a production/population accuracy claim.
- A leakage-conscious feature schema is now generated at datasets/f-series-evaluation/feature-schema/f_series_features.csv.
- V3/V5/V6 predictions are excluded from ML input features; current features use SIP timing/counts, target diversity, transaction-confirmed rejections, REGISTER success, and CDR evidence.
- Do not train/finalize ML on only 12 rows.
- Next research phase: generate a larger varied development set, train lightweight interpretable models, freeze preprocessing/model, then collect a fresh held-out set for final rule-only vs rule+ML evaluation.

## 2026-09-30 matched-stimulus ambiguity audit
- Evidence: /home/astrix/sip-fraud-research/datasets/ambiguity-development/20260930T101524Z
- Two fresh matched F05/F11 development runs independently passed SIP/log/CDR verification and cleanup.
- Both had 6 failures, REGISTER success and answered isolated call; V6 emitted the same three progression stages.
- Do not infer malicious intent from timing differences or promise ML resolves identical observations. Excluded from final held-out evaluation.
- Next: varied overlapping development scenarios, causal feature availability, grouped splits, frozen model and fresh holdout.

## 2026-09-30 varied lab development and frozen ML holdout
- New evidence is isolated under `datasets/ml-lab-20260930/`; the earlier F01-F12 and matched runs were not changed. Predeclared manifest SHA-256: `3377f6ce41df2a224db214d7d56498b51355592312210c80f8cb58a0dedcc915`.
- 24 development and 10 fresh held-out scenarios used only generator 172.16.200.68, PBX 172.16.200.81, accounts 1001/1002, and temporary 88001/88002 routes to the SIPp UAS. All 34 passed PCAP, failed-auth log, REGISTER, SIP leg, CDR, hash and cleanup checks. See `evidence_index.json` and per-run `independent_verification.json`.
- Assigned benign and simulated-abuse intent overlap by design. H003/H007 are matched seven-failure answered-call cases; H004/H008 are matched seven-failure registration-only cases. Each pair has the same V6 stages and ML decision despite opposite assigned intent.
- Model was frozen before the first H run at 2026-09-30T10:59:39Z. `freeze.json` SHA-256 `dceed239a6316d5c76eb4153eb0e82925755cc91fdb82173eb0ff4cc3c173268`; selected depth-two tree SHA-256 `092e7b025e871ff111e135d139747d62187de8e1655edaad250b3f1ab9e0cad4`. Grouped development balanced accuracy: tree 0.625, logistic 0.5417.
- Frozen tree heldout intent: TP=1 FP=0 TN=5 FN=4 (6/10 correct; balanced accuracy 0.60); six cases fall into its predeclared 0.4-0.6 review band. V6 any-stage: TP=3 FP=2 TN=3 FN=2 (6/10); V6 answered-stage: TP=2 FP=1 TN=4 FN=3 (6/10). Endpoint meanings differ; the tree is retrospective because it uses CDR.
- No measured improvement in intent classification is established. One PBX, one generator, two accounts and crafted label balances preclude population claims. Similar SIP/CDR evidence cannot establish who was authorized.
- Final check: zero active calls, both temporary routes absent, temporary credential XML cleaned. Next: obtain independently measured authorization and destination history, vary devices/networks/days, and predeclare a larger prospective holdout before another model change.

## 2026-10-01 archived event-time progression audit
- Read-only audit on the 24 development and 10 previously inspected held-out ML runs; no new calls or route changes.
- New separate scripts: `scripts/stream_progression_prototype.py`, `scripts/adapt_checkpoint_events.py`, `scripts/audit_online_replay.py`; frozen V5/V6 sources remain at checkpoint hashes.
- Evidence: `datasets/online-prototype-audit-20261001/` (protocol, 34 per-run event/alert/summary files, aggregate summary). Summary SHA-256 `b0fe8589fd2feb2a1e26f21964a6f0325fa83371107d30a3bb827e3a2aa6cfc7`.
- All 34 archived runs matched V6 ordered stages; 253 adapted events and 37 alerts. These H cases were inspected before the new prototype and are development regression evidence, not new held-out accuracy.
- Median read-only adapter+engine processing was 3.0748 ms/development run and 3.3216 ms/inspected H run; not live detection latency or PBX overhead.
- Preflight/postflight had zero active calls and absent exact temporary routes 88001/88002.
- Next: prospective multi-call benign/abuse bursts, live external and genuine in-process PBX paths, event-to-alert and call-setup overhead comparison, then frozen causal ML refinement on new held-out runs.

## 2026-10-01 three-call burst development
- Predeclared manifest: `datasets/burst_development_manifest_20261001.json`, SHA-256 `836b25b9a7173724208ebe5e658a1b81f7226623d2a518bb86db9227a782a488`.
- Four development cases B001–B004, two opposite assigned-intent pairs, three exact-route SIPp UAS calls each. All 4 independently verified three distinct completed SIP legs, three answered six-second CDRs, expected 0/6 failed auth logs, and cleanup. No external/provider calls.
- Raw evidence: `datasets/burst-lab-20261001/development/B001`–`B004`; event-time analysis: `datasets/burst-lab-20261001/event_time_analysis/`, summary SHA-256 `dfeee8488205e8adc1f86ced42432974273878f73359b0f1860c2f4bdfdd808e`.
- Fixed development CALL_BURST rule emitted at third INVITE in both benign and simulated unauthorized pairs; first-to-third spans 15.65–17.71 s. The same SIP observations cannot identify the actor's permission. CDR count is verified separately but per-call CDR linkage is ambiguous for three same-account calls.
- In-process Asterisk 20.6.0 auth-event module source and ARM64 binary compiled under `inprocess-lab/`, but **not installed or loaded**. Asterisk module directory `/usr/lib/asterisk/modules` is root-owned and the connector denied sudo. No live in-process comparison can be claimed yet.

## 2026-10-01 same-host external process replay
- Loopback-only Python stage service `scripts/external_event_service.py` and runner `scripts/measure_external_replay.py` processed 253 saved events in 34 session-scoped archived runs; 34/34 stage sequences matched.
- Results: `datasets/external-service-replay-20261001/`, summary SHA-256 `b48d61a6d2c04eba79b3657b1025a166be7f5e4dd5c68131098703f7777df62d`. Median local round trip 0.059149 ms, p95 0.085501 ms; child service peak RSS 17,888 KiB. The service exited after replay.
- This is not live SIP-to-alert latency, a second-host external deployment, or an in-process comparison. Live event acquisition and PBX call impact remain to measure.

## 2026-10-01 first live external detector case B005
- Predeclared isolated case manifest: `datasets/live_external_case_manifest_20261001.json`, SHA-256 `64ecae88aff7daaba74dff85f4a1ac3715e438e749e1baea3fbef2c7ef17d32d`.
- The rootless restricted collector `scripts/live_external_collector.py` piped tcpdump SIP capture through tshark into the loopback stage service. It emitted six auth-rejection, one REGISTER-success, and three distinct outbound-INVITE events and five review alerts (recovery, three per-call attempts, burst). Collector source SHA-256 `99cce35b12875d2dc3ac2a3af31b7af74b2789e55e59fc463d448204a1dd72ba`.
- Independent B005 verification passed: three completed SIP legs, three answered six-second CDRs, six auth-log lines, PCAP hash, zero calls and absent exact route after cleanup. Raw capture: `datasets/burst-lab-20261001/development/B005/`; live selected evidence: `datasets/live-external-20261001/B005/`.
- Packet-to-decision for the five alerts was 545.102–646.735 ms (median 645.520 ms); service processing ~0.09–0.106 ms. One case, same-host external process, no live resource/call setup baseline. In-process module still unloaded; no H3 comparison yet.


## 2026-10-01 recovered batch, causal ML holdout and live ML validation
- B006–B015 were already captured and independently verified; recovered without repeating calls.
- Frozen model ece43b48… evaluated once: 2 LOWER, 6 REVIEW, 2 HIGHER; all five matched opposite-intent pairs got the same priority categories. No demonstrated unauthorized-intent improvement; rule alerts remain visible.
- Holdout evaluation summary: datasets/causal-ml-holdout-20261001/summary.json; SHA-256 442d5bb558858b53c30184174a202d642c5deeb02a1e454e668943082a58dcd3.
- Predeclared live B016 passed: 6 failures, valid registration, 3 completed calls and 3 answered CDRs. Live ML score 0.4732518114 (REVIEW).
- B016 alert packet-to-decision median 362.630 ms, range 112.713–942.540 ms; median service processing 0.122834 ms. One live case, no overhead baseline or in-process comparison.
- Evidence: datasets/live-ml-20261001/B016 and datasets/burst-lab-20261001/development/B016.
- Final state: collector/service exited, zero active calls, both temporary routes absent. In-process module remains unloaded.
- Read RESUME_CHECKPOINT_20261001.md next; do not reuse inspected cases as fresh holdout.


## 2026-10-01 external detector off/on preliminary measurements
- Declared B017–B020 OFF/ON/ON/OFF; all four independently verified three completed SIP calls, three answered CDRs, six auth failures and route cleanup (12 calls total).
- Evidence: datasets/external-overhead-20261001; manifest SHA-256 270bc7b8700d31002472a470a5377fc595d4584f379e1ea79905db77ec0bff3b; summary SHA-256 542df517b394a6e49fdae796034797cbdcebd2bbfec51251f7700111f097ee53.
- Setup medians OFF/ON/ON/OFF: 72.399/25.757/24.373/18.091 ms. Paired on-minus-off deltas -46.642/+6.282 ms are inconclusive. Host/WLAN not controlled; source searches occurred during first OFF case.
- Asterisk sampled average CPU 0.166–0.205% of one core; RSS 104,992 KiB. Collector/service peak RSS 17,808/17,888 KiB each; capture/decoder costs are additional.
- B018/B019 live alert delivery medians 231.517/439.087 ms; service processing 0.110315/0.115353 ms. Both retained REVIEW ML priority.
- No causal overhead, stress capacity, production acceptance or in-process comparison claim.
- Prepared inprocess-lab/install_lab_module_checked.sh for local sudo installation; not run. Module remains unloaded and only implements auth subset.
- Read PERFORMANCE_CHECKPOINT_20261001.md next; Section 3 objective mapping and next step recorded. Final zero active calls, no temporary routes and no detector processes.


## 2026-10-01 in-process module installed and live auth validation
- User installed the checked binary; installed SHA-256 matched 02160968346541cc7ca45b848758a269275567707dd1fb54fb1c31c518f3bb26. Loaded successfully.
- Fresh registration-only A000/A001/A002 independently passed: normal valid registration no alert; 10 failures authentication alert; 6 failures then success compromise-suspicion review. No calls/routes/new CDRs; account 1001 unaffected.
- Evidence: datasets/inprocess-auth-validation-20261001; live summary SHA-256 f99b2a5965ffa5d06bb29ae2a07657711d7d55507e40b7879ac7c398a0be92b4.
- External archived replay matched all 3 auth-stage outputs using capture termination-log timestamp as observation end; summary SHA-256 45d0a7e63086987a4e2129778d60d1aefb4eafc11f93d9d6dca4efc7a9e83929. First partial replay preserved; PCAP write time incorrectly truncated silent retry grace.
- Auth subset only: no full multi-stage/ML equivalence, no live latency/overhead H3 comparison yet.
- Final module unloaded, zero active calls, temporary routes absent. Read INPROCESS_CHECKPOINT_20261001.md next. Installed binary remains available.


## 2026-10-02 literature expansion and new development evidence
- Read LITERATURE_CHECKPOINT_20261002.md next. Eight relevant research publications screened; unverified prior MDPI 16/18/9346 rate claim excluded. Jansky 2017 describes distributed detection but did not observe distributed guessing.
- DL001–DL008 registration development: all eight verified; six eligible causal vectors. Four opposite-role profile pairs have the same V6 stages and ML categories. No new local model or fresh holdout result; frozen ece43b48… unchanged.
- RE001/RE002: six unauthenticated REGISTERs to one/six unused lab IDs, respectively; all 401, no new CDRs. Current progression misses target-diversity probe. Separate candidate reviewed fifth unique target at archived event delay 4.002101 s; only RE002 alerted among 16 development captures. NAT/proxy controls and fresh heldout pending.
- Author-linked external SIP-DDoS archive downloaded/audited: 1,351,310 INVITE rows. Content-Length template shortcut separates labels completely; excluded from timing-only external tree. Whole-file retrospective balanced accuracies 0.914367/0.966683/0.968151. Separate flooding endpoint, not improved local fraud-intent accuracy.
- Evidence: datasets/literature-development-20261002, datasets/register-enumeration-20261002, datasets/register-diversity-candidate-20261002. All new manifests/wrappers/hashes preserved. Ten new live development captures total; no provider calls, zero active calls and no temporary routes after work.
- Next: genuine multi-account/shared-source controls, independently observed authorization context, new session/day/device data, frozen candidate plus fresh heldout, full deployment comparison. F13–F28 not all completed. Thesis DOCX not edited; later integration notes are in the checkpoint.

## 2026-10-02 shared-auth measurement and baseline audit completed
Six cases T001–T006 passed with no calls/CDRs; internal observed alert availability 1.790/1.808 ms, external 274.645/574.066 ms. Different delivery interfaces and only two enabled observations per mode; no full-stage or call-setup comparison claim. Archived F-series common-onset audit does not support universally earlier V6 alerts. See DEPLOYMENT_CHECKPOINT_20261002.md and datasets/deployment-auth-comparison-20261002/ plus datasets/first-alert-comparison-20261002/. Existing Oct2 diversity development remains separate. Final PBX check idle, module unloaded, temporary routes absent.

## 2026-10-02 shared-authentication call setup pilot completed
Six accepted cases B021–B023/B027–B029: 18 completed calls, 18 answered six-second CDRs, six auth log failures per case, expected auth-only review, zero capture drops and cleanup. B024 retained as failed: repeated first authenticated REGISTER with same Call-ID/CSeq 2 produced seven auth log lines. B025/B026 not run; replacement block declared separately, original gate unchanged. Total seven attempted cases /21 lab calls. Independent raw-PCAP recalculation passed. OFF case medians 45.972/54.484 ms, internal 16.100/35.571 ms, external 26.004/78.351 ms. No causal overhead or full-stage equivalence claim. Combined summary SHA-256 712001679d2f0aeee31b471b71b3e006ee283ad9f627381fd36ad9003e31e9df. Read CALL_SETUP_CHECKPOINT_20261002.md; canonical datasets/deployment-call-comparison-20261002 and datasets/deployment-call-comparison-replacement-20261002. Final idle, routes absent, module unloaded, frozen hashes match. Thesis integration remains next; diversity development stays separate.

## 2026-10-02: five-stage native port and predeclared comparison

User authorized continuing native/external comparison. No new live calls were placed in this step. New passive PJSIP observer compiled for Asterisk 20.6.0 under inprocess-full-lab; existing module remains unloaded. Native .so SHA256 84c30bcaf2d9f1db5336b06a91a3244752659239d6dd2ac56ea04431d84bb712. Native port matches 34 saved runs (253 events/37 alerts) and ten already evaluated recovery cases (142 events/52 alerts), including frozen ML. These are regression checks, not new accuracy evidence. Packet adapter passed five protocol fixtures and nine archived PCAP checks; B024 remains excluded from the old pilot.

Frozen comparison_manifest.json declares B030 benign native smoke, then B031-B036 OFF/native/external/external/native/OFF, 21 isolated calls total, ten wrong-password dialogs in each primary case and five distinct OPTIONS targets. Unchanged SIP/CDR verifier plus new packet/stage/ML checks stop on any failure. CPU/RSS samples and decision/observation timestamps are saved separately. Five online stages only; CDR answered stage remains retrospective evidence. No model retraining or threshold changes.

Read-only preflight verifies all source/model/template hashes and idle PBX, then stops because /usr/lib/asterisk/modules/res_sipfraud_full_lab.so is not installed. Root-owned destination requires local checked installation: sudo bash /home/astrix/sip-fraud-research/inprocess-full-lab/install_full_module_checked.sh . The installer leaves the module unloaded. After installation, run read-only preflight then the already authorized run_comparison.py --execute; investigate any STOPPED.json before further cases. Full live comparison remains PENDING. See inprocess-full-lab/README.md.

## 2026-10-02: live five-stage native/external comparison COMPLETE

Checked installation, hashes and idle state; executed frozen B030-B036 manifest. All seven cases passed unchanged independent SIP/CDR/auth/cleanup gate and new raw-packet/stage/ML verifier. 21 completed lab calls, all answered with six-second CDRs; primary six-case comparison contains 18 calls. B030 benign smoke produced CALL_BURST. Both native cases and both external cases produced seven alerts covering all five declared online stages and matching frozen ML within predeclared tolerances. All four authorized ten-failure development cases received HIGHER review metadata (~0.68-0.69); this is not evidence of fraud or improved ML accuracy.

Median packet-to-decision ms native/external: reconnaissance 0.085/628.500; auth attack 1015.987/1907.184 (both include one-second retry grace); recovery+ML 4.709/394.017; linked INVITE 0.090/522.112; burst 0.091/640.665. Logger observation timing is separate. Two cases per mode; no causal overhead inference. Native primary call-setup medians 60.539/43.350 ms versus OFF 15.710/12.900 ms and external 38.099/19.613 ms; report this alongside faster native decisions, not zero-overhead claims. Whole-PBX CPU around0.20-0.22% one core; tshark per-process peak151.969MiB external. Cache/allocator carryover and small sample limit memory/CPU inference. Live answered-CDR stage remains unimplemented; CDR is independent retrospective corroboration.

Evidence, descriptive analysis, RESULTS.md, final_state.json and 255-file hash index are in datasets/full-stage-deployment-comparison-20261002. Raw captures remain in burst-lab-20261001/development/B030-B036. Final checks verified0activecalls,0sipfraudmodulesloaded, both temporary routes absent, no tcpdump/tshark/collector/service remaining, loopback19067 closed, all frozen hashes unchanged. New .so remains installed but unloaded. Next authorized research task can use these results to update thesis deployment/limitations sections; avoid broadening accuracy claims.
