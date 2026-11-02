# SIP fraud research: results and fastest finish plan
Updated 2026-10-02 UTC. This checkpoint extends the existing evidence; frozen detectors and model were not retuned.

## Fresh shared authentication-stage comparison
Six predeclared isolated cases ran in counterbalanced order: OFF, INTERNAL, EXTERNAL, EXTERNAL, INTERNAL, OFF. Each case used account 1002 with six rejected digest authentications followed by a valid registration. All six passed packet, authentication-log and cleanup checks. There were no INVITEs, calls or new CDRs. Independent recalculation verified packet hashes and zero reported capture drops.

| Case | Mode | Expected review alerts | Request to observed alert (ms) |
| --- | --- | ---: | ---: |
| T001 | OFF | 0 | — |
| T002 | INTERNAL | 1 | 1.790 |
| T003 | EXTERNAL | 1 | 274.645 |
| T004 | EXTERNAL | 1 | 574.066 |
| T005 | INTERNAL | 1 | 1.808 |
| T006 | OFF | 0 | — |

The common onset is the captured authenticated REGISTER request that receives the successful response. INTERNAL ends when a polling observer sees the module log line; logger delivery and 2 ms polling are included. EXTERNAL ends when the collector receives the rule-service alert reply; packet acquisition, decoding and IPC are included. These are observed alert-availability measurements through different interfaces, not exact internal decision timestamps. Two observations per enabled mode establish a pilot result, not a latency distribution or full architecture equivalence. The external comparison excludes ML, and the internal module implements the shared authentication subset only.

PBX sampled CPU was 0.155–0.204% of one core across these short runs, with 94,624 KiB peak RSS in every case. External collector CPU was 0.052–0.102%; its decoder peak RSS was about 151.5 MiB. Zero sampled CPU for some processes means activity below sampling resolution, not no work. Shared RSS can double-count pages; internal module memory was not isolated. Registration response times were 0.640–8.759 ms; these do not measure call setup impact.

## Archived baseline timing audit
The common onset is the first captured request in each original F-series scenario. Times below are seconds to the first alert of any stage. A dash means no alert. These are previously inspected archived cases, not a new holdout or live processing measurements.

| Case | Assigned truth | V3 | V5 | V6 |
| --- | --- | ---: | ---: | ---: |
| F05 | Benign recovery | 9.785 | — | 16.298 |
| F07 | Simulated attack | 4.004 | 4.004 | 4.004 |
| F08 | Simulated attack | 5.243 | 5.243 | 5.243 |
| F09 | Simulated attack | 4.007 | 10.006 | 10.006 |
| F10 | Simulated attack | — | 29.853 | 29.853 |
| F11 | Simulated attack | 8.057 | — | 13.619 |
| F12 | Simulated attack | — | 29.770 | 29.770 |

V6 does not universally alert earlier. Reconnaissance timing matched the baselines; confirmed-rejection thresholds sometimes alerted later than V3, which counts normal challenges. V6 covered cases missed by earlier policies. In F11/F12, recovery review preceded the first linked INVITE by about 1.7 seconds, but the same behavior occurred in benign F05. Review is a suspicion indicator, not proof of unauthorized use. First-alert comparisons can involve different stages and risk meanings.

## Defensible hypothesis conclusions
- H1: Universal earlier detection is not supported. Report coverage, stage semantics and pre-call review timing together.
- H2: The frozen causal ML experiment has not demonstrated a false-alarm or priority improvement. Matched authorized/simulated behavior remains observationally ambiguous; retain the negative result.
- H3: The fresh shared-auth pilot shows lower observed native-module alert delivery time on this Pi, and documents external process resources. Full-stage parity, ML parity, call setup impact and load-dependent overhead remain unmeasured.

## Fastest remaining work
1. Consolidate the thesis results now: separate detection coverage, archived event-time timing and live alert availability. Keep the frozen model and original false positives intact.
2. Write the discussion around the negative findings: suspicion is not intent, ML adds no demonstrated gain, and deployment results cover the shared authentication stage.
3. Complete only measurements required by the agreed thesis scope. If call setup overhead is required, predeclare a small OFF/internal/external isolated call comparison with matched workloads. Do not label the auth-only pilot as that test.
4. Treat the Oct 2 diversity candidate and public flooding dataset as separate development work unless fresh candidate validation and benign/NAT controls are completed. Do not merge them into fraud holdout claims.

## Reproducibility and checkpoint
Canonical raw packets, logs, manifests and process samples remain on Astrix-lab under:
- /home/astrix/sip-fraud-research/datasets/deployment-auth-comparison-20261002/
- /home/astrix/sip-fraud-research/datasets/first-alert-comparison-20261002/

This package contains the new scripts, result summaries and independent audit, not the complete prior repository or raw PCAPs. Scripts depend on existing lab helpers in the Pi repository.
Deployment manifest SHA-256: 13dd84d26470f1f063b9a2734118b490ba318e746fe00e2c521268457a2cf78d
Deployment summary SHA-256: 8a5d9a8ae86495ea5973b060756895ef5913c49f5de1334a0ca87834837d51d6
Baseline summary SHA-256: 647ce38beffc08f5af018d3bec65361fd0e91e22c47fde8aedbb3a8589a35501
Installed module SHA-256: 02160968346541cc7ca45b848758a269275567707dd1fb54fb1c31c518f3bb26

Final checked state: zero active calls, temporary routes 88001/88002 absent, experiment processes stopped, module unloaded. The installed binary remains available. Existing development checkpoints and frozen artifacts are preserved.

