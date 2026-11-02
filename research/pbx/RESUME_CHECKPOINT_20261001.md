# SIP Research Resume Checkpoint — 1 October 2026

## Completed after recovering the unresponsive session
- Astrix-lab online; previous experiment batch had finished, with no research processes running.
- B006–B015: all ten saved runs verified; no calls were repeated.
- Each holdout case contains three completed SIP calls, three answered CDRs, planned failed-auth logs, matching PCAP hash and successful cleanup.
- Frozen stage-time ML model hash: ece43b48eb1d98115c2796735c67fc80589f8ff85d51765e78d373e3079ee30d.
- Holdout manifest hash: 652e68d674fa5bac4909cc407206bcb991b60301bba8aab75eef145790afdaa5.
- One-time evaluation completed; summary hash: 442d5bb558858b53c30184174a202d642c5deeb02a1e454e668943082a58dcd3.
- Priority counts: LOWER 2, REVIEW 6, HIGHER 2.
- Each matched authorized/simulated-unauthorized pair received the same priority category.
- HIGHER included one authorized and one simulated-unauthorized case; LOWER also included one of each.
- No demonstrated improvement in identifying unauthorized intent. Review scores never suppress rule alerts.
- Labels describe experimenter-assigned roles; no stolen credentials or provider/billed calls were used.
- Model used only four features available at REGISTER success; no future CDR information.

## New live integration validation B016
- Already-declared development case completed with unchanged frozen model.
- Six confirmed auth rejections, one valid registration, three completed calls and three answered six-second CDRs.
- Live score 0.4732518114, priority REVIEW; recovery, call-attempt and burst alerts preserved.
- Five alert packet-to-decision times: median 362.630 ms, range 112.713–942.540 ms.
- Median service processing 0.122834 ms; this excludes capture/decoding delivery delay.
- One case does not establish general latency, call setup overhead or an in-process comparison.
- Collector/service exited; zero active calls and temporary routes 88001/88002 absent.

## Canonical evidence on Astrix-lab
- Root: /home/astrix/sip-fraud-research.
- Holdout captures: datasets/burst-lab-20261001/heldout/B006–B015.
- Evaluation: datasets/causal-ml-holdout-20261001/summary.json.
- Live capture and independent verification: datasets/burst-lab-20261001/development/B016.
- Live events, alerts, status and timing: datasets/live-ml-20261001/B016.
- Updated continuity file: MIGRATION_STATUS.md.

## Next work — still incomplete
1. In-process module is compiled but unloaded; root-owned module installation remains blocked by connector sudo policy. Do not change permissions or claim that comparison is complete.
2. Prepare and predeclare paired detector-on/off call setup and resource measurements, then measure both paths once module installation is available.
3. Obtain independent authorization/destination context if intent classification remains an objective; SIP timing alone did not separate matched roles.
4. Use new devices/networks/days for broader prospective evaluation. These inspected holdouts must not be reused as fresh test data.
5. Update thesis with the measured results, negative ML finding, deployment limitation and exact evidence paths.


## Later continuation — performance work completed
- Read PERFORMANCE_CHECKPOINT_20261001.md for the newest state.
- B017–B020 passed (12 calls); preliminary external off/on measurements saved under datasets/external-overhead-20261001.
- Two pairs give inconclusive setup-time effects; no in-process comparison yet.
- Local checked module-install script prepared but not run; module remains unloaded.


## Newest state: live in-process auth validation
- Read INPROCESS_CHECKPOINT_20261001.md next.
- User installed module; A000–A002 passed live registration-only checks; external archived auth stages match with explicit capture-stop metadata.
- Module unloaded afterward; zero calls; two-path live latency/overhead comparison still pending.

## 2026-10-02 shared-auth measurement and baseline audit completed
Six cases T001–T006 passed with no calls/CDRs; internal observed alert availability 1.790/1.808 ms, external 274.645/574.066 ms. Different delivery interfaces and only two enabled observations per mode; no full-stage or call-setup comparison claim. Archived F-series common-onset audit does not support universally earlier V6 alerts. See DEPLOYMENT_CHECKPOINT_20261002.md and datasets/deployment-auth-comparison-20261002/ plus datasets/first-alert-comparison-20261002/. Existing Oct2 diversity development remains separate. Final PBX check idle, module unloaded, temporary routes absent.

## 2026-10-02 shared-authentication call setup pilot completed
Six accepted cases B021–B023/B027–B029: 18 completed calls, 18 answered six-second CDRs, six auth log failures per case, expected auth-only review, zero capture drops and cleanup. B024 retained as failed: repeated first authenticated REGISTER with same Call-ID/CSeq 2 produced seven auth log lines. B025/B026 not run; replacement block declared separately, original gate unchanged. Total seven attempted cases /21 lab calls. Independent raw-PCAP recalculation passed. OFF case medians 45.972/54.484 ms, internal 16.100/35.571 ms, external 26.004/78.351 ms. No causal overhead or full-stage equivalence claim. Combined summary SHA-256 712001679d2f0aeee31b471b71b3e006ee283ad9f627381fd36ad9003e31e9df. Read CALL_SETUP_CHECKPOINT_20261002.md; canonical datasets/deployment-call-comparison-20261002 and datasets/deployment-call-comparison-replacement-20261002. Final idle, routes absent, module unloaded, frozen hashes match. Thesis integration remains next; diversity development stays separate.
