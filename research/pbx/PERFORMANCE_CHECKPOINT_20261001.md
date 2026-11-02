# SIP research performance update — 1 October 2026

The external detector now has a preliminary live detector-on/off comparison. The in-process comparison remains incomplete.

## New experiment and verification
Four declared development cases ran in OFF, ON, ON, OFF order: B017–B020, two matched pairs. Each used account 1002, six wrong-password dialogs, one valid registration and three isolated calls to the lab SIPp UAS. All four independently passed PCAP hash, three completed SIP dialogs, three answered CDRs, six failed-auth log entries and cleanup checks. There were no provider calls.
Manifest SHA-256: 270bc7b8700d31002472a470a5377fc595d4584f379e1ea79905db77ec0bff3b.
Summary SHA-256: 542df517b394a6e49fdae796034797cbdcebd2bbfec51251f7700111f097ee53.
Measurement script: measure_external_overhead_20261001.py.

## Observed measurements
Call setup means the first generator INVITE to the first PBX INVITE 200 OK for each Call-ID. CPU is the sampled average for Asterisk during the traffic-runner window; 100% corresponds to one busy CPU core.

| Case | Detector | Median setup (ms) | Asterisk CPU, one-core % |
|---|---|---:|---:|
| B017 | Off | 72.399 | 0.166 |
| B018 | On | 25.757 | 0.204 |
| B019 | On | 24.373 | 0.205 |
| B020 | Off | 18.091 | 0.187 |

On minus off median setup: pair 1 = -46.642 ms; pair 2 = +6.282 ms. Opposite signs and two pairs do not establish a causal latency effect or speed improvement.
Asterisk sampled RSS stayed at 104,992 KiB. Each detector-on case recorded collector peak RSS 17,808 KiB and service peak RSS 17,888 KiB. Decoder role peaks were 155,584/156,624 KiB with detector on; that role includes both live decoding and evidence extraction. These figures are not the model's memory alone and RSS includes shared pages.
Collector plus service sampled CPU averaged about 0.15–0.17% of one core. CPU is sampled and may miss short-lived process tails; zero reported capture CPU means below sampled resolution, not zero work.
B018/B019 live alert packet-to-decision medians: 231.517/439.087 ms. Service-processing medians: 0.110315/0.115353 ms. Both retained five rule alerts and ML REVIEW priority.

## Limits and interpretation
This is exploratory feasibility evidence, not a production capacity test. The same independent evidence capture ran in both arms; detector on added its own capture, decoder, collector and service. Background source-file searches occurred during the first OFF case. Host load and WLAN conditions were not controlled. No statistical significance, acceptable-overhead threshold, stress capacity or in-process latency comparison is established.
The frozen model and the previously inspected holdouts were not changed. Existing matched-role findings still show no demonstrated ML improvement in identifying unauthorized intent.

## Proposal objectives — Section 3 numbering
The supplied proposal contains different objective numbering in its introduction and Section 3. This checklist follows the detailed Section 3/Table 3-1 numbering.

| Objective | Evidence and remaining work |
|---|---|
| O1: Identify early indicators | Protocol-aware auth failures, discovery diversity, recovery and burst indicators tested. Matched authorized/abuse observations expose ambiguity; they cannot prove compromise. |
| O2: Develop progression model | V6 and live external engine track restricted lab source/account progression. Broader entity context, destination history and authorization context remain limited. |
| O3: Examine both deployment modes | External deployment works live. In-process auth observer is compiled but remains unloaded and is not yet equivalent to the full external progression/ML path. |
| O4: Add ML refinement | Frozen retrospective and stage-time models trained and evaluated. H2 improvement is not supported on the matched-role evidence; report the negative finding rather than claim success. |
| O5: Evaluate performance | Controlled accuracy, live latency and preliminary on/off resources are measured. Larger cross-day/device workloads and the deployment comparison remain incomplete. |

H1 early-warning comparison must distinguish suspicion/review alerts from confirmed fraud or the proposal's high-risk endpoint. H3 remains untested between deployment modes.

## Local installation gate and next step
A checked script has been prepared at /home/astrix/sip-fraud-research/inprocess-lab/install_lab_module_checked.sh. It verifies the compiled binary hash, requires zero active calls, refuses overwrite, and installs only that module file. It does not load the module or restart Asterisk. Shell syntax validation passed; installation has not been executed.
Run locally on Astrix-lab:
```bash
sudo bash /home/astrix/sip-fraud-research/inprocess-lab/install_lab_module_checked.sh
```
The connector blocks sudo, so this step needs the Pi's local terminal. After installation, first test actual Asterisk auth events in a declared auth-only case; establish comparable event semantics before claiming a full two-path comparison.
Binary SHA-256: 02160968346541cc7ca45b848758a269275567707dd1fb54fb1c31c518f3bb26.
Final state: zero active calls, both temporary routes absent, detector processes exited; module unloaded.
Canonical Pi evidence: /home/astrix/sip-fraud-research/datasets/external-overhead-20261001/ and datasets/burst-lab-20261001/development/B017–B020.

