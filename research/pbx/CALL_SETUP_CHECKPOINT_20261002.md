# SIP research: shared-authentication call setup pilot
Updated 2026-10-02 UTC. This extends the earlier authentication alert-availability study and archived baseline audit.

## Completed work
Six accepted cases contain 18 distinct completed lab calls and 18 answered six-second CDRs. Each accepted case has exactly six failed-authentication log lines, a valid registration, no reported capture drops, and verified cleanup. Both enabled observers produced one SUSPECTED_COMPROMISE review. Independent analysis re-extracted SIP fields from the raw PCAPs and reproduced every setup measurement.

Seven cases were attempted, making 21 lab calls in total. B024 failed the prespecified authentication-log gate and remains excluded. Its three calls completed, but the first rejected authenticated REGISTER appeared twice with the same Call-ID and CSeq 2, generating seven log lines instead of six. B025/B026 were not run. A new manifest declared B027/B028/B029 as the replacement block; the gate was not relaxed. This exclusion restricts the accepted comparison to cases without that duplicate-log mismatch.

## Measurement and scope
Call setup means the first generator INVITE to the first PBX 200 response for INVITE on the same generator Call-ID. It includes the INVITE authentication exchange. Calls went only to the lab SIPp UAS through the exact temporary 88002 route; no provider destination was used.

INTERNAL runs the installed authentication-only Asterisk module. EXTERNAL runs the rule service with authentication events only; its collector decodes lab packets but does not forward INVITEs to the service. ML is excluded. This compares call setup while the shared authentication stage is enabled, not full detector implementations.

| Case | Mode | Block | Median setup (ms) | Three individual setup values (ms) |
| --- | --- | ---: | ---: | --- |
| B021 | OFF | 1 | 45.972 | 19.879, 45.972, 55.738 |
| B022 | INTERNAL | 1 | 16.100 | 16.100, 84.192, 13.037 |
| B023 | EXTERNAL | 1 | 26.004 | 11.087, 26.004, 51.898 |
| B027 | EXTERNAL | 2 | 78.351 | 78.351, 40.644, 124.027 |
| B028 | INTERNAL | 2 | 35.571 | 35.614, 35.571, 14.649 |
| B029 | OFF | 2 | 54.484 | 54.484, 16.750, 56.377 |

| Block | Enabled mode | Enabled minus OFF median (ms) |
| --- | --- | ---: |
| 1 | INTERNAL | -29.872 |
| 1 | EXTERNAL | -19.968 |
| 2 | INTERNAL | -18.913 |
| 2 | EXTERNAL | 23.867 |

The external delta changed sign between blocks. The internal cases had lower observed medians than OFF, but this small, nonrandomized WLAN pilot cannot establish an improvement or a precise causal overhead estimate. Calls are clustered within cases; there are only two cases per mode. Do not report the 18 calls as 18 independent deployment replications. No performance acceptance threshold or production-readiness claim was tested.

## Process resource observations
Samples were taken every 0.25 seconds; analysis used the interval from the first generator REGISTER through the last generator-leg BYE plus 0.5 seconds. Preparation, startup and offline PCAP extraction are excluded.

| Process | Sampled CPU, percent of one core | Peak RSS across accepted cases |
| --- | --- | --- |
| Asterisk PBX | 0.202–0.231% | 94.73–96.23 MiB |
| External collector | 0.050–0.076% | 17.22–17.41 MiB |
| External rule service | 0–0.025% | 17.47–17.67 MiB |
| External tshark decoder | 0.025–0.051% | 151.97–152.97 MiB |

These are process observations at low lab load, not whole-system CPU costs or isolated module memory. Zero sampled CPU means below sample resolution. Short-lived tails may be missed, and summed RSS can count shared pages more than once. PBX RSS increased between blocks across all modes; do not attribute that increase to the module.

## Thesis-ready result paragraph
A counterbalanced pilot compared detector-disabled operation with internal and external implementations of the shared authentication-recovery stage. Six accepted cases produced 18 completed isolated SIP calls, verified against raw packet captures and answered CDRs. One additional case was excluded by the predeclared authentication-log-count gate after a repeated authenticated REGISTER generated a duplicate log entry; its evidence was retained and a replacement block was declared separately. Per-case median call setup times ranged from 45.972 to 54.484 ms for disabled operation, 16.100 to 35.571 ms for the internal observer, and 26.004 to 78.351 ms for the external observer. The external-minus-disabled difference changed sign across blocks. These results characterize operation at low lab load but do not establish a causal overhead penalty, a performance improvement, or full internal/external detector equivalence.

## Updated research conclusions and finish steps
- Detection: retain the original coverage and false-positive results. The archived timing audit does not show universally earlier V6 alerts.
- ML: retain the frozen evaluation and negative finding; no demonstrated priority/false-alarm improvement. Identical authorized and simulated SIP sequences do not reveal authorization.
- Deployment: shared-authentication alert availability, process resources and an initial call setup pilot are now measured. Full-stage internal/ML parity and stress/load behavior remain outside this pilot.
- Next: integrate the measured results, architecture figures, detector evolution, discussion and limitations into the thesis. Keep all hypothesis answers evidence-based; a negative answer is a result.
- If the thesis requires full in-process progression rather than the shared authentication subset, that implementation and its evaluation remain outstanding. Keep the coverage gap explicit in the objective table.
- Keep the Oct 2 diversity candidate and external flooding dataset separate from final fraud claims until their own fresh validation and benign/NAT controls are completed.

## Reproducibility and safe checkpoint
Combined summary SHA-256: 712001679d2f0aeee31b471b71b3e006ee283ad9f627381fd36ad9003e31e9df
Original manifest SHA-256: 8455a384721e6e6ec8283b5104c895774f8f5a3b2af486ce932364d118fd72ef
Replacement manifest SHA-256: 9276878925edbcf099184e9543e07718a12b67b92cbe8ad86d40e62f227c9e53

Canonical evidence remains on Astrix-lab:
- /home/astrix/sip-fraud-research/datasets/deployment-call-comparison-20261002/
- /home/astrix/sip-fraud-research/datasets/deployment-call-comparison-replacement-20261002/
- /home/astrix/sip-fraud-research/datasets/burst-lab-20261001/development/B021–B024 and B027–B029/

Final checks found zero active calls, both temporary routes absent, the module unloaded and no detector/traffic-runner processes. V5, V6, the frozen causal model, installed module and declared rule-service hashes still match. The installed module remains available.

This package contains the scripts, manifests, summaries and independent audit. Raw PCAPs and original log/CDR captures remain at the canonical Pi paths; existing lab helpers are required to run the scripts.

