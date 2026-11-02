# PP2 High-Priority Research Validation

## Audit status
- This is a READ-ONLY replication using previously inspected captures; not a new validation set.
- PASS: 34/34 archived PCAP SHA256 values match the saved evidence index.
- PASS: frozen retrospective ML model and freeze manifest hashes match.
- PASS: historical confusion matrices have been recalculated from per-case predictions.
- PASS: seven native/external live cases are independently marked verified in the existing archive.

## Stage-detector development results on F01-F12
| Model | TP | FP | TN | FN | Precision | Recall | FPR | Balanced accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| V3 | 4 | 2 | 4 | 2 | 0.6667 | 0.6667 | 0.3333 | 0.6667 |
| V5 | 5 | 1 | 5 | 1 | 0.8333 | 0.8333 | 0.1667 | 0.8333 |
| V6 | 6 | 1 | 5 | 0 | 0.8571 | 1.0 | 0.1667 | 0.9167 |

## Retrospective ML comparison on previously held-out H001-H010
| Model | TP | FP | TN | FN | Precision | Recall | FPR | Balanced accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| ML | 1 | 0 | 5 | 4 | 1.0 | 0.2 | 0.0 | 0.6 |
| V6_any | 3 | 2 | 3 | 2 | 0.6 | 0.6 | 0.4 | 0.6 |
| V6_answered | 2 | 1 | 4 | 3 | 0.6667 | 0.4 | 0.2 | 0.6 |

**ML does not establish an improvement.** The ML endpoint uses retrospective CDR, while the V6 stage endpoint can alert online; the comparison is descriptive, not a matched prospective early-detection trial.

## Research caveats and CDR
- Matched opposite-intent pairs with same ML decision and V6 alert outcome: H003/H007, H004/H008.
- Independently verified lab CDR call counts across H scenarios: {'BENIGN': 3, 'SIMULATED_ABUSE': 3}. CDR verifies outcome, not authorization.
- Separate causal ML priority experiment on 10 archived cases: {'LOWER': 2, 'REVIEW': 6, 'HIGHER': 2}. Review priority is NOT fraudulent intent.
- Archived comparable first-alert cases V6 versus V3: {'later': 3, 'same': 2} over 5 comparable cases. No universal earlier-detection claim.

## Remaining high-priority experiments
1. Independent account/destination permission records created BEFORE new traffic; validate legitimate recovery versus simulated unauthorized action.
2. New legitimate multi-account NAT/proxy and mixed-session controls plus diversity probe tests.
3. Prospective fresh grouped sessions with frozen rules/model; evaluate the same early-time endpoint for simple baseline, stage rules, context checks and causal ML.
4. Larger normal CDR baseline with consent/anonymization. Never use future answered CDR as an input to an early detector.
5. Expand repeated native/external load and stability measurements only if time allows. The initial pilot is already complete.

## Operational blocker
- SIPp generator (172.16.200.68) responds to ping, but the non-interactive SSH key for pi@172.16.200.68 is rejected; no new live tests attempted by this audit.
- Do not install modules, change PBX routes, dial PSTN or reuse the previously inspected heldout cases as if fresh.

## PP2 takeaway
Stage-aware detection and five-stage native/external pilot work; independent attribution of unauthorized toll fraud, local ML improvement and generalized performance remain unproven.

## Additional independent CDR reconciliation (10 October)
- PASS: 34/34 run-local CDR before/after deltas match verification records.
- PASS: 21/21 new lab call CDRs answered for six seconds, 21 distinct unique IDs, only 1001->88001 or 1002->88002.
- These are isolated scripted calls. They cannot substitute for a diverse external normal-call baseline or prove authorization.
- Early ML must not use final answered CDR outcome or final billsec.
