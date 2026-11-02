# F01-F12 scenario-level evaluation

Created UTC: 2026-09-30T09:49:22.075445Z

This table consolidates the registered F-series captures without changing any source evidence.
It is a small controlled lab set (6 benign, 6 attack), not a production accuracy estimate.

| Detector | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| V3 | 4 | 2 | 4 | 2 | 0.667 | 0.667 | 0.667 | 0.333 | 0.667 |
| V5 | 5 | 1 | 5 | 1 | 0.833 | 0.833 | 0.833 | 0.167 | 0.833 |
| V6 | 6 | 1 | 5 | 0 | 0.857 | 1.000 | 0.923 | 0.167 | 0.917 |

V6 expected-stage pass: 11/12 (0.917).

Important failure cases: F03 tests benign repeated OPTIONS to one target; F05 tests benign credential recovery followed by an authorized call. These are especially useful when designing the next refinement/ML features.

Use scenario_results.csv for the exact case-by-case evidence.
