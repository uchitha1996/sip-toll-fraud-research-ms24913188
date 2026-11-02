# Research repository inventory

Updated 2 November 2026 for MS24913188.

## Current coverage

The repository combines 310 initially supplied artifacts with 3,779 unchanged files recovered from the main research Pi and its helper folder. `FILE_MANIFEST.json` records all 4,089 preserved artifact paths, sizes and SHA-256 values. Documentation, verification tools and collection indexes are additional files.

The source locations are `/home/astrix/sip-fraud-research` and `/home/astrix/sipp-lab`, mapped to `research/pbx/` and `research/sipp-helper/`. The standalone generator folder `/home/sipp/sip-fraud-lab` was not retrieved; the current scope proceeds with the main Pi export. Filesystem links and Git internals were not followed into other locations.

## Documents and initial supplied evidence

`documents/final/` contains the current revised Word/PDF pair. Their identities are recorded separately in `documents/final/FILES.json`, and navigation checks in `documents/final/VALIDATION.json`. The funding narrative is removed, the laboratory history is stated neutrally, and reference 19 identifies the immutable GitHub evidence snapshot.

- `documents/baseline/`: thesis retained before the next editorial revision.
- `documents/drafts/`: supplied earlier thesis versions with original filenames.
- `documents/proposal/` and `documents/template/`: supplied approved proposal and SLIIT thesis template.
- `documents/presentations/` and `documents/demonstration/`: PP2 variants and supervisor demonstration guide.
- `experiments/accelerated-20261012/`: initially supplied context-comparison subset.
- `evidence/supervisor-20261012/`: initially supplied earlier results and ML records.

These versions are historical artifacts. A newer filename does not automatically supersede the experimental evidence in another file.

## Recovered main Pi material

The unchanged recovered import contains 158 source/scenario files, two model files, 839 JSON result/metadata files, 993 CSV datasets/metrics files, 1,470 logs, 269 text/checkpoint documents, 37 exportable PCAPs and 11 other files. One separate sanitized XML template supplies the structure of a withheld credential-bearing source.

Important paths under `research/pbx/` include:

| Path | Material |
| --- | --- |
| `scripts/` | Frozen V5/V6, external services, collectors, ML integration and laboratory/measurement scripts |
| `inprocess-lab/` | Earlier native authentication observer sources |
| `inprocess-full-lab/` | Later native progression C sources, comparison and build material |
| `accelerated-20261012/` | Fresh context comparison, REGISTER controls, freezes and portable reproduction script |
| `datasets/causal-review-ml-20261001/` | Frozen causal logistic configuration and development material |
| `datasets/causal-ml-holdout-20261001/` | Fresh causal evaluation records |
| `datasets/ml-lab-20260930/` | Earlier D/H records and retrospective decision-tree material |
| `datasets/f-series-evaluation/` | F-series development comparisons |
| `datasets/deployment-auth-comparison-20261002/` | Authentication-stage deployment pilot |
| `datasets/deployment-call-comparison-20261002/` | Call-setup pilot and retained failure record |
| `datasets/deployment-call-comparison-replacement-20261002/` | Separately declared replacement block |
| `datasets/full-stage-deployment-comparison-20261002/` | Later five-stage native/external results |
| `datasets/burst-lab-20261001/` | Laboratory call evidence and exported observations |

The causal logistic JSON matches thesis SHA-256 `ece43b48eb1d98115c2796735c67fc80589f8ff85d51765e78d373e3079ee30d`. The older `model.joblib` belongs to a different decision-tree experiment. Frozen V5 and V6 also match their recorded identities.

## Originals retained outside GitHub

The main Pi export recovered 3,991 regular files. Of these, 212 originals are excluded: 64 generated Python caches, 145 authentication-bearing PCAPs, two enclosing archives and one credential-bearing XML template. Original bytes remain locally and on the research machine. No original source or evidence was edited to make a recorded hash pass.

`research/EXCLUDED_ORIGINALS.json` records every excluded path, size, hash and reason. The separate sanitized template is identified in `research/SANITIZED_SOURCE_MANIFEST.json`. Fourteen explicit wrong-password stimuli were reviewed as intentionally invalid test fixtures and retain their original bytes.

Safe members of the excluded archives are already present at identical hashes elsewhere. `research/ARCHIVE_MEMBER_INDEX.json` maps them without substituting an edited archive for an original.

## Verification and replay

`tools/verify_artifacts.py` verifies 4,089 imported artifact identities. `tools/replay_exported_cases.py` checks freezes and replays twelve cases from event exports, matching saved predictions and confusion counts. It reports that the raw C-series captures are absent from the clone.

The original recovered `accelerated-20261012/reproduce_results.py` was reviewed and run read-only against the complete recovered originals. It matched twelve original PCAP hashes and all twelve predictions and confusion matrices. Its output is preserved in `research/READ_ONLY_REPRODUCTION_CHECK.json`. No traffic generation, PBX configuration change, model retraining or deployment occurred during this check.

## Outside the current collection

- Standalone generator `/home/sipp/sip-fraud-lab` and its machine-specific runtime/configuration.
- Original public SIP-DDoS CSV benchmark and the student's complete timing-benchmark source/results, not located in the recovered main Pi tree.
- SSH private keys, valid account credentials and unrelated operational PBX configuration.
- A repaired historical P002 receive-path experiment. Collection preserves the failure/replacement distinction; it does not change that experimental status.

Archival source availability is distinct from configuring a fresh live laboratory. Replaying development cases does not turn them into independent new evaluation samples.
