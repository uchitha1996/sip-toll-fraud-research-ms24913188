# SIP toll fraud research

**Adaptive Multi-Stage Behavioural Progression Architecture for Early Detection of SIP Toll Fraud**

MSc in Information Systems research by K.M.U.P. Kosgoda, registration MS24913188, Sri Lanka Institute of Information Technology. Supervisor: Dr. Nimal Rathnayake.

This private repository brings together the available thesis documents, experimental source, recorded results and laboratory evidence. It preserves the distinction between observable SIP progression, an assigned experimental role, learned review priority and independently declared permission context.

## Repository status

The repository contains the locally available documents plus a verified export recovered on 2 November 2026 from `/home/astrix/sip-fraud-research` and `/home/astrix/sipp-lab` on the main PBX Pi. The export recovered 3,991 regular files; 3,779 originals are included unchanged. Authentication-bearing captures, enclosing archives, caches and one credential-bearing template remain outside GitHub. A clearly labelled sanitized copy of that template is supplied.

The standalone SIPp generator folder `/home/sipp/sip-fraud-lab` is outside this import. The current scope proceeds with the main Pi materials; this is not a complete two-machine deployment backup.

[INVENTORY.md](INVENTORY.md) records exactly what is present, missing and retained outside GitHub. Original frozen sources and result files are preserved without editing their bytes. Earlier and later experiments remain separate evidence families.

## Find the material

| Directory or file | Contents |
| --- | --- |
| [documents/baseline](documents/baseline) | Thesis version retained before the next editorial changes |
| [documents/drafts](documents/drafts) | Supplied earlier drafts with their original filenames |
| [documents/proposal](documents/proposal) | Approved research proposal supplied in the earlier research chats |
| [documents/template](documents/template) | Supplied SLIIT thesis template and guidance |
| [documents/presentations](documents/presentations) | Available PP2 presentation variants |
| [documents/demonstration](documents/demonstration) | Laboratory demonstration guide |
| [experiments/accelerated-20261012](experiments/accelerated-20261012) | Frozen common evaluator, permission policy, fresh experiment records and REGISTER controls |
| [research/pbx](research/pbx) | Recovered main Pi source, native C modules, services, models, results and exportable evidence |
| [research/sipp-helper](research/sipp-helper) | Recovered PBX-side SIPp helper files |
| [research/RECOVERY_MANIFEST.json](research/RECOVERY_MANIFEST.json) | Original paths, sizes and hashes for the recovered unchanged files |
| [evidence/supervisor-20261012](evidence/supervisor-20261012) | Earlier result summaries, development/held-out ML records and comparison material |
| [FILE_MANIFEST.json](FILE_MANIFEST.json) | SHA-256 hashes and sizes of the imported research artifacts |
| [tools/verify_artifacts.py](tools/verify_artifacts.py) | Read-only verification of the imported artifact manifest |

## Principal controlled comparison

The C001–C012 comparison uses six assigned benign roles and six simulated-abuse roles, with nine answered isolated laboratory calls. These are constructed experiment labels, not independently observed criminal intent.

| Method | TP | FP | TN | FN | Balanced accuracy | Before-first-INVITE warnings |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Auth 10 | 1 | 0 | 6 | 5 | 58.3% | 0/5 |
| Auth 5 | 5 | 2 | 4 | 1 | 75.0% | 4/5 |
| V6 | 5 | 2 | 4 | 1 | 75.0% | 4/5 |
| V6 plus context | 5 | 1 | 5 | 1 | 83.3% | 2/5 |

The classification denominator is twelve complete cases. The early-warning denominator is the five simulated-role cases containing an INVITE. Context reduces one false alert while changing which simulated case is missed and reducing pre-call coverage. The five-failure baseline has a larger positive warning lead than V6 on the comparable calling cases. These results do not establish general fraud accuracy or production readiness.

The later frozen causal logistic evaluation and the older retrospective decision-tree experiment are distinct. The `frozen/model.joblib` files are the older tree. The later model is [research/pbx/datasets/causal-review-ml-20261001/frozen_model.json](research/pbx/datasets/causal-review-ml-20261001/frozen_model.json), whose hash matches the thesis-recorded causal model. CDRs corroborate completed laboratory calls and are not future information supplied to an earlier registration-time score.

## Verify the imported artifacts

Run from a clone using Python 3.9 or later:

```text
python tools/verify_artifacts.py
python tools/replay_exported_cases.py
```

The first command checks imported file sizes and hashes. The second verifies the relevant freezes and replays all twelve C-series event exports, checking their saved predictions and confusion counts. It reports explicitly that the raw authentication-bearing PCAPs are absent from the clone. Neither command generates traffic or deserializes the older model.

The original [reproduce_results.py](research/pbx/accelerated-20261012/reproduce_results.py) was also checked against the recovered originals, including all twelve original PCAP hashes. See [research/READ_ONLY_REPRODUCTION_CHECK.json](research/READ_ONLY_REPRODUCTION_CHECK.json). That full check requires the original captures retained outside GitHub. The live runners retain their original laboratory paths and dependencies.

## Evidence handling and versioning

The excluded originals are listed by path and hash in [research/EXCLUDED_ORIGINALS.json](research/EXCLUDED_ORIGINALS.json). Thirty-seven exportable PCAPs are included. No edited capture is substituted for an original. Fourteen deliberately invalid password test fixtures retain their original bytes; these are failed-authentication stimuli rather than the valid account credential.

The single sanitized template is under [research/sanitized](research/sanitized), with its changes recorded in [research/SANITIZED_SOURCE_MANIFEST.json](research/SANITIZED_SOURCE_MANIFEST.json). Safe members of the withheld archives are already included at identical hashes elsewhere; [research/ARCHIVE_MEMBER_INDEX.json](research/ARCHIVE_MEMBER_INDEX.json) maps those identities.

Thesis documents will be revised separately from the frozen experiment source and results. Subsequent thesis citations should identify the repository version or commit used, so an evolving branch is not confused with the evidence supporting a submitted document.

No software or data redistribution license is granted by this initial private import. Third-party material retains its original ownership and terms.
