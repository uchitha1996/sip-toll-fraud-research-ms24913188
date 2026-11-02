# SIP toll fraud research

**Adaptive Multi-Stage Behavioural Progression Architecture for Early Detection of SIP Toll Fraud**

MSc in Information Systems research by K.M.U.P. Kosgoda, registration MS24913188, Sri Lanka Institute of Information Technology. Supervisor: Dr. Nimal Rathnayake.

This private repository brings together the available thesis documents, experimental source, recorded results and laboratory evidence. It preserves the distinction between observable SIP progression, an assigned experimental role, learned review priority and independently declared permission context.

## Repository status

The initial import contains the materials available locally on 2 November 2026. **It is a partial export, not yet the complete Pi project.** The canonical source remains on the PBX research Pi under `/home/astrix/sip-fraud-research` and on the SIPp generator under `/home/sipp/sip-fraud-lab`.

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

The later frozen causal logistic evaluation and the older retrospective decision-tree experiment are distinct. The supplied `frozen/model.joblib` is the older tree; it must not be described as the later causal logistic model. CDRs corroborate completed laboratory calls and are not future information supplied to an earlier registration-time score.

## Verify the imported artifacts

Run from a clone using Python 3.9 or later:

```text
python tools/verify_artifacts.py
```

This checks file sizes and SHA-256 hashes against `FILE_MANIFEST.json`. It does not execute laboratory runners, deserialize models, generate traffic or claim to reproduce missing experiments. A passing manifest check establishes integrity of the imported files, not the truth of every research claim.

The experiment runners retain their original laboratory paths and dependencies. A complete traffic-generation or historical reproduction environment requires the missing sources, models and experiment directories listed in the inventory.

## Evidence handling and versioning

Twelve raw authentication-bearing C-series PCAPs and their enclosing ZIP archives are retained locally outside this repository. Their exported fields, independent verifier records, result files and recorded original hashes remain available. The four unauthenticated REGISTER-control PCAPs are included. No edited capture is substituted for an original.

Thesis documents will be revised separately from the frozen experiment source and results. Subsequent thesis citations should identify the repository version or commit used, so an evolving branch is not confused with the evidence supporting a submitted document.

No software or data redistribution license is granted by this initial private import. Third-party material retains its original ownership and terms.
