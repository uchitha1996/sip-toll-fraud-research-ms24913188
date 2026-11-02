# Available research materials

This repository assembles the locally available documents, frozen experiment sources, recorded results and laboratory evidence for MS24913188. It is a partial export of the canonical Pi research directory, not a complete copy of `/home/astrix/sip-fraud-research`.

## Organization

- `documents/baseline/`: the thesis present at repository preparation, retained as a baseline before subsequent revisions.
- `documents/drafts/`: original supplied thesis drafts and a separately downloaded final document where it differs from the baseline.
- `documents/proposal/` and `documents/template/`: recovered research proposal and supplied institutional thesis template.
- `documents/presentations/`: all available PP2 presentation variants with original filenames.
- `documents/demonstration/`: the original supervisor live demonstration guide.
- `experiments/accelerated-20261012/`: safe, byte-exact extracted members of the final controlled context experiment, with their original relative paths.
- `evidence/supervisor-20261012/`: byte-exact outer evidence summaries, local ML features, held-out result records and older comparison files.
- `FILE_MANIFEST.json`: SHA-256 and byte length of each preserved research artifact. No frozen research file was edited during collection.

## Available canonical research material

The accelerated experiment includes the common evaluator, protocol preparation, batch and case runners, registration-control runner and sender, implementation checks, fixed account policy, prospective manifest, freeze records, final/interim results, per-case metrics and timestamped stage progression. Frozen V5 and V6 source files, the older local decision-tree model and its archived protocol/index, and the causal evaluation summary are present under its `frozen/` directory.

All twelve C001–C012 cases include exported SIP packet fields, authentication evidence, before/after CDR snapshots, declared protocols, status and verifier records, label-blind prediction records, SIPp logs and V5 timelines. Four P101–P104 controls include original unauthenticated REGISTER PCAPs, exported packet fields, sender/verification records and unchanged CDR snapshots. Source filenames and bytes are preserved.

The outer evidence records include local ML development and held-out features, held-out results, protocol/freeze metadata, historical comparison data and older stage/dataset CSVs. These different experiment families must retain their separate denominators and interpretations.

## Sensitive originals retained outside this repository

Twelve original C001–C012 `traffic.pcap` files contain SIP Digest Authorization material. They and the enclosing original ZIP archives were preserved unchanged in a local quarantine and were not staged. The withheld paths are `runs/fresh/C001/traffic.pcap` through `runs/fresh/C012/traffic.pcap` within the accelerated archive. Their recorded hashes remain in the original verifier and freeze records. No redacted capture has been substituted for an original, and no frozen hash has been changed.

The original outer archive is `SIP_Research_Supervisor_Evidence_20261012.zip`; its nested archive is `V6/accelerated-evidence-20261012.zip`. Those archive files are withheld because they contain the same authentication material. The remaining extracted research members retain their original bytes. No private key material, access token or literal password assignment was found in the inspected source/config text. SSH key paths in laboratory runners identify dependencies; they do not contain private keys.

## Missing from the local export

- The complete canonical Pi repository and its original Git history.
- `accelerated-20261012/reproduce_results.py`, named in the thesis but absent from the supplied archive.
- The frozen causal logistic model file corresponding to the causal model checksum in the thesis. The supplied `frozen/model.joblib` is the older local decision tree and is not a substitute.
- Raw D001–D024 and H001–H010 PCAPs and complete scenario directories; the supplied indexes record these historical files but do not include them.
- Full B006–B015 raw captures and associated causal-model directory; an archived summary is available.
- Original B016 live integration, T001–T006 authentication pilot, B021–B029 call pilot and B030–B036 full-stage deployment directories and their raw measurements.
- Native C module source/binary and the original full-stage comparison runner/configuration.
- Canonical `external_event_service.py`, `external_event_service_ml.py`, `lab_burst_runner.py`, `verify_burst_run.py` and all other unprovided Pi scripts.
- `run_remote_sipp_challenges.py`, `prepare_valid_register.py`, `prepare_valid_register_1002.py`, SIPp XML templates, runtime dependencies and laboratory host configuration required by the supplied live runners.
- The original public SIP-DDoS CSV benchmark, the student's benchmark model/code/results and its full provenance package.
- An original repaired P002 receive-path test. P102 is a separately declared replacement observation; it does not repair historical P002.

The preserved runners refer to the original laboratory paths and machines. They are source evidence, not a claim that a fresh clone can generate traffic or reproduce every historical result without the missing dependencies and sensitive originals.

## Scope exclusions

Unrelated business documents, prior-chat dumps, internal document-authoring scripts, extracted drafting text, render/QA images, local automation scripts and credentials are excluded. No supplied experimental code was executed while preparing this collection. The raw capture exclusions do not alter the original measured results.
