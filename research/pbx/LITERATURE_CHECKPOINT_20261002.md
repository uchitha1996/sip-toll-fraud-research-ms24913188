# SIP research: literature expansion and completed work
Date: 2 October 2026 (Asia/Colombo).
Purpose: continuity checkpoint and evidence for a later thesis update. The thesis DOCX was not edited.

## 1. What was actually completed
- Read the current SIP_ML_V2_Progress_20261002.md and SIP_ML_V2_Audit_20261001.md, plus the Pi's MIGRATION_STATUS.md and ML_V2_CHECKPOINT_20261002.md.
- Confirmed Astrix-lab access and SSH access to Sipp-generator. PBX 172.16.200.81; generator 172.16.200.68.
- Checked eight relevant research publications through publisher, author or university sources, plus SIP's protocol specification. Access levels and restrictions are recorded below.
- Retrieved the public SIP dataset linked by the authors of the 2026 SIP-DDoS paper; audited all four CSVs and all 1,351,310 message rows.
- Predeclared and collected eight real, separate-host registration development cases DL001–DL008, followed by two bounded REGISTER identity-probe cases RE001–RE002. All ten passed their evidence checks.
- Exported six new eligible registration-time feature vectors and replayed the existing frozen model without replacing it.
- Found a REGISTER-target-diversity gap and implemented a separate exploratory review rule. It emitted one alert across 16 archived development captures.
- Trained a separate lightweight external INVITE timing classifier, using one whole CSV for training and three whole CSVs for retrospective evaluation.
- Preserved old detectors, models and evidence. Final checks: zero active calls, routes 88001/88002 absent; this batch produced no new CDRs and no provider calls.

Completed here does not mean all F13–F28 or the thesis objectives are complete. Local collection, offline replay and an external retrospective benchmark are different types of evidence.

## 2. Corrections to earlier suggestions
1. The earlier reference https://www.mdpi.com/2076-3417/16/18/9346 and claimed REGISTER rates 2/5/10/20 requests/s could not be verified. Do not cite that reference or those figures in the thesis.
2. Jansky et al. (2017) support distributed guessing as a detection capability, but explicitly say it was NOT observed in their monitored network. Do not say they empirically observed distributed guessing.
3. A successful REGISTER after failures does not prove credential theft. Our simulations deliberately supply the correct lab credential; there is no demonstrated stolen password.
4. More scenarios do not guarantee that the earlier 6/10 intent-classification result improves. Intent cannot be recovered from observations that are matched across authorized and simulated-abuse roles.
5. A busy SIP trace alone does not establish DoS, SPIT or financial fraud. Those endpoints require service-impact, unwanted-call or authorization evidence respectively.

## 3. Verified sources and how they apply
The summaries below are paraphrases; no published performance percentage is imported as our result.

| Ref | Publication and verified access | Supported use in this project |
|---|---|---|
| S1 | Jansky, T., Čejka, T., & Bartoš, V. (2017). *Hunting SIP Authentication Attacks Efficiently*. AIMS 2017, pp. 125–130. [DOI](https://doi.org/10.1007/978-3-319-60774-0_9). Full publisher text read, especially Sections 2–4. | Distinguish attempted account diversity from repeated password failures; consider source/account relationships and shared NAT. Distributed detection is described, not observed. |
| S2 | Čejka, T., Bartoš, V., Truxa, L., & Kubátová, H. (2015). *Using Application-Aware Flow Monitoring for SIP Fraud Detection*. AIMS 2015, pp. 87–99. [DOI](https://doi.org/10.1007/978-3-319-20034-7_10). Publisher abstract read; full chapter subscription-restricted. | Application information is necessary for interpreting toll-fraud attempts against poorly configured PBXs. Supports a separate authorized-destination endpoint. |
| S3 | Nassar, M., State, R., & Festor, O. (2010). *Labeled VoIP Data-Set for Intrusion Detection Evaluation*. EUNICE 2010, pp. 97–106. [DOI](https://doi.org/10.1007/978-3-642-13971-0_10); [full IFIP paper](https://opendl.ifip-tc6.org/db/conf/ifip6-6/eunice2010/NassarSF10.pdf). Full paper read. | Correlate traffic, server logs and CDRs; preserve scenario metadata; vary normal profiles and mixed traffic. Paper also warns about limits of transaction-oriented traffic generation. |
| S4 | Alvares, C., Dinesh, D., Alvi, S., Gautam, T., Hasib, M., & Raza, A. (2021). *Dataset of attacks on a live enterprise VoIP network for machine learning based intrusion detection and prevention systems*. Computer Networks 197, 108283. [DOI](https://doi.org/10.1016/j.comnet.2021.108283); [author university record](https://researchportal.hw.ac.uk/en/publications/dataset-of-attacks-on-a-live-enterprise-voip-network-for-machine-/). University abstract/metadata read; publisher full text blocked. | Supports retaining attack sub-datasets and raw captures. Exact downloadable raw archive and complete attack inventory not verified in this session. |
| S5 | Nazih, W., Hifny, Y., Elkilani, W. S., Dhahri, H., & Abdelkader, T. (2020). *Countering DDoS Attacks in SIP Based VoIP Networks Using Recurrent Neural Networks*. Sensors 20(20), 5875. [DOI](https://doi.org/10.3390/s20205875); [primary paper record](https://pmc.ncbi.nlm.nih.gov/articles/PMC7589981/). Indexed primary text/abstract retrieved; direct page had a verification wall. | Low/high intensity and varied duration need separate tests and balanced normal controls. This is flooding research, not proof that recovery timing identifies fraud intent. |
| S6 | Sbai, O., Allaert, B., Sondi, P., & Meddahi, A. (2026). *SIP-DDoS framework based on federated learning for collaborative anomaly detection*. Cybersecurity 9, 109. Published 21 January 2026. [DOI](https://doi.org/10.1186/s42400-025-00527-6); [authors' repository](https://github.com/ballaert/SIP-DDos). Full publisher text and repository read. | INVITE intensity, mixed/transition sequences and deployment-context variation. Its public data was audited separately below; no federated model was implemented here. |
| S7 | Naeem, M. M., Hussain, I., & Missen, M. M. S. (2020). *A survey on registration hijacking attack consequences and protection for session initiation protocol (SIP)*. Computer Networks 175, 107250. [DOI](https://doi.org/10.1016/j.comnet.2020.107250). Publisher search extract/abstract retrieved; full text blocked. | Justifies a future registration-binding test family. Contact change alone must not be labelled hijacking without an unauthorized replacement outcome. |
| S8 | Nazih, W., Alnowaiser, K., Eldesouky, E., & Youssef Atallah, O. (2023). *Detecting SPIT Attacks in VoIP Networks Using Convolutional Autoencoders: A Deep Learning Approach*. Applied Sciences 13(12), 6974. [DOI](https://doi.org/10.3390/app13126974); [author university record](https://psau.sa.elsevierpure.com/en/publications/detecting-spit-attacks-in-voip-networks-using-convolutional-autoe/). University abstract/metadata read. | SPIT is an unwanted-call endpoint; a normal campaign burst is a needed look-alike control. Specific public SPIT raw data was not obtained here. |

Protocol reference: Rosenberg et al. (2002), [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261), especially REGISTER/authentication and security considerations. Protocol validation must distinguish challenge, authenticated rejection and registration success.

Other screening outcomes:
- S3's historical raw-data URL http://webloria.loria.fr/~nassar/voip-dataset/ could not be retrieved. The accessible paper is not the raw dataset.
- [Yoro et al. (2025)](https://doi.org/10.1371/journal.pone.0326571) link an [SDN-DDoS dataset](https://data.mendeley.com/datasets/b7vw628825/1). Its SIP-specific authentication evidence was not established; it was not merged into our dataset.
- A community SIP GitHub dataset also surfaced, but publication/label provenance was not established; it was not used.
- There was no author contact or message sending.

## 4. Public data acquired and audited
Source chain: S6 paper footnote -> authors' repository README -> public ZIP.

[Author-linked download](https://www.dropbox.com/scl/fi/6fidlecyoijng71wsrzsn/SIP-Dataset.zip?rlkey=bkctnqrvukv97n0ztdnxklcj8&dl=1).

Archive: 77,609,891 bytes.
SHA-256: `c0a979e26aad75596139fad5f1d800bc70bf37d5b0cbbb94b800f59b23c7b8b6`.

| CSV | Message rows | Good | Attack |
|---|---:|---:|---:|
| sample_2_1_F.csv | 77,670 | 16,140 | 61,530 |
| sample_2_2_F.csv | 446,668 | 125,148 | 321,520 |
| sample_2_3_F.csv | 137,784 | 27,999 | 109,785 |
| sample_2_4_F.csv | 689,188 | 159,643 | 529,545 |
| Total | 1,351,310 | 328,930 | 1,022,380 |

All rows are INVITE messages. CSV parsing found no extra/missing fields. Timing extraction found no backward timestamps within any file. This is an INVITE message dataset: the archive contains no raw PCAPs, REGISTER transaction history, PBX authentication logs, CDRs or destination-permission records.

S6 describes six attack intensity levels: 10, 25, 50, 100, 500 and 1,000 INVITE messages/s. These are the publication's configured rates, not locally generated Pi loads. The downloaded CSVs contain Good and Attack message labels plus intensity sub-labels; mixed sequences are present. We did not reproduce its four-class or federated evaluation.

### Shortcut diagnostic
In all four CSVs, every Good row has Content-Length 134 and every Attack row has Content-Length 607. A mapping learned on file 1 classified all rows in files 2–4 correctly using this field alone. This is an observed generator-template shortcut, NOT evidence of a perfect real-world detector. The paper's supplied notebook uses other features; this diagnostic does not reproduce or explain the authors' model.

Exclude raw labels, sub-labels, sequence IDs, absolute dates, generator identity and template artifacts when building behavioral models. Split complete captures/sessions and audit overlapping windows.

## 5. Separate external timing-only ML baseline
Endpoint: the public dataset's per-message Good/Attack label, with Attack treated as positive.
It is NOT our registration-time fraud-intent endpoint.

Features, computed using current/prior timestamps only:
1. Time since preceding INVITE, capped at 10 seconds (first message: 0).
2. Number of INVITEs in the trailing one-second window, including the current message.
3. Number of INVITEs in the trailing ten-second window, including the current message.

No Source, From, To, Call-ID, Contact, Subject, Content-Length, Label, Sub_Label or Seq input.
Feature windows reset at each source file and never span training/evaluation files.

Model: DecisionTreeClassifier, max_depth=3, min_samples_leaf=50, class_weight=balanced, random_state=17; scikit-learn 1.8.0. Train file 1 only; freeze tree before predictions on files 2–4. No parameter search or adjustment after their results.

This is a RETROSPECTIVE whole-file benchmark. All file schemas/label counts had already been inspected. All data comes from one published synthetic setup; three different files do not establish independent real-world deployments. No external baseline was installed on the PBX.

| Evaluation CSV | Rows | Balanced accuracy | Precision | Recall | F1 | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| sample_2_2_F.csv | 446,668 | 91.44% | 98.37% | 86.56% | 92.09% | 4,608 | 43,227 |
| sample_2_3_F.csv | 137,784 | 96.67% | 98.94% | 97.44% | 98.18% | 1,148 | 2,814 |
| sample_2_4_F.csv | 689,188 | 96.82% | 98.87% | 97.31% | 98.09% | 5,880 | 14,227 |

For example, the lowest-rate Attack_VeryLow recall in file 2 is 14,001/17,320 = 80.84%; strong aggregate results still conceal missed low-rate messages.

External tree SHA-256: `07fb7bc225430e2859f6533f8f956fe45402e5616e3a65d22d002588171684ef`.
Results JSON SHA-256: `56fda269cead0946935fee4d2d4d69ed991e0da0df54ec0f9232be8e00aa41ae`.
The audit, exact trainer, protocol, model tree and results are preserved in the accompanying evidence package. The original external ZIP is not bundled; retrieve it from the source URL and verify its hash.

## 6. Eight new local registration cases
Manifest was written before traffic. The complete orchestration wrapper has its own hash, in addition to hashes of reused modules.

| Case | Assigned role | Rejected dialogs | Requested interval (s) | REGISTER success | V6 stages | Frozen ML priority (score) |
|---|---|---:|---:|---|---|---|
| DL001 | Authorized recovery/configuration | 6 | 6 | Yes | SUSPECTED_COMPROMISE | HIGHER (0.606089) |
| DL002 | Simulated abuse role | 6 | 6 | Yes | SUSPECTED_COMPROMISE | HIGHER (0.605190) |
| DL003 | Authorized recovery/configuration | 10 | 6 | No | AUTHENTICATION_ATTACK | Not eligible |
| DL004 | Simulated abuse role | 10 | 6 | No | AUTHENTICATION_ATTACK | Not eligible |
| DL005 | Authorized recovery/configuration | 10 | 3 | Yes | AUTHENTICATION_ATTACK → SUSPECTED_COMPROMISE | HIGHER (0.732688) |
| DL006 | Simulated abuse role | 10 | 3 | Yes | AUTHENTICATION_ATTACK → SUSPECTED_COMPROMISE | HIGHER (0.732534) |
| DL007 | Authorized recovery/configuration | 5 | 1 | Yes | SUSPECTED_COMPROMISE | LOWER (0.392518) |
| DL008 | Simulated abuse role | 5 | 1 | Yes | SUSPECTED_COMPROMISE | LOWER (0.393029) |

Evidence gate: exact rejected-dialog count against Asterisk failure logs, protocol-aware V5 counts, expected REGISTER 200 count, PCAP hash, unchanged CDR, absent temporary routes and idle postflight. All eight passed.

The wrong-password template uses one fixed incorrect lab password. These cases emulate rejected authentication; they are not a real dictionary attack. Success cases use a supplied correct lab credential. No identity was compromised.

Actual timing is measured from packets, not assumed from requested scheduling. For example DL007 requested one-second starts but six-second-plus failure span resulted because each SSH/SIP dialog had to finish. Stored feature vectors contain measured spans.

Six cases met the existing ML gate: first successful REGISTER following at least five confirmed failures within 120 seconds. DL003/DL004 had no success and are detector controls, not eligible registration-time ML rows.

All four matched profile pairs received identical V6 stages and the same ML priority categories despite opposite assigned roles. Two authorized profiles received HIGHER priority; one simulated-abuse profile received LOWER priority. These scores are uncalibrated review scores, not probabilities of actual fraud.

Do not randomly split these eight cases. Matched profiles share a group; the entire session shares one source/account environment. They are development data, not a fresh held-out test. No new LOCAL registration model was trained.

## 7. REGISTER identity probes and exploratory candidate
All targets 9001–9006 were checked as unconfigured before the test. Each case sent six unauthenticated REGISTER requests at about one request/s, received six 401 responses, produced no calls or new CDRs, and passed capture/dialog/target checks.

| Case | Control/probe | Unique attempted identities | Current V5/progression | Separate diversity candidate |
|---|---|---:|---|---|
| RE001 | Repeated unconfigured-identity control | 1 | No confirmed auth failures or progression alert | No alert |
| RE002 | Bounded identity-diversity probe | 6 | No confirmed auth failures or progression alert | Review at fifth distinct identity |

Candidate: five distinct attempted REGISTER identities from a source within 60 seconds; each source/Call-ID/identity dialog counted once. It does not use scenario labels, later responses, CDRs or ML scores.

Replay across 16 development captures (DL001–DL008, DV2001–DV2006, RE001–RE002): only RE002 emitted REGISTER_TARGET_DIVERSITY_REVIEW. Decision event was 4.002101 seconds after the first request in its window. This is archived event-time delay, NOT live processing/transport latency.

This candidate was created after inspecting the development gap. It remains separate from frozen V6 and has no prospective held-out result. Legitimate multi-account traffic behind a NAT/proxy is an untested false-alert challenge. A six-ID probe with uniform 401s does not demonstrate discovery of valid extensions.

## 8. F13–F28 status and prioritized work
The earlier suggested F numbers are proposed families; they do not replace canonical DL/RE IDs or imply that every family is completed.

| Proposed family | Actual status | Required next evidence |
|---|---|---|
| F13 normal recovery | Expanded by prior DV cases and this batch's authorized success profiles | Real phone/network recovery and independent sessions |
| F14 slow guessing | Bounded slow rejection simulations collected; fixed wrong password | Varied lab guesses, longer gaps/window boundaries and matched stale-device controls |
| F15 distributed guessing | Literature/design only | Multiple genuinely distinct source hosts/IPs with target-account aggregation |
| F16 account enumeration | Two unused-identity probe/control captures completed | Mixed known/unknown lab IDs and genuine multi-account benign controls |
| F17 scan plus guessing | Not collected as one combined scenario | Predeclared combined trace and benign provisioning look-alike |
| F18 successful credential attack | Only supplied-credential progression simulations | Independent authorization context; retain simulated label |
| F19 toll-fraud after login | Earlier isolated three-call bursts; no billed calls | Predeclared lab destination policy and separately observed authorization decisions |
| F20 registration hijacking | Not tested | Controlled unauthorized binding replacement and authorized contact-change control |
| F21 low-rate INVITE flood | Public timing benchmark completed; local validation pending | Safe capped LAN stimulus plus PBX response/availability measurements |
| F22 multi-rate REGISTER flood | Not tested | Rate-varied bounded load, normal re-registration control and resource metrics |
| F23 multi-rate INVITE flood | External data includes varied rates; Pi stress test pending | Local rate limits and service-impact endpoint |
| F24 mass re-registration | Not completed | Several legitimate identities/clients recovering concurrently |
| F25 legitimate outbound burst | Earlier three-call burst controls; narrow coverage | Different callers, destinations, durations and independent sessions |
| F26 SPIT | Literature justification only | Predeclared unwanted-call proxy label and matched permitted short-call control |
| F27 malformed signalling | Not tested | Isolated parser/validation robustness controls and preserved raw messages |
| F28 normal/attack transitions | External mixed sequence data audited; binary baseline only | Causal sequence/stage evaluation on predeclared new mixed lab traces |

Immediate priorities:
1. Validate REGISTER diversity against legitimate multi-account/shared-source controls, freeze a candidate, then collect new held-outs.
2. Add independently observed source/account and destination permissions. Freeze policy before traffic; never feed experiment labels into ML.
3. Separate three endpoints: suspicious authentication behavior; destination-policy violation at INVITE; abnormal traffic/availability impact.
4. Compare rules, direct policy checks and timing/context ML on the same eligible groups. Report abstentions and false alerts.
5. Use independent sessions/days/devices and an untouched prospective holdout before claiming a stronger local model.
6. Preserve H001–H010 and B006–B015 as already-inspected evidence. Never reuse them as fresh V2 tests.
7. Complete the two live implementation paths' latency/overhead comparison; the in-process path currently has only authentication-subset validation.

## 9. Later thesis additions
- Literature review: use the source matrix with the exact access limits; distinguish authentication scanning, toll fraud, flooding, SPIT and registration hijacking.
- Methodology: explain transaction-confirmed failures, causal feature availability, paired-role ambiguity, session grouping, archived versus live timing and external whole-file benchmarks.
- Implementation: document the separate REGISTER diversity candidate and its unvalidated NAT/shared-source limitation.
- Results: add the ten new local cases, six causal feature vectors, external timing baseline table and template-shortcut diagnostic in separate subsections.
- Discussion: keep the negative local intent result. Explain why more observations help coverage while identical permitted/unpermitted stimulus requires additional context.
- Limitations: one PBX/generator session, fixed wrong-password templates, supplied valid credentials, no billed fraud, source data without responses/CDRs and no new prospective evaluation.
- Avoid claims of all F13–F28 complete, 100% fraud detection, production readiness, live 4.002101-second latency, or improved local 6/10 accuracy.

## 10. Canonical paths and provenance
Pi root: /home/astrix/sip-fraud-research.
- datasets/literature-development-20261002/manifest.json, summary.json, causal_features.csv and development/DL001–DL008 evidence.
- datasets/register-enumeration-20261002/manifest.json, summary.json and RE001/RE002 evidence.
- datasets/register-diversity-candidate-20261002/protocol.json and results.json.
- scripts/literature_development_20261002.py.
- scripts/register_enumeration_20261002.py.
- scripts/register_diversity_candidate_20261002.py.
- LITERATURE_CHECKPOINT_20261002.md and appended MIGRATION_STATUS.md continuity entry.

| Item | SHA-256 |
|---|---|
| Frozen local causal model, unchanged | ece43b48eb1d98115c2796735c67fc80589f8ff85d51765e78d373e3079ee30d |
| New local manifest | c2a6d86edb81547a9ea9ed82c2b067dbde20d8c924c5cc9097b2e518282081c9 |
| New local wrapper | 785c47c38c53cda5321b9e323d86eb91435a9403eda86de4411f771f62a163fc |
| New local summary | 324aed12944429d83df08abb0bb4d92372c1c71bfe19c76790bb427a797b20bb |
| Enumeration manifest | f941d82a5ae008c7a925c676d47b25077aa14f41d29262e45b3618b03554431a |
| Enumeration wrapper | 49bc866c77229bdb6cd226152d5897dfc55707a5b96df4924126a4bf62cbe2a3 |
| Enumeration summary | 53b86531aabd597c46067e7942c9cfea76516fca7666ba8459b89b2b70600905 |
| Diversity candidate source | 21d9fc92a91ff37cb83d2ab289e33dbaff48728e1211186ad823250d489e4b79 |

Prior audit warning remains: the current train_causal_review_model.py source differed from its original recorded trainer hash and some original output files were absent. Earlier numerical reconstruction reproduced the frozen model, but does not resolve source identity. Do not rewrite old metadata. This batch's standalone wrappers are preserved and hashed separately.

## 11. Resume instructions
Read this checkpoint, then MIGRATION_STATUS.md. Inspect access and idle state before new traffic. Do not rerun either completed batch into its existing directory. Use new IDs/directories/manifests for new experiments. Keep old V5/V6 and both frozen local models unchanged. New diversity logic is exploratory; external timing-tree performance must remain separate from local authorization-intent evaluation.
