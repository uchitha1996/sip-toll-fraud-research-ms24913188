# Five-stage deployment comparison — 2 October 2026

Status: compiled and archived regression checks passed. **Live comparison has not run.**

The new passive Asterisk 20.6.0 observer implements reconnaissance, authentication attack, suspected recovery, suspected outbound attempt and distinct-call burst. It adds the unchanged frozen causal ML score at REGISTER success. It restricts traffic to generator 172.16.200.68 and accounts 1001/1002. It has no call-control functions. Existing V5/V6, model, old module and captures remain unchanged.

Verified on Astrix-lab:

- 34 archived runs: 253 events, 37 alerts, identical ordered C/Python output.
- Ten previously evaluated recovery cases: 142 events, 52 alerts; matching stages, ML features and scores. This is regression evidence, not another holdout evaluation.
- Five authentication transaction fixtures and nine saved PCAPs: initial challenges, retry success, retransmission, stale digest and one-second rejection grace checked. Retained failed B024 remains excluded from the original pilot.
- ARM native module compiled with warnings treated as errors, except two warning classes in upstream headers. Required PJSIP provider exports were checked. Loading is still untested.

Predeclared next traffic:

| Case | Mode | Wrong passwords | OPTIONS targets | Calls |
| --- | --- | ---: | ---: | ---: |
| B030 | Native benign smoke | 0 | 1 repeated five times | 3 |
| B031 | OFF | 10 | 5 distinct | 3 |
| B032 | Native | 10 | 5 distinct | 3 |
| B033 | External | 10 | 5 distinct | 3 |
| B034 | External | 10 | 5 distinct | 3 |
| B035 | Native | 10 | 5 distinct | 3 |
| B036 | OFF | 10 | 5 distinct | 3 |

All cases are authorized development stimuli, not fresh fraud-classification holdout data. Wrong-password spacing is 2.1 seconds; both detectors use one-second confirmation grace. The existing isolated SIPp UAS route and unchanged independent verifier require three distinct completed SIP calls, three answered six-second CDRs, exact auth log counts and clean route removal. The new verifier additionally checks five-stage sequences, raw packet counts, capture drops, frozen ML and common packet timing. Any failure stops the batch and preserves its evidence; no automatic replacement case or rerun.

Report decision and observation latency separately for each stage, first generator INVITE to PBX 200, and sampled process CPU/RSS within matched packet windows. Native RSS is whole Asterisk memory; it does not isolate module allocation. The six primary cases have 18 calls; B030 is excluded from the primary comparison. WLAN and small sample sizes limit causal overhead conclusions. The ten-failure profile exceeds the model's original development profiles, so its score remains exploratory review metadata.

The live comparison covers **five online stages**. The answered-outbound CDR stage remains retrospective independent evidence. Do not describe this as live native CDR integration or improved fraud accuracy.

## Remaining local installation

The checked installer copies only this new module into the root-owned Asterisk module directory, verifies its exact hash, refuses a different existing target, and leaves it unloaded. It checks PBX idle and both routes absent. It changes no loader configuration.

Run locally on Astrix-lab:

```bash
sudo bash /home/astrix/sip-fraud-research/inprocess-full-lab/install_full_module_checked.sh
```

Expected native module SHA-256:
`84c30bcaf2d9f1db5336b06a91a3244752659239d6dd2ac56ea04431d84bb712`

After installation, the already authorized isolated comparison can proceed with:

```bash
cd /home/astrix/sip-fraud-research/inprocess-full-lab
python3 run_comparison.py
python3 -u run_comparison.py --execute
```

The first command is read-only. Execution loads the module only for native cases, runs one case at a time and unloads it in cleanup. Fresh evidence is written under `datasets/full-stage-deployment-comparison-20261002`; original raw call captures remain under the established burst development directory. Output creation is exclusive. Failed cases require investigation before declaring any new manifest.

This bundle contains source, protocol and archived verification reports. It intentionally omits compiled local x86 libraries; the verified ARM binaries remain on Astrix-lab. Rebuilding changes the installed-byte requirement unless the binary hash stays identical, so update all predeclared hashes before any traffic.
