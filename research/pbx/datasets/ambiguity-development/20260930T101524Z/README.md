# SIP Fraud Research — 30 September 2026 checkpoint

## Verified today
Both Pis connected: Asterisk 172.16.200.81 and SIPp 172.16.200.68. Asterisk had zero active calls before testing.
Two fresh separate-host development runs used matched stimuli: six wrong-password REGISTER dialogs at a planned 2-second interval, valid registration, and one isolated answered call to lab destination 88002.
Both independently verified: 44 SIP packets, six failed-auth log entries, one REGISTER success, one new ANSWERED CDR with six billable seconds, completed SIP call legs, no recorded cleanup errors.
V5 confirmed six rejected digest dialogs and raised no alert. V6 raised SUSPECTED_COMPROMISE, SUSPECTED_OUTBOUND_ATTEMPT, and ANSWERED_EMULATED_OUTBOUND in both cases.

## Interpretation
F05 represents scripted benign recovery; F11 represents simulated credential abuse. Their protocol stimuli were matched. The results demonstrate ambiguity for the present detector, not proven credential theft or real billed toll fraud. Packet IDs and runtime timing differ between executions; those differences do not establish intent.
The earlier F01–F12 evaluation remains unchanged. These two new runs are exploratory development evidence, excluded from final holdout and final accuracy claims.
Do not claim ML can solve this false alert merely by separating the original 12.29-second and 9.73-second failure spans. Whole-run duration and completed-call CDR features also cannot support an earlier online alert without accounting for availability time.

## Next implementation
1. Build a parameterized generator retaining PCAP, SIP transaction evidence, independent labels, CDR and cleanup verification per run.
2. Cross benign and attack labels over overlapping rates, failure counts, accounts and durations. Include low-and-slow attacks, benign bursts and matched recovery cases.
3. Add measurable account/source history and destination deviation where supported. Retain an uncertain/suspicious outcome when observations do not establish intent.
4. Separate retrospective scenario classification from causal online detection and measure CDR availability latency.
5. Use grouped development splits; freeze model/preprocessing before collecting a new held-out set. Compare rules, ML and refinement, including false alerts and resource usage.
No ML model has been trained today. sklearn and pandas were not installed on this Pi at the check.
