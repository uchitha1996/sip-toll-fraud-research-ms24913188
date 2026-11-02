# In-process SIP auth validation — 1 October 2026

The installed module matched SHA-256 02160968346541cc7ca45b848758a269275567707dd1fb54fb1c31c518f3bb26. It loaded successfully into Asterisk 20.6.0 with clean account counters.

| Fresh case | Traffic | Live in-process result | Independent checks |
|---|---|---|---|
| A000 | Valid registration only | No alert; zero failures | PASS |
| A001 | Ten wrong-password registration dialogs | Ten failures; one AUTHENTICATION_ATTACK alert | PASS |
| A002 | Six wrong-password dialogs, then valid registration | Six failures; one SUSPECTED_COMPROMISE review alert | PASS |

All cases used generator 172.16.200.68 and account 1002. Account 1001 stayed unaffected. Packet counts, successful registration counts, failed-auth log counts and module counters matched. No INVITEs, calls, routing changes or new CDRs were generated.
Predeclared manifest SHA-256: 781d9b9bcf8766a8f207df0bed547727ada0eca19581e1c07d4ea6e211d01455.
Live verification summary SHA-256: f99b2a5965ffa5d06bb29ae2a07657711d7d55507e40b7879ac7c398a0be92b4.

## External-engine comparison on the same captures
The frozen V5 protocol-aware adapter and external progression engine replayed the three captures and matched all three live in-process auth-stage results.
Corrected replay summary SHA-256: 45d0a7e63086987a4e2129778d60d1aefb4eafc11f93d9d6dca4efc7a9e83929.

The first replay was preserved under external_auth_parity. Its default PCAP modification-time endpoint left the tenth A001 rejection unresolved: the PCAP was last flushed at 11:15:43.725 UTC, but the rejection required observation through 11:15:44.096 UTC. The capture termination log was written at 11:15:45.917 UTC.
A separate replay under external_auth_parity_capture_end explicitly used the tcpdump termination-log filesystem timestamp. This is recorded metadata, not an invented packet. It allowed the already-observed silent grace interval to be included. The frozen detector sources and captures were not changed. Future experiments should record capture-stop UTC explicitly, independently of PCAP write time.

## What this establishes
The in-process authentication observer can receive real Asterisk security events and distinguish normal registration challenges from actual wrong-password failures in these declared templates. Its auth-stage outputs agree with external archived replay for this small set.
It does not establish full progression/ML equivalence, live two-path latency or overhead, confirmed compromise, production accuracy or H3. The C module observes authentication only; its success event is an Asterisk authentication event, not a generic packet-based REGISTER-only classifier.

## Next work
1. Add explicit event observation/decision timestamps and capture-stop timestamps before a new paired live latency experiment.
2. Compare the same auth-stage endpoint under both live paths and measure resources with background work excluded.
3. Extend in-process coverage or clearly restrict the deployment comparison to the shared auth-stage subset.
4. Keep the negative matched-role ML finding and the broader dataset limitations in the thesis.

Final state: module unloaded after testing; zero active calls; temporary routes 88001/88002 absent. Installed binary remains available for the next declared test.
Canonical Pi evidence: /home/astrix/sip-fraud-research/datasets/inprocess-auth-validation-20261001/.

