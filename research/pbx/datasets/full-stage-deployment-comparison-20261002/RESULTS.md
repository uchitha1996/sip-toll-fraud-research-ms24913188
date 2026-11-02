# Live native/external comparison — 2 October 2026

All seven declared cases passed independent capture and cleanup checks. B030 is a separate benign smoke case. Six primary cases contain 18 answered six-second lab calls.

| Case | Mode | Call setup median (ms) |
| --- | --- | ---: |
| B030 | INTERNAL | 15.765 |
| B031 | OFF | 15.71 |
| B032 | INTERNAL | 60.539 |
| B033 | EXTERNAL | 38.099 |
| B034 | EXTERNAL | 19.613 |
| B035 | INTERNAL | 43.35 |
| B036 | OFF | 12.9 |

| Stage | Native decision median (ms) | External decision median (ms) | n per path |
| --- | ---: | ---: | ---: |
| RECONNAISSANCE | 0.085 | 628.5 | 2 |
| AUTHENTICATION_ATTACK | 1015.987 | 1907.184 | 2 |
| SUSPECTED_COMPROMISE | 4.709 | 394.017 | 2 |
| SUSPECTED_OUTBOUND_ATTEMPT | 0.09 | 522.112 | 6 |
| CALL_BURST | 0.091 | 640.665 | 2 |

| Case | Whole-PBX mean CPU (% of one core) | Whole-PBX peak RSS (MiB) |
| --- | ---: | ---: |
| B030 | 0.258 | 99.234 |
| B031 | 0.205 | 98.469 |
| B032 | 0.217 | 98.469 |
| B033 | 0.204 | 98.469 |
| B034 | 0.22 | 98.469 |
| B035 | 0.204 | 98.969 |
| B036 | 0.199 | 98.969 |

Native and external outputs matched the declared stages and frozen ML tolerances. Each primary enabled case emitted seven alerts covering five distinct stages. Benign B030 produced CALL_BURST, illustrating that an alert identifies behaviour rather than proven abuse.

Limitations:

- Two cases per deployment mode; no statistical causal overhead conclusion.
- Stage-specific clocks/onsets: recovery uses authenticated REGISTER request, other stages use the causative packet event.
- One-second authentication rejection grace is part of both paths, not computation overhead.
- Native observation uses 250 ms logger polling; external observation is collector receipt.
- CPU/RSS includes capture and instrumentation; native RSS is entire Asterisk, external python3 processes combine service/collector. Samples cannot isolate module memory or exact per-event CPU.
- All cases are authorized development stimuli; ML is frozen exploratory priority metadata.
- Five online stages; answered CDR corroboration remains retrospective.

Additional observations:

| Enabled case | Frozen ML probability | Review priority |
| --- | ---: | --- |
| B032 | 0.6909 | HIGHER |
| B033 | 0.6802 | HIGHER |
| B034 | 0.6855 | HIGHER |
| B035 | 0.6832 | HIGHER |

All four enabled primary cases were authorized, yet received HIGHER review priority. This is exploratory behaviour scoring on a development workload, not evidence of fraud or improved classification accuracy.

The external tshark process reached 151.969 MiB peak RSS in each external case; the two Python processes individually peaked around 17–18 MiB. These are per-process RSS figures, not unique combined memory. Whole-PBX CPU stayed around 0.20–0.22% of one core in primary cases. CPU tick quantization, shared-memory accounting, and allocator/cache carryover without PBX restarts limit interpretation.

Native primary case setup medians (60.539 and 43.350 ms) were above the OFF baselines (15.710 and 12.900 ms). These descriptive results must be reported alongside faster alert decisions; the pilot does not establish a causal call-setup penalty or zero overhead.
