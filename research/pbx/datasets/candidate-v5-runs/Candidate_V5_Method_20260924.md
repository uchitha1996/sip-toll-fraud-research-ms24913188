# Candidate V5 development rule and held-out protocol — 24 September 2026

**Status before new held-out traffic:** Candidate source on the Asterisk Pi has SHA-256 `e23ffd00ef931c23b1e2a4e9b0fccb6731d57025f94dbdc3a9045a75de825004`. The archived frozen V3 source SHA-256 is `579cdc61a40d1a0c8e340fc24109bb7097ed3de60296d5e58bbbee5d437d5d6a`. V3 remains untouched. This is a deterministic offline candidate, not a trained ML model or the full proposed adaptive architecture.

## Predeclared rule

1. Pair a REGISTER reply with the original request using Call-ID, CSeq number, REGISTER method and reversed packet source/destination. Only a final SIP response counts.
2. Ignore the first 401 challenge when the request has no digest username. Ignore a 401 response marked `stale=true`.
3. A 401/403 in response to a REGISTER with a digest username becomes a **pending** rejection. A 200 response for that same dialog cancels it. Count a pending rejection after one second without a successful retry; repeated challenges within that second replace the pending item. A later distinct rejected transaction with the same Call-ID can be counted again. Rejections whose one-second observation window was not captured remain unresolved.
4. Alert AUTHENTICATION_ATTACK when one source has **10 counted rejections in 60 seconds**. Record the 10-second failure count for analysis; do not use it to change the threshold. Retain V3's OPTIONS and INVITE thresholds for the other stages.
5. Use only safe extracted indicators (digest present and stale flag). Do not archive Authorization values, passwords or nonces in the output table. Keep PCAPs on the Asterisk Pi.

The one-second wait trades some detection speed for more confidence in the final rejection. A normal phone may retry later than one second, so this rule still needs more varied successful registrations before broad false-alert claims.

## Development evidence seen before freezing

- Two answered calls from 23 September: zero alerts, one stale challenge ignored, two REGISTER 200 responses.
- Separate-host 24 September OPTIONS 4/5: no alert / reconnaissance alert at request five (7.821911 s).
- Separate-host ten fast wrong-password dialogs: ten actual rejections counted, first candidate alert 4.106329 s after the first request. Frozen V3 alerted at 1.391449 s after counting five normal challenges as failures.
- Separate-host ten slow wrong-password dialogs: ten actual rejections counted, first candidate alert 46.850273 s; V3 missed them.
- Older loopback fast and slow captures stop too near the final responses for a full one-second observation. The candidate leaves respectively 3 and 1 attempts unresolved, so these captures do not verify the candidate's ten-rejection trigger. Preserve that limitation.

## Fresh cases fixed before generation

The next two separate-host captures will use extension **1002** and the same deliberately wrong lab password. They will have their own labels, SIPp logs, Asterisk auth-log excerpts, PCAPs, safe extracted SIP fields, CDR snapshots, frozen V3 replay and candidate replay.

| Case | Intent and expected boundary |
| --- | --- |
| `heldout-1002-10-paced` | Ten wrong-password dialogs launched separately without a fixed pause. Candidate should alert only after ten verified rejections within 60 s; compare when V3 alerts. |
| `heldout-1002-6-fast` | Six wrong-password dialogs at about three per second. Candidate should **not** reach its ten-rejection threshold; this is an attack the candidate is expected to miss. V3 may alert early by double-counting 401 challenges. |

These are selected lab cases from the same generator IP with a new SIP identity, not a population estimate. A passive capture of a real softphone has also been started as a possible additional normal control; if it records no successful registration, report that honestly rather than inventing a control.
