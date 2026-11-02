# Normal SIP registration capture — 24 September 2026

Observation: 09:14:28–09:19:28 UTC on Asterisk Pi 172.16.200.81, wlan0. The user was asked to re-register 1001 and 1002 and place several answered internal calls. The expected 1001 registration and calls did not occur during this window.

- tcpdump closed cleanly after 300 seconds: 26 UDP/5060 packets captured, 0 kernel drops. PCAP SHA-256: 02089563ef0cbcbc0b587a120f153cdb57fac1fb8397723d9832982e05b5fb44.
- Four packets decode as SIP: 1002 at 172.16.200.39 sent REGISTER CSeq 46985, received 401, retried with CSeq 46986 and received 200 OK at 09:17:53 UTC.
- No decoded SIP packet identifies 1001, and no INVITE was captured. PJSIP contacts before and after list only 1002. CDR CSV was byte-for-byte unchanged (0 new calls).
- Independent observed ground truth: one successful, ordinary 1002 registration. No ground truth for answered calls was assigned.
- Frozen V3 SHA-256 579cdc61a40d1a0c8e340fc24109bb7097ed3de60296d5e58bbbee5d437d5d6a: 2 REGISTER requests, 0 alerts; it counts the initial 401 as one failed REGISTER even though the retry succeeded.
- Frozen V5 candidate SHA-256 e23ffd00ef931c23b1e2a4e9b0fccb6731d57025f94dbdc3a9045a75de825004: 2 requests, 1 ignored unauthenticated challenge, 1 successful REGISTER 200, 0 confirmed rejections, 0 alerts.
- All raw PCAP and detailed event timelines remain restricted on the Pi because SIP authentication data may be present. This run supports only a normal successful registration control; it cannot estimate false-positive rates or completed-call detection.

The capture filter excluded the separate generator Pi 172.16.200.68. It was not a full network capture; absence of 1001 packets means only that none matched the PBX SIP/UDP filter in this timed window.
