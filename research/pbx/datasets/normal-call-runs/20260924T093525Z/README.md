# Seven real answered internal calls — 24 September 2026

Manual five-minute capture on Asterisk Pi 172.16.200.81, wlan0, started 09:35:25 UTC; the separate generator Pi 172.16.200.68 was excluded by the packet filter. The user made ordinary calls between real softphones 1001 (172.16.200.67) and 1002 (172.16.200.39).

- Raw PCAP: 168 UDP/5060 packets, 141 decoded SIP packets. SHA-256: 0c78d98d7d6dc3ae110a8c2afbdac6b9e9f93171500100397cb032a2748ed1a3.
- The before/after CDR files share an identical prefix. Exactly seven new records are ANSWERED: five 1001->1002 and two 1002->1001. Billed talk times are 8, 5, 1, 2, 2, 3 and 3 seconds.
- Each independently labelled CDR matches a separate client-originated SIP INVITE dialog with 200 OK, ACK and BYE in the capture. The SIP records include 9 REGISTER requests with four 401 challenges and five 200 successes. 1001 registered within the capture; contacts_before lists only 1002.
- Ground truth is the seven new ANSWERED CDRs, independently matched to completed SIP dialogs. scenario_ground_truth.csv was created before replaying either detector.
- Frozen V3 replay (SHA-256 579cdc61a40d1a0c8e340fc24109bb7097ed3de60296d5e58bbbee5d437d5d6a): 30 relevant SIP requests, all NORMAL, zero attack alerts, seven new CDR rows. The 30 requests include multiple signalling requests and PBX call legs; they are not 30 independent calls.
- Frozen V5 candidate (SHA-256 e23ffd00ef931c23b1e2a4e9b0fccb6731d57025f94dbdc3a9045a75de825004): 30 relevant requests, zero attack alerts, five successful REGISTER 200 responses, three stale challenges ignored and one initial unauthenticated 401 ignored. Its replay summary is in datasets/candidate-v5-runs/20260924T093525Z-normal7/.
- The capture includes only seven calls between two users on one LAN. Short talk times and this selected control cannot estimate production false-positive rates. No external toll call or compromised account was created by this run.

Raw normal_calls.pcap may contain SIP authentication data and stays restricted on the Pi. sip_packets.csv omits Authorization headers and digest fields.
