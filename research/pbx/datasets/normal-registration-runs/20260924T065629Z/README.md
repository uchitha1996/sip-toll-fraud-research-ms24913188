# Passive real-phone control attempt — 24 September 2026

Captured UDP port 5060 traffic only between softphone 172.16.200.39 and Asterisk 172.16.200.81 on wlan0 for 180 seconds. The PCAP contains 13 UDP packets, but tshark decodes **zero SIP packets**, so there is no observed REGISTER or completed call in this capture. This run is excluded from V3/V5 evaluation. The raw PCAP is restricted to the Asterisk Pi.
