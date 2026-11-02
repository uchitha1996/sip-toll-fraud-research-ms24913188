#!/bin/bash
set -euo pipefail

BASE="/home/astrix/sip-fraud-research"
DATA="$BASE/datasets"
CAP="$BASE/captures"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$DATA/runs/$RUN_ID"
PCAP="$CAP/v3-$RUN_ID.pcap"

mkdir -p "$RUN_DIR" "$CAP"

echo "========================================"
echo " V3 RASPBERRY PI EXPERIMENT"
echo " Run: $RUN_ID"
echo "========================================"

echo "[1/6] Starting SIP packet capture on loopback"
tcpdump -i lo -n -s0 udp port 5060 -w "$PCAP" >"$RUN_DIR/tcpdump.log" 2>&1 &
PID=$!
cleanup() {
  if kill -0 "$PID" 2>/dev/null; then
    kill -INT "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT
sleep 2

echo "[2/6] Generating the 50-event Azure V3 baseline"
python3 "$BASE/scripts/generate_sip_traffic.py" | tee "$RUN_DIR/generator_console.txt"
sleep 2

echo "[3/6] Stopping packet capture"
kill -INT "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
trap - EXIT

echo "[4/6] Converting PCAP to detector CSV"
tshark -r "$PCAP" -Y sip -T fields \
  -e frame.time_epoch -e ip.src -e ip.dst \
  -e sip.Method -e sip.Status-Code -e sip.CSeq.method \
  -e sip.Call-ID -e sip.from.user -e sip.to.user -e sip.r-uri.user \
  -E header=y -E separator=, -E quote=d \
  > "$DATA/sip_packets_v2.csv"

echo "[5/6] Running V3 stage detector"
python3 "$BASE/scripts/stage_detector_v3.py" | tee "$RUN_DIR/detector_console.txt"

echo "[6/6] Archiving experiment evidence"
cp "$DATA/ground_truth_events.csv" "$RUN_DIR/"
cp "$DATA/sip_packets_v2.csv" "$RUN_DIR/"
cp "$DATA/stage_detection_timeline_v3.csv" "$RUN_DIR/"
cp "$DATA/stage_detection_summary_v3.csv" "$RUN_DIR/"
cp "$DATA/stage_detection_metrics_v3.csv" "$RUN_DIR/"
cp "$BASE/scripts/generate_sip_traffic.py" "$RUN_DIR/"
cp "$BASE/scripts/stage_detector_v3.py" "$RUN_DIR/"

echo
echo "Run directory: $RUN_DIR"
echo "Ground truth rows: $(wc -l < "$RUN_DIR/ground_truth_events.csv")"
echo "SIP packet rows: $(wc -l < "$RUN_DIR/sip_packets_v2.csv")"
echo
cat "$RUN_DIR/stage_detection_metrics_v3.csv"
