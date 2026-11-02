#!/bin/bash
set -euo pipefail
BASE="/home/astrix/sip-fraud-research"
DATA="$BASE/datasets"; CAP="$BASE/captures"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$DATA/robustness-runs/$RUN_ID"
PCAP="$CAP/v4-$RUN_ID.pcap"
mkdir -p "$RUN_DIR" "$CAP"

echo "========================================"
echo " V4 ROBUSTNESS EXPERIMENT"
echo " Run: $RUN_ID"
echo "========================================"
echo "[1/6] Starting capture"
tcpdump -i lo -n -s0 udp port 5060 -w "$PCAP" >"$RUN_DIR/tcpdump.log" 2>&1 &
PID=$!
cleanup(){ if kill -0 "$PID" 2>/dev/null; then kill -INT "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi; }
trap cleanup EXIT
sleep 2
echo "[2/6] Running robustness scenarios"
python3 "$BASE/scripts/generate_robustness_v4.py" | tee "$RUN_DIR/generator_console.txt"
sleep 2

echo "[3/6] Stopping capture"
kill -INT "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
trap - EXIT

echo "[4/6] Extracting SIP packets"
tshark -r "$PCAP" -Y sip -T fields \
 -e frame.time_epoch -e ip.src -e ip.dst -e sip.Method -e sip.Status-Code \
 -e sip.CSeq.method -e sip.Call-ID -e sip.from.user -e sip.to.user -e sip.r-uri.user \
 -E header=y -E separator=, -E quote=d > "$DATA/sip_packets_v4.csv"

echo "[5/6] Running detector"
python3 "$BASE/scripts/stage_detector_v4.py" | tee "$RUN_DIR/detector_console.txt"
echo "[6/6] Saving evidence"
for f in ground_truth_events_v4.csv sip_packets_v4.csv stage_detection_timeline_v4.csv stage_detection_summary_v4.csv stage_detection_metrics_v4.csv; do
  cp "$DATA/$f" "$RUN_DIR/"
done
cp "$BASE/scripts/generate_robustness_v4.py" "$RUN_DIR/"
cp "$BASE/scripts/stage_detector_v4.py" "$RUN_DIR/"

echo
echo "========================================"
echo " V4 ROBUSTNESS RUN COMPLETE"
echo "========================================"
echo "$RUN_DIR"
echo
echo "=== COUNTS ==="
wc -l "$RUN_DIR/ground_truth_events_v4.csv" "$RUN_DIR/sip_packets_v4.csv" "$RUN_DIR/stage_detection_timeline_v4.csv"
echo
echo "=== METRICS ==="
cat "$RUN_DIR/stage_detection_metrics_v4.csv"
echo
echo "=== SCENARIO SUMMARY ==="
cat "$RUN_DIR/stage_detection_summary_v4.csv"
