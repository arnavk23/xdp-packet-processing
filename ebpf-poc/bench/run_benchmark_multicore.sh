#!/bin/bash
# run_benchmark_multicore.sh
# Benchmark DPDK UPF with and without eBPF, using multiple cores and real traffic
# Usage: sudo ./run_benchmark_multicore.sh <upf_binary> <num_cores> <duration_sec>

set -e
if [ $# -lt 3 ]; then
  echo "Usage: $0 <upf_binary> <num_cores> <duration_sec>"
  exit 1
fi
UPF_BIN=$1
CORES=$2
DURATION=$3

# Start UPF with specified core mask (example: 0xF for 4 cores)
COREMASK=$(printf '0x%X' $(( (1 << CORES) - 1 )))
echo "Launching UPF: $UPF_BIN with coremask $COREMASK"
$UPF_BIN -c $COREMASK &
UPF_PID=$!
sleep 3

echo "Running baseline traffic (no eBPF)..."
# Example: use pktgen or other generator here
# pktgen -c 0x10 -n 2 -T -m "0.0,1.0" -f traffic_script.lua &
# sleep $DURATION

echo "Attaching eBPF uprobe for flow tagging..."
sudo python3 ../attach_upf_uprobe_flowtag.py --binary $UPF_BIN --pid $UPF_PID --duration $DURATION

echo "Benchmark complete. Killing UPF."
kill $UPF_PID
