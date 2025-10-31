set -euo pipefail

# Helper to sample interface counters and process CPU usage once (for debugging)
if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <iface> <pid> <outfile>"
  exit 1
fi

IFACE="$1"
PID="$2"
OUTFILE="$3"

echo "timestamp,rx_bytes,tx_bytes,upf_cpu" > "$OUTFILE"
for i in {1..10}; do
  ts=$(date +%s)
  rx=$(cat /sys/class/net/$IFACE/statistics/rx_bytes)
  tx=$(cat /sys/class/net/$IFACE/statistics/tx_bytes)
  cpu=$(ps -p $PID -o %cpu= || echo 0)
  echo "$ts,$rx,$tx,$cpu" >> "$OUTFILE"
  sleep 1
done
