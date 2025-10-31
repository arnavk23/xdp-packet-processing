set -euo pipefail

# Lightweight benchmark harness to collect interface counters and UPF CPU usage
OUTDIR="$(dirname "$0")/results-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"

print_usage(){
  cat <<EOF
Usage: $0 --upf-pid PID --iface IFACE --duration SEC --traffic-cmd "CMD" --mode baseline|ebpf
Examples:
  $0 --upf-pid 1234 --iface eth0 --duration 60 --traffic-cmd "iperf3 -c 10.0.0.2 -t 60" --mode baseline
EOF
}

UPF_PID=""
IFACE=""
DURATION=30
TRAFFIC_CMD=""
MODE="baseline"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --upf-pid) UPF_PID="$2"; shift 2;;
    --iface) IFACE="$2"; shift 2;;
    --duration) DURATION="$2"; shift 2;;
    --traffic-cmd) TRAFFIC_CMD="$2"; shift 2;;
    --mode) MODE="$2"; shift 2;;
    -h|--help) print_usage; exit 0;;
    *) echo "Unknown arg $1"; print_usage; exit 1;;
  esac
done

if [[ -z "$UPF_PID" || -z "$IFACE" || -z "$TRAFFIC_CMD" ]]; then
  print_usage; exit 1
fi

echo "Running benchmark: mode=$MODE, upf_pid=$UPF_PID, iface=$IFACE, duration=$DURATION"

OUT_METRICS="$OUTDIR/metrics.csv"
echo "timestamp,rx_bytes,tx_bytes,upf_cpu_percent" > "$OUT_METRICS"

SAMPLE_INTERVAL=1
END=$(( $(date +%s) + DURATION ))

echo "Starting traffic: $TRAFFIC_CMD"
# Run traffic in background
bash -c "$TRAFFIC_CMD" &
TRAFFIC_PID=$!

while [[ $(date +%s) -lt $END ]]; do
  ts=$(date +%s)
  # read interface counters
  rx_bytes=$(cat /sys/class/net/$IFACE/statistics/rx_bytes)
  tx_bytes=$(cat /sys/class/net/$IFACE/statistics/tx_bytes)
  # read UPF CPU (user+system) % via ps
  upf_cpu=$(ps -p $UPF_PID -o %cpu= || echo 0)
  echo "$ts,$rx_bytes,$tx_bytes,$upf_cpu" >> "$OUT_METRICS"
  sleep $SAMPLE_INTERVAL
done

echo "Benchmark finished. Results in $OUTDIR"
echo "Metrics file: $OUT_METRICS"
