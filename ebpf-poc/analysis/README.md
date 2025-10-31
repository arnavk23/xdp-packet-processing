# Parse PoC telemetry

Usage:

```sh
python3 parse_telemetry.py /path/to/ebpf_telemetry.log /path/to/out.csv
```

- The script looks for lines like: "pid 153721: 599 pkts" and computes per-sample deltas
  (assumes the PoC printed totals at a fixed 1s interval) or it can parse CSV lines
  produced by the PoC (timestamp,pid,total[,interval_seconds]). The CSV output contains columns:
  `sample_idx,timestamp,pid,total,delta`

Notes:
- If your PoC used a different interval, either include it as the optional fourth CSV column per-line, or
  include a header line at the top of the CSV: `# interval_seconds=<n>`. The parser will use that to
  normalize deltas to pps.

Plotting:
- See `ebpf-poc/analysis/plot_telemetry.py` to create a PNG from the parsed CSV. Example:

```sh
python3 ebpf-poc/analysis/plot_telemetry.py /tmp/ebpf_parsed_live.csv /tmp/telemetry.png
```
