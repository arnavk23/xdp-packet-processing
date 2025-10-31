"""
Simple parser for the PoC telemetry output.
Supports two input styles:
 - human-readable output with lines like: "pid 153721: 599 pkts"
 - CSV lines written by the PoC when run with --log-csv: timestamp_iso,pid,total

The script auto-detects format and computes per-sample deltas (pps). It can write
an output CSV with columns: sample_idx,timestamp,pid,total,delta
"""
import sys
import re
import csv
from statistics import mean, median, stdev
from datetime import datetime

PAT = re.compile(r"pid\s+(\d+):\s+(\d+)\s+pkts")


def parse_file(path):
    """Parse either human-readable or CSV telemetry files.

    Returns (samples, interval_seconds) where samples is a list of (timestamp_or_empty, pid, total).
    """
    samples = []  # list of (ts, pid, total)
    interval = 1
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # header line with metadata: # interval_seconds=NN
            if line.startswith('#'):
                # try to parse interval
                try:
                    if 'interval_seconds=' in line:
                        part = line.split('interval_seconds=')[-1].strip()
                        interval = int(part)
                except Exception:
                    pass
                continue
            # CSV style: timestamp,pid,total
            if ',' in line:
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 3:
                    ts = parts[0]
                    try:
                        pid = int(parts[1])
                        total = int(parts[2])
                        # optional per-line interval_seconds column
                        if len(parts) >= 4:
                            try:
                                interval = int(parts[3])
                            except Exception:
                                pass
                        samples.append((ts, pid, total))
                        continue
                    except Exception:
                        # fall through to try human readable parse
                        pass

            # Human-readable style: look for "pid <n>: <m> pkts"
            m = PAT.search(line)
            if m:
                pid = int(m.group(1))
                total = int(m.group(2))
                samples.append(("", pid, total))
    return samples, interval


def analyze(samples, interval_seconds=1, out_csv=None):
    if not samples:
        print('No samples found in file.')
        return 1

    # assume single pid (most use case). Group preserving order for that pid.
    pid0 = samples[0][1]
    filtered = [(ts, p, t) for (ts, p, t) in samples if p == pid0]
    totals = [t for (ts, p, t) in filtered]
    deltas = [totals[i] - totals[i-1] for i in range(1, len(totals))]

    print(f'Samples: {len(totals)}')
    print(f'Interval seconds (from header or default): {interval_seconds}')
    print(f'Total packets observed: {totals[-1] - totals[0]}')
    if deltas:
        # normalize to pps using interval_seconds
        pps = [d / interval_seconds for d in deltas]
        print('Per-sample (normalized to pps) stats:')
        print(' mean pps: {:.1f}'.format(mean(pps)))
        print(' median pps: {:.1f}'.format(median(pps)))
        print(' min pps: {:.1f}'.format(min(pps)))
        print(' max pps: {:.1f}'.format(max(pps)))
        if len(pps) > 1:
            print(' stddev pps: {:.1f}'.format(stdev(pps)))
    else:
        print('Not enough samples to compute deltas (need >=2).')

    if out_csv:
        with open(out_csv, 'w', newline='') as csvf:
            writer = csv.writer(csvf)
            writer.writerow(['sample_idx', 'timestamp', 'pid', 'total', 'delta'])
            prev = None
            for i, (ts, p, t) in enumerate(filtered):
                delta = ''
                if prev is not None:
                    delta = t - prev[3]
                writer.writerow([i, ts, p, t, delta])
                prev = (i, ts, p, t)
        print('CSV written to', out_csv)
    return 0


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: parse_telemetry.py <telemetry_log> [out.csv]')
        sys.exit(2)
    path = sys.argv[1]
    out = None
    if len(sys.argv) >= 3:
        out = sys.argv[2]
    samples, interval = parse_file(path)
    # ensure interval is int
    try:
        interval = int(interval)
    except Exception:
        interval = 1
    sys.exit(analyze(samples, interval, out))
