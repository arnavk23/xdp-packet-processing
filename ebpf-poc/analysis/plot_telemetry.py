#!/usr/bin/env python3
"""
Plot telemetry CSV produced by parse_telemetry.py (/ parsed CSV) and save PNG.
Usage:
  python3 plot_telemetry.py /path/to/parsed.csv /path/to/out.png

If matplotlib is not installed, prints instructions to install it.
"""
import sys
import csv
from datetime import datetime

try:
    import matplotlib.pyplot as plt
except Exception:
    plt = None


def read_parsed_csv(path):
    rows = []
    with open(path) as f:
        r = csv.reader(f)
        header = next(r, None)
        for row in r:
            if not row:
                continue
            # expected: sample_idx,timestamp,pid,total,delta
            try:
                idx = int(row[0])
                ts = row[1]
                pid = int(row[2])
                total = int(row[3])
                delta = row[4]
                delta = int(delta) if delta != '' else None
                rows.append((idx, ts, pid, total, delta))
            except Exception:
                continue
    return rows


def main():
    if len(sys.argv) < 2:
        print('Usage: plot_telemetry.py /path/to/parsed.csv [/path/to/out.png]')
        sys.exit(2)
    path = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) >= 3 else '/tmp/telemetry_pps.png'

    rows = read_parsed_csv(path)
    if not rows:
        print('No data in parsed CSV')
        sys.exit(1)

    # prefer delta column; if missing compute from totals
    deltas = [r[4] for r in rows]
    if any(d is None for d in deltas):
        totals = [r[3] for r in rows]
        deltas = [totals[i] - totals[i-1] for i in range(1, len(totals))]
        xs = list(range(1, len(totals)))
    else:
        deltas = [int(d) for d in deltas]
        xs = [r[0] for r in rows]

    if plt is None:
        print('matplotlib not available. To install:')
        print('  python3 -m pip install --user matplotlib')
        print('Or install via your distro package manager (e.g., apt install python3-matplotlib)')
        sys.exit(1)

    plt.figure(figsize=(10,4))
    plt.plot(xs, deltas, marker='o')
    plt.xlabel('sample')
    plt.ylabel('packets per interval')
    plt.title('Telemetry — packets per interval')
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(out)
    print('Saved plot to', out)


if __name__ == '__main__':
    main()
