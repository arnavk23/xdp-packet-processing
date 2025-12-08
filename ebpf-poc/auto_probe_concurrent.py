"""
Scan a target PID for candidate "RecvPackets"/rx functions across the main executable
and its mapped shared libraries, then try attaching the existing BCC PoC to each
candidate concurrently for a short interval.

Output: per-candidate logs and CSVs in the provided --out-dir and a JSON summary.

This is a safe harness: it supports `--dry-run` to list candidates without attaching.
"""
import argparse
import concurrent.futures
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

SYMBOL_RE = re.compile(r"(RecvPackets|rte_eth_rx_burst|recv_pkts|rx_burst)", re.IGNORECASE)


def mapped_files_for_pid(pid):
    files = set()
    maps = f"/proc/{pid}/maps"
    try:
        with open(maps, "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 6:
                    path = parts[-1]
                    if path.startswith("/"):
                        files.add(path)
    except Exception:
        logging.exception("Failed to read /proc/%s/maps", pid)
    # always include /proc/<pid>/exe
    exe = f"/proc/{pid}/exe"
    files.add(exe)
    return sorted(files)


def extract_symbols_from_file(path):
    """Run readelf -Ws <path> | c++filt and return matching symbol names."""
    try:
        cmd = ["/usr/bin/readelf", "-Ws", path]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        out = p.stdout
        # demangle
        try:
            p2 = subprocess.run(["/usr/bin/c++filt"], input=out, text=True, capture_output=True, timeout=5)
            out = p2.stdout
        except Exception:
            pass
        names = set()
        for line in out.splitlines():
            if not line.strip():
                continue
            # readelf symbol lines often have the name at the end
            parts = line.split()
            if parts:
                candidate = parts[-1]
                if SYMBOL_RE.search(candidate):
                    names.add(candidate)
        return sorted(names)
    except Exception:
        logging.debug("readelf failed on %s", path)
        return []


def build_candidates(pid):
    files = mapped_files_for_pid(pid)
    candidates = []
    seen = set()
    for f in files:
        syms = extract_symbols_from_file(f)
        for s in syms:
            key = (s, f)
            if key not in seen:
                seen.add(key)
                candidates.append({"symbol": s, "object": f})
    return candidates


def run_probe(pid, candidate, outdir, duration, try_shared, no_sudo):
    symbol = candidate["symbol"]
    obj = candidate["object"]
    safe_sym = re.sub(r"[^0-9A-Za-z_]+", "_", symbol)
    base = f"probe_{safe_sym}_{pid}"
    log_path = Path(outdir) / (base + ".log")
    csv_path = Path(outdir) / (base + ".csv")
    cmd = [sys.executable, "attach_upf_uprobe.py", "--binary", f"/proc/{pid}/exe", "--function", symbol, "--interval", "1", "--duration", str(duration), "--log-csv", str(csv_path)]
    if try_shared:
        cmd += ["--try-shared"]
    if not no_sudo and os.geteuid() != 0:
        cmd = ["sudo"] + cmd

    with open(log_path, "w") as lf:
        lf.write(f"Command: {' '.join(shlex.quote(x) for x in cmd)}\n\n")
        lf.flush()
        logging.info("Starting probe %s (obj=%s) -> %s", symbol, obj, log_path)
        try:
            p = subprocess.Popen(cmd, stdout=lf, stderr=subprocess.STDOUT)
            try:
                p.wait(timeout=duration + 15)
            except subprocess.TimeoutExpired:
                p.kill()
                lf.write("\nTimeout expired; killed child.\n")
        except Exception:
            logging.exception("Failed to run probe for %s", symbol)
            with open(log_path, "a") as lf2:
                lf2.write("Failed to start child process\n")

    had_data = False
    if csv_path.exists():
        try:
            # count non-header lines
            with open(csv_path, "r") as cf:
                rows = [l for l in cf if l.strip()]
            # If more than header (1) present -> had data
            if len(rows) > 1:
                had_data = True
        except Exception:
            pass

    return {"symbol": symbol, "object": obj, "log": str(log_path), "csv": str(csv_path), "had_data": had_data}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--out-dir", default="/tmp/auto_probe_concurrent")
    parser.add_argument("--duration", type=int, default=10, help="seconds per candidate")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--try-shared", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-sudo", action="store_true", help="Do not prefix child invocations with sudo")
    args = parser.parse_args()

    outdir = Path(args.out_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    logging.info("Building candidate list for pid %s", args.pid)
    candidates = build_candidates(args.pid)
    logging.info("Found %d candidates", len(candidates))

    summary = {"pid": args.pid, "candidates": candidates, "results": []}
    summary_path = outdir / f"summary_{args.pid}.json"
    with open(summary_path, "w") as sf:
        json.dump(summary, sf, indent=2)

    if args.dry_run:
        print(f"Dry-run: found {len(candidates)} candidates. Summary saved to {summary_path}")
        return

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futures = []
        for c in candidates:
            futures.append(ex.submit(run_probe, args.pid, c, outdir, args.duration, args.try_shared, args.no_sudo))
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            summary["results"].append(res)
            with open(summary_path, "w") as sf:
                json.dump(summary, sf, indent=2)

    logging.info("Completed probes. Summary: %s", summary_path)


if __name__ == "__main__":
    main()
