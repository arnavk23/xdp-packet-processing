"""
Automated probe runner: try a list of candidate function names against a running process
by invoking the existing `attach_upf_uprobe.py` PoC for a short timeout and check
if any telemetry rows are produced. Saves results in an output directory.

Usage:
  sudo python3 ebpf-poc/auto_probe.py --pid 12345

This script is intentionally simple: it shells out to the PoC script and inspects
the CSV output to determine whether any observations were recorded for each candidate.
"""
import argparse
import os
import subprocess
import sys
import time
import json

DEFAULT_CANDIDATES = [
    "rte_eth_rx_burst",
    "_ZN7PMDPort11RecvPacketsEhPPN4bess6PacketEi",
    "PMDPort::RecvPackets",
    "VPort::RecvPackets",
    "PCAPPort::RecvPackets",
    "CndpPort::RecvPackets",
    "RecvPackets",
]


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--pid", type=int, help="PID of running dataplane (bessd)")
    p.add_argument("--binary", default=None, help="Path to binary (default: /proc/<pid>/exe)")
    p.add_argument("--timeout", type=int, default=10, help="seconds to run each probe")
    p.add_argument("--out-dir", default="/tmp/auto_probe_results", help="output directory")
    p.add_argument("--no-sudo", dest='no_sudo', action='store_true', help='Do not prefix PoC calls with sudo (useful when running this script as root)')
    p.add_argument("--candidates-file", default=None, help="file with newline-separated candidates")
    p.add_argument("--pocexe", default="ebpf-poc/attach_upf_uprobe.py", help="path to PoC attach script")
    return p.parse_args()


def load_candidates(path):
    if not path:
        return DEFAULT_CANDIDATES
    with open(path, "r") as f:
        return [l.strip() for l in f if l.strip()]


def csv_has_data(csv_path):
    if not os.path.exists(csv_path):
        return False
    try:
        with open(csv_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # header line contains commas but not numeric timestamp; we look for numeric rows
                parts = line.split(',')
                # check if there's a numeric value in one of the columns
                for p in parts:
                    p = p.strip()
                    if p.replace('.', '', 1).isdigit():
                        return True
    except Exception:
        return False
    return False


def run_probe(pocexe, binary, pid, candidate, timeout, out_dir, no_sudo=False):
    safe_name = candidate.replace('/', '_').replace(' ', '_').replace(':', '_')
    csv_path = os.path.join(out_dir, f"probe_{safe_name}_{pid}.csv")
    log_path = os.path.join(out_dir, f"probe_{safe_name}_{pid}.log")

    cmd = []
    # If no_sudo is False, prefix with sudo so child process runs as root.
    if not no_sudo:
        cmd.append("sudo")
    cmd += [sys.executable, pocexe,
           "--binary", binary,
           "--function", candidate,
           "--interval", "1",
           "--timeout", str(timeout),
           "--log-csv", csv_path,
           "--try-shared"]

    with open(log_path, "w") as logf:
        start = time.time()
        try:
            subprocess.run(cmd, stdout=logf, stderr=logf, check=False, text=True, timeout=timeout + 10)
        except subprocess.TimeoutExpired:
            logf.write("\n[auto_probe] attach timed out\n")
        elapsed = time.time() - start
        logf.write(f"\n[auto_probe] candidate={candidate} elapsed={elapsed:.1f}s\n")

    had_data = csv_has_data(csv_path)
    return {
        "candidate": candidate,
        "csv": csv_path,
        "log": log_path,
        "had_data": had_data,
    }


def main():
    args = parse_args()
    if not args.pid and not args.binary:
        print("Either --pid or --binary must be provided", file=sys.stderr)
        sys.exit(2)

    if args.pid and not args.binary:
        binary = f"/proc/{args.pid}/exe"
    else:
        binary = args.binary

    candidates = load_candidates(args.candidates_file)

    os.makedirs(args.out_dir, exist_ok=True)

    results = []
    for candidate in candidates:
        print(f"[auto_probe] Trying candidate: {candidate}")
        res = run_probe(args.pocexe, binary, args.pid or 0, candidate, args.timeout, args.out_dir, no_sudo=args.no_sudo)
        print(f"[auto_probe] Result: candidate={candidate} had_data={res['had_data']} csv={res['csv']}")
        results.append(res)

    results_path = os.path.join(args.out_dir, f"results_{args.pid or 'unknown'}.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)

    print("\nSummary:\n")
    for r in results:
        status = "FOUND" if r["had_data"] else "no-data"
        print(f"- {r['candidate']}: {status} (csv: {r['csv']}, log: {r['log']})")

    print(f"\nWrote results to {results_path}")


if __name__ == '__main__':
    main()
