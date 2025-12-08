"""
Microbenchmark runner that exercises a synthetic demo or other traffic generator,
measures baseline and probe overhead using `perf stat`, and aggregates results.

Usage (example):
  sudo python3 run_microbench.py --pid <bessd-pid> --duration 30 --out /tmp/bench

It attempts to find `ebpf-poc/demo/test_rte` as the traffic generator. If not
present, it will still run the attach probes as a dry-run mode if `--dry-run`.
"""
import argparse
import json
import logging
import os
import shlex
import subprocess
import sys
from pathlib import Path
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")


def run_cmd(cmd, timeout=None, capture=False, env=None):
    logging.info("Running: %s", ' '.join(shlex.quote(x) for x in cmd))
    p = subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout, env=env)
    return p


def perf_stat(duration, outpath):
    cmd = ["sudo", "perf", "stat", "-a", "-e", "cycles,instructions,cache-misses,context-switches", "-I", "1000", "-o", str(outpath), "sleep", str(duration)]
    return run_cmd(cmd, timeout=duration + 10)


def start_traffic_generator(demo_path):
    # start as background process
    p = subprocess.Popen([str(demo_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    return p


def stop_process(p):
    try:
        p.terminate()
        p.wait(timeout=5)
    except Exception:
        try:
            p.kill()
        except Exception:
            pass


def attach_probe(pid, function, duration, out_csv, extra_args=None, try_shared=False):
    # Resolve the path to attach_upf_uprobe.py relative to this script
    script_dir = Path(__file__).parent.parent
    poc_script = script_dir / "attach_upf_uprobe.py"
    cmd = [sys.executable, str(poc_script), "--binary", f"/proc/{pid}/exe", "--function", function, "--interval", "1", "--duration", str(duration), "--log-csv", str(out_csv)]
    if try_shared:
        cmd += ["--try-shared"]
    if extra_args:
        cmd += extra_args
    # Use sudo if necessary
    if os.geteuid() != 0:
        cmd = ["sudo"] + cmd
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out, _ = p.communicate()
    return p.returncode, out


def parse_perf_file(path):
    try:
        with open(path, "r") as f:
            data = f.read()
        return data
    except Exception:
        return ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--out", default="/tmp/ebpf_microbench")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--try-shared", action="store_true")
    args = parser.parse_args()

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    demo = Path(__file__).parents[1] / "demo" / "test_rte"
    can_run_demo = demo.exists() and demo.is_file() and os.access(demo, os.X_OK)

    modes = [
        {"name": "baseline", "probe": None},
        {"name": "uprobe_count", "probe": "_ZN7PMDPort11RecvPacketsEhPPN4bess6PacketEi"},
        {"name": "uprobe_sample", "probe": "_ZN7PMDPort11RecvPacketsEhPPN4bess6PacketEi", "sample": True},
    ]

    results = []

    for m in modes:
        logging.info("Running mode: %s", m["name"])
        perf_path = outdir / f"perf_{m['name']}.txt"
        csv_path = outdir / f"csv_{m['name']}.csv"

        if args.dry_run:
            results.append({"mode": m["name"], "perf": "dry-run", "csv": "dry-run"})
            continue

        traffic = None
        if can_run_demo:
            traffic = start_traffic_generator(demo)
            logging.info("Started demo traffic (pid=%s)", traffic.pid)
        else:
            logging.info("No demo found at %s; continuing without traffic", demo)

        # start the probe (if any) and perf simultaneously
        if m.get("probe"):
            extra = []
            if m.get("sample"):
                extra += ["--sample-rate", "1000"]
            code, out = attach_probe(args.pid, m["probe"], args.duration, csv_path, extra_args=extra, try_shared=args.try_shared)
            # attach_probe blocks and waits for completion
            logging.info("Probe finished (code=%s)" , code)
            with open(outdir / f"probe_{m['name']}.log", "w") as lf:
                lf.write(out)
            # while probe ran, measure perf post-hoc is limited; we'll still collect a perf stat separately
            perf_stat(args.duration, perf_path)
        else:
            perf_stat(args.duration, perf_path)

        if traffic:
            stop_process(traffic)

        perf_text = parse_perf_file(perf_path)
        results.append({"mode": m["name"], "perf": str(perf_path), "csv": str(csv_path), "perf_text": perf_text})

    summary_path = outdir / "microbench_summary.json"
    with open(summary_path, "w") as sf:
        json.dump(results, sf, indent=2)

    # Try to plot if matplotlib present
    try:
        import matplotlib.pyplot as plt
        import csv

        # Build a very small table: mode -> approximate cycles (parse perf_text crude)
        table = []
        for r in results:
            cycles = "n/a"
            if r.get("perf_text"):
                import re
                m = re.search(r"(\d+[\,\d]*)\s+cycles", r["perf_text"])
                if m:
                    cycles = int(m.group(1).replace(',', ''))
            table.append((r["mode"], cycles))

        modes = [t[0] for t in table]
        cycles = [t[1] if isinstance(t[1], int) else 0 for t in table]
        plt.bar(modes, cycles)
        plt.title("Microbench: cycles per mode (approx)")
        plt.ylabel("cycles (approx)")
        plt.savefig(outdir / "microbench_cycles.png")
        logging.info("Plot written to %s", outdir / "microbench_cycles.png")
    except Exception:
        logging.info("matplotlib not available or plotting failed; summary written to %s", summary_path)

    logging.info("Microbench complete. Summary: %s", summary_path)


if __name__ == "__main__":
    main()
"""
Microbenchmark harness for the eBPF PoC using the synthetic `test_rte` program.

It performs three runs:
  - baseline: run `test_rte` alone and sample CPU usage
  - probe: attach PoC (entry+return) and collect CSV
  - probe_sampled: attach PoC with sampling enabled (--sample-rate)

Outputs are written to an output directory under /tmp/bench_results.

Usage:
  sudo python3 ebpf-poc/bench/run_microbench.py --duration 15

Note: the script uses `ps` sampling for CPU; for more precise CPU/hardware counters,
use `perf` and adapt the script accordingly.
"""
import argparse
import os
import subprocess
import sys
import time
from pathlib import Path


def build_test_rte(src="/home/arnav/Desktop/xdp-packet-processing/ebpf-poc/demo/test_rte.c", out="/tmp/test_rte"):
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    cmd = ["gcc", "-O2", "-o", out, src]
    subprocess.check_call(cmd)
    return out


def start_test_rte(binary):
    p = subprocess.Popen([binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # wait a short moment for startup
    time.sleep(0.5)
    return p


def sample_cpu(pid, duration, out_path):
    samples = []
    end = time.time() + duration
    while time.time() < end:
        # ps %cpu gives total CPU% for the process
        try:
            out = subprocess.check_output(["ps", "-p", str(pid), "-o", "%cpu="], text=True)
            cpu = float(out.strip() or "0")
        except Exception:
            cpu = 0.0
        samples.append((time.time(), cpu))
        time.sleep(1)
    with open(out_path, "w") as f:
        for t, c in samples:
            f.write(f"{t},{c}\n")


def run_probe(pocexe, binary, pid, out_csv, timeout, sample_rate=None):
    cmd = [sys.executable, pocexe, "--binary", binary, "--function", "rte_eth_rx_burst", "--interval", "1", "--timeout", str(timeout), "--log-csv", out_csv, "--try-shared"]
    if sample_rate:
        cmd += ["--sample-rate", str(sample_rate)]
    # run under sudo to permit BPF loading
    full_cmd = ["sudo"] + cmd
    subprocess.check_call(full_cmd)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--duration", type=int, default=15, help="seconds per run")
    p.add_argument("--out-dir", default="/tmp/bench_results", help="output directory")
    p.add_argument("--pocexe", default="/home/arnav/Desktop/xdp-packet-processing/ebpf-poc/attach_upf_uprobe.py")
    args = p.parse_args()

    outdir = Path(args.out_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    test_rte_bin = build_test_rte()

    # Baseline
    print("[bench] Starting baseline run")
    proc = start_test_rte(test_rte_bin)
    time.sleep(1)
    pid = proc.pid
    baseline_cpu = outdir / "baseline_cpu.csv"
    sample_cpu(pid, args.duration, str(baseline_cpu))
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except Exception:
        proc.kill()

    # Probe (no sampling)
    print("[bench] Starting probe run")
    proc = start_test_rte(test_rte_bin)
    time.sleep(1)
    pid = proc.pid
    probe_csv = outdir / "probe.csv"
    try:
        run_probe(args.pocexe, f"/proc/{pid}/exe", pid, str(probe_csv), args.duration)
    except subprocess.CalledProcessError as e:
        print("[bench] probe run failed:", e)
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except Exception:
        proc.kill()

    # Probe + sampling
    print("[bench] Starting probe+sampling run")
    proc = start_test_rte(test_rte_bin)
    time.sleep(1)
    pid = proc.pid
    probe_sampled_csv = outdir / "probe_sampled.csv"
    try:
        run_probe(args.pocexe, f"/proc/{pid}/exe", pid, str(probe_sampled_csv), args.duration, sample_rate=100)
    except subprocess.CalledProcessError as e:
        print("[bench] probe+sample run failed:", e)
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except Exception:
        proc.kill()

    print(f"[bench] Results written to {outdir}")


if __name__ == '__main__':
    main()
