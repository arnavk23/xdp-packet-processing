# Deliverables summary — eBPF PoC for SD-Core UPF (DPDK mode)

Files added

- `ebpf-poc/attach_upf_uprobe.py` — BCC Python PoC that attaches uprobes/uretprobes to a DPDK symbol and aggregates return counts.
- `ebpf-poc/requirements.txt` — lists `bcc`.
- `ebpf-poc/README.md` — PoC overview and quick usage.
- `ebpf-poc/bench/run_benchmark.sh` — simple harness to run traffic and collect interface counters and UPF CPU usage.
- `ebpf-poc/bench/collect_metrics.sh` — helper sampler for quick checks.
- `ebpf-poc/omec_build.sh` — helper script to clone and attempt building OMEC UPF v1.5.0 (manual dependency installation required).
- `docs/upf_omec_v1.5.0_integration.md` — step-by-step guide to clone, build, and run the PoC against OMEC UPF v1.5.0.
- `docs/benchmark_plan.md` — benchmark methodology and expectations.
- `docs/technical_report.md` — 3–5 page draft technical report describing architecture, design choices and PoC details.
- `slides/slide_notes.md` — slide notes and outline for a presentation.

How to run the quick PoC

1. Install dependencies: BCC (python3-bcc). On Debian/Ubuntu:

```bash
sudo apt install -y bpfcc-tools python3-bpfcc
pip3 install -r ebpf-poc/requirements.txt
```

2. Run OMEC UPF or any DPDK app that exports `rte_eth_rx_burst`.

3. Attach the PoC (example):

```bash
sudo python3 ebpf-poc/attach_upf_uprobe.py --binary /path/to/upf_binary --function rte_eth_rx_burst --try-shared
```

4. Start traffic and use the benchmark harness to collect metrics (adapt iface and PIDs):

```bash
./ebpf-poc/bench/run_benchmark.sh --upf-pid <pid> --iface eth0 --duration 60 --traffic-cmd "iperf3 -c <peer> -t 60" --mode ebpf
```

Notes and next steps

- To fully validate against OMEC UPF v1.5.0, run `ebpf-poc/omec_build.sh` on an environment with the required dependencies and then follow `docs/upf_omec_v1.5.0_integration.md`.
- For production-grade telemetry, consider combining uprobes for counters with NIC mirroring + AF_XDP for packet sampling.
