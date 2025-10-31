# Slides: eBPF Integration in SD-Core UPF (DPDK mode)

Slide 1 — Title
- eBPF Integration in SD-Core UPF (DPDK mode)
- PoC: uprobe-based telemetry

Slide 2 — Motivation
- Need observability/analytics in cloud-native 5G UPF.
- Keep line-rate DPDK datapath unchanged.

Slide 3 — Challenges
- DPDK bypasses kernel; kernel eBPF/XDP cannot see packets.
- Must avoid impacting packet path and CPU-critical loops.

Slide 4 — Integration options
- Uprobes (observe user-space functions)
- NIC hardware mirroring (mirror flows to kernel)
- AF_XDP sidecar or copy queue

Slide 5 — Chosen PoC
- Uprobes for telemetry: attach to `rte_eth_rx_burst` and collect per-call packet counts.
- Non-intrusive, low-risk.

Slide 6 — PoC demo
- BCC Python script: attach_upf_uprobe.py
- Live printing of per-PID packet totals.

Slide 7 — Benchmark plan
- Baseline vs uprobe: throughput, latency, CPU usage.
- Use pktgen-DPDK / iperf for traffic.

Slide 8 — Results & observations (fill after running)

Slide 9 — Next steps
- Per-port metrics, sampled header reads, NIC mirroring + AF_XDP path.

Slide 10 — Questions
