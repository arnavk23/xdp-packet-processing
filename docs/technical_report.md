# eBPF Integration into SD-Core UPF (DPDK mode)

This report explores non-intrusive methods for integrating eBPF into the SD-Core User Plane Function (UPF) operating in DPDK mode. The primary objective is to enable observability and lightweight analytics without degrading the existing DPDK datapath performance.

We present a design focused on user-space probes (uprobes/uretprobes) for telemetry collection and outline alternative approaches (hardware NIC mirroring and kernel-side AF_XDP sidecar). A small proof-of-concept (PoC) demonstrates using BCC uprobes attached to DPDK functions (e.g., `rte_eth_rx_burst`) to collect packet counts and simple metrics. The PoC preserves the data path and requires only read-only observations of user-space runtime.

## Background: SD-Core UPF (DPDK mode) datapath

SD-Core UPF in DPDK mode performs packet I/O directly in user-space using DPDK poll-mode drivers (PMDs). Packets arrive on NIC RX queues and are pulled by the UPF process via calls such as `rte_eth_rx_burst`, processed in user-space, and transmitted using `rte_eth_tx_burst`. Key characteristics:

- Zero-copy user-space packet processing.
- Kernel bypass for line-rate performance.
- Deterministic RX/TX loops often bound to isolated CPUs.

Because packets do not traverse the kernel network stack, kernel eBPF programs attached to kprobes/XDP cannot observe the packets directly. Any eBPF integration that attempts to inspect packets must either (a) intercept the DPDK user-space processing, (b) rely on hardware NIC-level mirroring, or (c) use out-of-band copies/sample streams.

## Integration approaches considered

1) Uprobes (user-space tracing)

- Mechanism: Attach eBPF uprobes/uretprobes to DPDK functions in the UPF binary (e.g., `rte_eth_rx_burst`) to observe call entry/exit and return values.
- Pros: Non-intrusive to packet buffers, low-risk, compatible with existing DPDK binaries, easier deployment as it only requires root and BPF tooling on the host.
- Cons: Limited by what's available in function arguments/returns; reading packet contents requires careful use of `bpf_probe_read_user` and knowledge of `rte_mbuf` layout which is fragile across DPDK versions.

2) Hardware-level mirroring / NIC filtering (SPAN/FTM/Flow Director)

- Mechanism: Configure the NIC to mirror a copy of selected flows or sampled packets to a separate port or queue. The mirrored traffic can be fed into the kernel (XDP/AF_PACKET) or another DPDK app for eBPF processing.
- Pros: True zero-intrusion — the UPF receives original traffic unmodified. Allows full packet visibility in kernel/eBPF if mirrored to kernel-facing interface.
- Cons: Requires NIC feature support and administrative access; may reduce total available NIC bandwidth if mirror duplicates heavy traffic.

3) Sidecar AF_XDP or dedicated copy queue

- Mechanism: Configure DPDK to duplicate/copy packets (e.g., using rte_flow rules or a small forwarding path that clones packets to another interface) where AF_XDP or kernel XDP programs perform inspection.
- Pros: Full packet visibility and flexibility.
- Cons: Potentially intrusive (if copying occurs in DPDK loop), additional CPU overhead, some NICs may not support efficient cloning.

4) Uprobes + Sampling / heuristics (hybrid)

- Use uprobes for lightweight, always-on telemetry (counts, per-call timing) and hardware mirroring or targeted AF_XDP for deeper packet inspection on sampled flows.

## Chosen approach for PoC

For this PoC we chose uprobes/uretprobes for the following reasons:

- Non-intrusive: does not alter packet buffers or the DPDK RX/TX path.
- Low setup overhead: only requires BPF tooling on the host.
- Practical: can obtain meaningful telemetry (packets received per call, per PID, per-core) sufficient for observability and trend analysis.

The PoC demonstrates attaching an uretprobe to `rte_eth_rx_burst` to capture the return value (number of packets retrieved), aggregate counts per PID, and periodically report totals.

## PoC implementation details

Files provided in the repository:

- `ebpf-poc/attach_upf_uprobe.py` — BCC Python script that installs an uprobe and uretprobe on a target binary's function (default `rte_eth_rx_burst`). The eBPF program stores totals in a map keyed by PID.
- `ebpf-poc/README.md` — usage notes and caveats.

How the BPF program works

- An entry probe is attached for completeness (no-op in this PoC).
- The return probe reads the function's return value using `PT_REGS_RC(ctx)` and updates a per-PID u64 counter in an eBPF hash map.
- A user-space Python loop reads and displays the counters at a configurable interval.

Extending the PoC

- Per-queue/port metrics: On function entry, capture the register(s) that contain `port_id` and `queue_id` and store them in a per-thread map, then read them on return to key the counts by (port, queue).
- Packet sampling: Use the pointer to `rte_mbuf **rx_pkts` to read the first packet buffer and sample headers via `bpf_probe_read_user`. This requires precise offsets for `rte_mbuf` and is DPDK-version-dependent.
- Flow-level classification: Implement heuristics in user-space by sampling packet bytes and updating flow maps.

## Benchmarking plan

We recommend the following bench harness and metrics to validate non-intrusiveness:

Testbed
- Machine with DPDK-capable NICs (dual-port recommended), isolated CPU cores for DPDK RX/TX, and a traffic generator (pktgen-DPDK or another machine running pktgen or iperf3).

Metrics
- Throughput (Mpps, Gbps) measured at the UPF egress and at NIC counters.
- Packet latency (if measurable) measured via timestamped test flows or latency generators.
- CPU utilization per core for the UPF process (top/ps or perf) and the host (system-wide) while eBPF is active.

Scenarios
1. Baseline: UPF running in DPDK mode, no eBPF monitoring.
2. Uprobe: Run PoC script attached (always-on uretprobe) and repeat traffic.
3. Hardware mirror: (optional) Configure NIC mirror to an AF_XDP listener and run kernel eBPF for deeper inspection.

Measurements and expectations
- For typical uprobe-based telemetry collecting counts only, we expect near-zero impact on throughput when probes are lightweight (just map updates). The main CPU cost is map update overhead which is mainly in kernel. If the UPF is CPU-bound, enable CPU isolation and allocate a dedicated core for eBPF aggregation or run the BPF maps read at coarse intervals.

## Observations & trade-offs

- Uprobes are attractive for production observability since they avoid changing the critical forwarding path; they are well-suited to counters, timings, and coarse telemetry.
- For packet-level inspection (headers/payload) without touching DPDK, hardware NIC mirroring or copying to a kernel-facing interface is necessary.
- Sampling combined with upright counters provides a good cost/visibility trade-off: measure counts always, inspect occasional packets.

## Next steps

1. Implement per-port/queue keys in the uprobe PoC to produce interface-level metrics.
2. Add optional payload sampling (careful: DPDK struct offsets) and map sampled headers into flow maps.
3. Automate benchmark runs and produce graphs (throughput vs. CPU) comparing baseline and uprobe.
4. Evaluate hardware mirroring configuration on target NICs and add an AF_XDP-based consumer for mirrored packets.

## Conclusion

Uprobes provide a low-risk, practical path to bring eBPF-based observability into a DPDK UPF without impacting the critical packet path. For full packet visibility, NIC-level mirroring or a copying sidecar is required. The provided PoC demonstrates the concept and forms a foundation for richer telemetry with sampling or hybrid designs.
