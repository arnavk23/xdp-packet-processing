eBPF PoC for SD-Core UPF (DPDK mode)
====================================

This folder contains a non-intrusive proof-of-concept showing how eBPF can be integrated with a DPDK-based UPF using user-space probes (uprobes/uretprobes).

Goals
- Demonstrate telemetry collection from a DPDK data plane without intercepting or modifying packet processing.
- Use eBPF uprobes to observe DPDK runtime behavior (e.g., calls to `rte_eth_rx_burst`) and gather packet counts/metrics.

Prerequisites
- Linux with BCC installed (or system packages that provide libbcc and python3-bcc).
- Root privileges to run the BCC script.
- Path to the DPDK-based UPF binary (or any DPDK app) that exports `rte_eth_rx_burst` symbol.

Files
- `attach_upf_uprobe.py` - BCC-based script that attaches to `rte_eth_rx_burst` (entry and return) and collects per-process/per-core packet counts.
- `requirements.txt` - Python dependency (bcc).

How it works
- The script attaches an uprobe on entry to `rte_eth_rx_burst` and an uretprobe on return. On return, the BPF program reads the return value (number of packets received) and aggregates it into maps keyed by PID.
- Because it only observes function entry/exit, it does not modify the DPDK dataplane or its packet buffers.

Quick usage
1. Install dependencies: `pip3 install -r requirements.txt` (or install the distribution package for BCC).
2. Run as root: `sudo python3 attach_upf_uprobe.py --binary /path/to/upf_binary`.
3. Generate traffic to the UPF (pktgen/iperf/pktsender) and observe printed metrics.

Notes
- This PoC demonstrates observability via tracing; extracting packet headers via uprobes is possible (using `bpf_probe_read_user`) but requires careful offsets for DPDK `rte_mbuf` layout and CPU/ABI considerations.
- For absolutely zero-impact on packet path, consider hardware mirroring (NIC-level) or a separate hardware queue copied into kernel space; the uprobe approach is non-intrusive but incurs some CPU for eBPF map updates and userspace printing.

Extending the PoC
- Add per-queue or per-port keys to BPF maps by reading the function arguments on entry (requires ABI knowledge / register parsing).
- Use uprobe entry to save argument pointers in a per-thread map, then read them on uretprobe to inspect packet buffers (advanced, fragile across DPDK versions).
