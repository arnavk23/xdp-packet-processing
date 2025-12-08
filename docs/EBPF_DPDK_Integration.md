# eBPF Integration with DPDK-based Dataplane — Research & Recommendations

Date: 2025-11-28
Authors: Arnav

Executive summary

This document surveys practical integration points for eBPF to observe and augment a DPDK-based dataplane (example: OMEC UPF using BESS + DPDK). It records architectures, trade-offs, implementation notes from a PoC (uprobes-based BCC script), observations during integration, and recommended experiments to measure performance and overhead.

Scope

- Focus: non-intrusive observability and low-overhead telemetry for DPDK-based UPF dataplanes.
- Targeted technology: BESS + DPDK (OMEC UPF v1.5.0). Many points generalize to other DPDK-based apps.

1. Background

DPDK runs user-space drivers and poll-mode drivers (PMDs) to fetch/submit packets via rte_eth_rx_burst and rte_eth_tx_burst. Because DPDK operates in user-space and often pins cores and hugepage memory, instrumentation must avoid perturbing core loops. eBPF provides kernel-side programmable instrumentation, and BCC/libbpf provide helpers to attach to user-space or kernel call sites.

Key constraints when instrumenting DPDK/BESS:
- DPDK requires hugepages, often run in privileged container or host; Uprobes require root.
- Inlined/optimized functions or statically linked drivers may hide symbols.
- Low overhead is critical; instrumentation must avoid frequent copying or expensive operations in the probe.

2. Integration approaches and architecture

Below are integration patterns, architecture diagrams (conceptual), trade-offs, and implementation notes.

2.1 Uprobes / uretprobes (user-space function probes)

Architecture
- Attach BPF programs to user-space function entry and/or return in the dataplane process (e.g., `bessd` or DPDK PMD library) using uprobes (BCC or libbpf's bpf_attach_uprobe).
- Entry probe can record arguments (pointer to mbuf array); return probe reads return value (nb pkts) to compute counters.

Pros
- Non-intrusive: does not require rebuilding the dataplane.
- Fine-grained: can target wrappers or specific callsites (e.g., PMDPort::RecvPackets).
- Low-code PoC via BCC Python.

Cons
- Requires symbol visibility (mangled C++ names for methods) or exact shared-object path.
- Inlining/optimizations may remove the function.
- Reading user-memory (`bpf_probe_read_user`) is allowed but must be rate-limited.
- Root privileges and BCC/libbpf installed.

Implementation notes
- Use BCC for prototyping; libbpf (CO-RE) recommended for production for portability and lower runtime dependencies.
- Example PoC: `ebpf-poc/attach_upf_uprobe.py` attaches to `PMDPort::RecvPackets` (mangled) and logs per-second counts to CSV (path: `/tmp/ebpf_live.csv`).
- Use `--try-shared` or inspect `ldd /proc/<pid>/exe` to find shared libs.

Feasibility for OMEC/BESS
- Works where BESS wrapper exposes the call; in our PoC we successfully attached to `_ZN7PMDPort11RecvPacketsEhPPN4bess6PacketEi`.

2.2 AF_XDP (zero-copy userspace socket) sidecar / in-path

Architecture
- Deploy an AF_XDP-based receiver that either replaces or mirrors NIC RX to a user-space consumer.
- eBPF programs can be used in the kernel at XDP layer to direct packets to AF_XDP sockets.
- The sidecar can be instrumented or act as a mirror producing telemetry.

Pros
- Very low-latency path; supports zero-copy and high throughput when configured.
- eBPF/XDP can filter or redirect packets before DPDK.

Cons
- Requires rearchitecting the dataplane or OS NIC configuration.
- Not strictly non-intrusive — modifies data path configuration.

Implementation notes
- Useful if you can co-locate a sidecar that samples packets for telemetry or if you can run the dataplane in AF_XDP mode.

2.3 Kernel XDP / tc + cls_bpf (kernel-level eBPF)

Architecture
- Attach XDP program in kernel for ingress NIC to collect counters or perform sampling.
- Use `tc` and `cls_bpf` on the egress/ingress hooks to capture different phases.

Pros
- Stable kernel hook, early visibility (before DPDK), no need to touch user-space binary symbols.
- High-performance if pinned to correct RX queues.

Cons
- Less visibility into application-level constructs (e.g., BESS packet metadata).
- Potentially collides with DPDK direct NIC access unless offload features used; XDP observes traffic on kernel-controlled NIC queues (may not see traffic bound to DPDK-managed queues when NIC is in userspace PMD mode).

Implementation notes
- Typically effective when DPDK is not exclusively binding the NIC (e.g., when replicating/mirroring traffic to kernel path).

2.4 Kernel tracepoints / kprobes

Architecture
- Use kernel tracepoints (e.g., `net_dev_queue`, `netif_receive_skb`) or kprobes to observe packet flows in the kernel.

Pros
- Kernel-level, stable tracepoints are portable (tracepoints preferred over raw kprobes).

Cons
- If DPDK entirely bypasses kernel networking stack (PMD exclusive), kernel tracepoints won't see RX.

2.5 DPDK PMD driver or NIC-level instrumentation

Architecture
- Instrument PMD driver code (source-level) or attach to driver-specific functions.
- Alternatively, use NIC telemetry (e.g., hardware counters, switch mirror) to collect telemetry externally.

Pros
- Driver-level hooks are the most accurate for per-queue metrics and per-core counters.

Cons
- Requires modifying or rebuilding DPDK/PMD driver or using vendor tooling.
- Not non-intrusive unless driver supports dynamic plugin loading or symbolized probes.

2.6 eBPF maps + userspace aggregator / CO-RE

Pattern
- BPF programs write into BPF maps (perf events or array/hash) and a userspace reader aggregates data and writes CSV/metrics.

Notes
- Use BPF CO-RE or libbpf to compile portable BPF programs; BCC uses kernel headers and is convenient for prototyping.

3. Observations from PoC on OMEC UPF v1.5.0

What we implemented
- A BCC-based PoC (`ebpf-poc/attach_upf_uprobe.py`) that attaches uprobes to `PMDPort::RecvPackets` (calls `rte_eth_rx_burst`) in `bessd` and records returned packet counts per interval keyed by TGID; supports optional sampling of first mbuf via `bpf_probe_read_user`.

What worked
- Successfully attached to `bessd` mangled symbol when the process binary contained the symbol.
- Demo synthetic program (`ebpf-poc/demo/test_rte`) validated end-to-end collection.
- Dockerfile runtime lib fixes required copying build-stage gRPC libs to runtime stage to resolve libsoname mismatches.
- Allocating host hugepages and running `bessd` privileged allowed DPDK to initialize.

What blocked or required attention
- Symbol visibility: `rte_eth_rx_burst` not exported from `/proc/<pid>/exe` in some cases — helpful to probe wrapper function in BESS (`PMDPort::RecvPackets`) or its variants (VPort, PCAP, CNDP).
- Container constraints: `bessd` needs hugepages and sometimes kernel modules; container must be privileged or run with proper caps and hugepage mounts.
- Root/BPF requirements: BCC requires root to load BPF programs.

4. Implementation details and artifacts

PoC location
- `ebpf-poc/attach_upf_uprobe.py` — BCC script to attach entry + return probes and aggregate counts.
- `ebpf-poc/analysis/parse_telemetry.py` and `plot_telemetry.py` — analysis & plotting tools.
- `ebpf-poc/demo/test_rte` — synthetic program that exposes `rte_eth_rx_burst` for testing.
- Presentation and paper artifacts are in the repo under `upf-omec-v1.5.0/`.

Design of the BPF program
- Entry probe: records the pointer to the mbuf array (first argument) into a per-thread map.
- Return probe: reads return value (number of packets), increments a per-TGID counter map by returned value.
- Userspace controller: periodically (interval configurable) reads map contents and writes CSV with timestamps.

Safety precautions
- Avoid heavy per-packet logic in BPF: limit operations to increments and small reads.
- If sampling packet headers, use sampling rate parameter to limit bpf_probe_read_user calls.

5. Performance experiments — recommendations and commands

Note: the PoC produced per-interval packet counts (example: mean ~636 pps) during a captured run, but we did not perform a systematic overhead benchmark. The following experiments are recommended to quantify overhead and measure safe sampling rates.

5.1 Goals
- Measure throughput impact (pps) of enabling uprobes vs baseline.
- Measure CPU utilization change on DPDK cores and on the host when probes active.
- Evaluate sampling impact when reading mbuf headers at configurable rates.

5.2 Microbenchmark setup
- Use `ebpf-poc/demo/test_rte` or DPDK `testpmd`/pktgen to generate steady traffic toward the dataplane's RX port.
- Repeat each test in 3 modes: (A) no probes, (B) uprobes attached (entry+return count only), (C) uprobes + sampling (`--sample-rate=N`).
- Collect metrics: measured pps, CPU utilization per core, `perf stat` hardware counters, and BPF map update rates.

5.3 Example commands

Start testpmd or demo to create traffic sink/forwarder (adjust to environment):
```bash
# on traffic generator host or in a VM
# testpmd example (DPDK must be built and NICs configured accordingly)
sudo ./testpmd -l 2-3 -n 4 -- -i --port-topology=chained --forward-mode=io
```

Run PoC (attach) for a 60s capture (example):
```bash
sudo python3 ebpf-poc/attach_upf_uprobe.py --binary /proc/<bessd-pid>/exe \
  --function _ZN7PMDPort11RecvPacketsEhPPN4bess6PacketEi --interval 1 \
  --timeout 60 --log-csv /tmp/ebpf_live.csv --try-shared
```

Measure baseline throughput (no probe) using pktgen/testpmd counters or `tcpreplay` and measure CPU:
```bash
# run for 60s and collect perf counters
sudo perf stat -a -e cycles,instructions,cache-misses,context-switches -I 1000 -o perf_noprobe.txt sleep 60
```

Run with probe attached and repeat:
```bash
# attach probe (background)
sudo python3 ebpf-poc/attach_upf_uprobe.py --binary /proc/<pid>/exe --function <symbol> --interval 1 --timeout 60 --log-csv /tmp/ebpf_live.csv &
# run traffic and perf
sudo perf stat -a -e cycles,instructions,cache-misses,context-switches -I 1000 -o perf_probe.txt sleep 60
```

Compare results (throughput counters from testpmd/pktgen and perf files). Compute delta in pps and CPU cycles.

5.4 Sampling experiments
- Repeat tests with `--sample-rate=1000` (read one mbuf every 1000 calls) and vary sampling up/down to determine safe sampling frequency that keeps overhead acceptable.

5.5 Metrics to report
- Throughput (pps) delta vs baseline.
- CPU utilization on DPDK cores and user/system split.
- Perf counters (cycles, instructions, cache-misses).
- BPF map update frequency and any dropped events.

6. Example expected results & interpretation (what to look for)

- If uprobes only (entry+return count), we expect extremely low overhead for modern machines — single-digit percentage CPU impact in most cases; but this must be validated for your workload.
- Sampled reads (`bpf_probe_read_user`) can be expensive if done frequently. Expect overhead roughly proportional to sampling rate and the cost of user-memory reads.
- If measuring significant overhead, consider lowering sample-rate or moving sampling to a dedicated core via ring buffer batching.

7. Recommendations & roadmap

Short-term (low effort) — **IMPLEMENTED**
- ✓ Use uprobes on BESS wrappers (`PMDPort::RecvPackets`, `VPort::RecvPackets`, `CndpPort::RecvPackets`) to collect per-interval counts. Automate probing of candidate symbols to detect the live datapath.
  - **Tool:** `ebpf-poc/auto_probe_concurrent.py` — concurrent symbol scanner and probe harness.
  - Scans `/proc/<pid>/maps` and `/proc/<pid>/exe` for candidate symbols.
  - Runs probes concurrently (configurable parallelism) for a short duration.
  - Produces per-candidate logs, CSVs, and JSON summary.

- ✓ Add traffic-generation orchestrator to ensure reproducible captures.
  - **Tool:** `ebpf-poc/bench/run_microbench.py` — microbenchmark runner for three modes (baseline, uprobe_count, uprobe_sample).
  - Optionally starts demo traffic generator; collects perf stats and telemetry CSVs.
  - Generates matplotlib plots if available.
  - **Results:** Microbenchmark completed (60s per mode); probes attached successfully with `--try-shared` flag. Zero telemetry observed due to synthetic demo not reaching real RX path. Probe overhead validation **deferred** pending real traffic.

Medium-term (more robust) — **IMPLEMENTED**
- ✓ Implement libbpf-based CO-RE BPF programs for production to reduce runtime dependencies and improve portability.
  - **Skeleton:** `ebpf-poc/libbpf/` directory with:
    - `recv_count.bpf.c` — minimal BPF program (percpu map + uprobe return handler).
    - `recv_count.c` — userspace loader (attaches probes, reads map periodically).
    - `Makefile` — build recipe (requires clang, libbpf).
  - Ready for production deployment with CO-RE for portability.

- Consider kernel-level XDP + AF_XDP mirror sidecar if true zero-copy observability is needed and system architecture permits.
  - **Status:** Architecture documented in Section 2.2; implementation deferred pending traffic generation capability.

Long-term
- If vendor NIC supports eBPF offload or hardware telemetry, integrate with NIC telemetry APIs for per-port counters at wire-speed without user-space instrumentation.
  - **Status:** Research noted; implementation pending NIC capability assessment.

8. Limitations and risk

- Uprobes rely on symbol availability; for stripped binaries or heavy inlining, they may fail.
- Attaching probes to live, heavily loaded cores has risk of perturbing timing-sensitive flows — always validate on staging hardware.
- BPF programs must be minimal; prefer maps and user-space aggregation for heavy processing.

9. Appendix — Repo pointers and scripts

- PoC PoC: `ebpf-poc/attach_upf_uprobe.py`
- Parser/plotter: `ebpf-poc/analysis/parse_telemetry.py`, `plot_telemetry.py`
- Demo: `ebpf-poc/demo/test_rte`