# Benchmark plan — validating eBPF non-intrusiveness

Goal
- Measure throughput, CPU usage, and basic latency before and after enabling the uprobe-based eBPF PoC.

Testbed
- Two machines: traffic generator (pktgen-DPDK or iperf3) and target UPF machine with DPDK-capable NICs.
- Isolate CPU cores for the UPF process to minimize noise.

Metrics
- Throughput: measure via NIC counters (rx_bytes/tx_bytes) and pktgen reported Mpps/Gbps.
- CPU utilization: per-process %CPU for UPF.
- Latency: if possible, use a latency-capable generator or test flows that measure RTT.

Procedure
1. Prepare the UPF and ensure it is bound to DPDK PMDs and running (note UPF PID or binary path).
2. Baseline run:
   - Ensure PoC is NOT running.
   - Start traffic generator with target rates (e.g., 1, 5, 10 Mpps) and run for N seconds.
   - Use `ebpf-poc/bench/run_benchmark.sh` to record interface counters and UPF %CPU.
3. PoC run:
   - Start the PoC: `sudo python3 ebpf-poc/attach_upf_uprobe.py --binary /path/to/upf_binary --try-shared --interval 1`
   - Re-run the same traffic scenarios and record metrics with `run_benchmark.sh`.
4. Compare results:
   - Convert `rx_bytes`/`tx_bytes` differences into bandwidth and packet rates.
   - Plot CPU usage across runs; note any uplift with PoC enabled.

Notes
- Ensure traffic is high enough to exercise the data path near capacity to see any potential impact.
- For low-overhead probes that only update counters, we expect near-zero measurable throughput loss; CPU may increase slightly for the host.

Automation
- The `ebpf-poc/bench/run_benchmark.sh` script helps capture simple metrics; adapt it to your environment (iface names, traffic commands).
