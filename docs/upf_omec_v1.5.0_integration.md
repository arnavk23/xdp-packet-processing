# Integrating the PoC with OMEC UPF v1.5.0

This document lists safe, reproducible steps to obtain the OMEC UPF v1.5.0 source, build it locally, find the runtime binary, and run the eBPF uprobe PoC against it.

Note: This repository does not attempt to fetch or build OMEC UPF automatically. The steps below are guidance you can run on your test machine (internet access required). If you prefer, follow the exact build instructions in the OMEC UPF repository README.

1) Clone the OMEC UPF repository and check out the v1.5.0 tag

```bash
# from a suitable work directory
git clone https://github.com/omec-project/upf.git
cd upf
git fetch --tags --all
git checkout tags/v1.5.0 -b v1.5.0
```

2) Build the project

Follow the repository's build instructions in its README. As repositories differ, I list safe, generic steps you can try; if they fail, use the project's README instead.

```bash
# Common generic approach (may vary):
# Install dependencies per repo README, then try a standard build flow:
mkdir -p build && cd build
cmake ..          # or run the project's provided build script
make -j$(nproc)

# If the project uses a Makefile at top-level, simply:
# make -j$(nproc)
```

3) Locate the UPF binary

After a successful build, find likely binaries:

```bash
# Example ways to discover built binaries
find . -type f -executable -name "*upf*" -print
# or search for main executable names
grep -R "main(" -n . | head
```

Common binary locations: `build/`, `bin/`, or top-level directories. The binary may be named `upf`, `upfd`, or similar depending on the project.

4) Confirm the function to probe (symbol availability)

The PoC script by default probes `rte_eth_rx_burst`. The OMEC UPF binary may link with DPDK; confirm the symbol exists in the binary (or its linked DPDK shared lib). Use `nm` or `objdump`:

```bash
# For symbols in the binary itself
nm -D /path/to/upf_binary | grep rte_eth_rx_burst || true

# Or check the DPDK shared library used by the binary
ldd /path/to/upf_binary | grep dpdk || true
```

If `rte_eth_rx_burst` is not present as a dynamic symbol in the user binary, it may be in a shared library (libdpdk). You can attach uprobes to the shared object as well by passing that file path to the PoC script.

5) Run the PoC (attach_upf_uprobe.py)

Run the BCC script as root and point it at the binary or the shared library containing the symbol.

```bash
sudo python3 /path/to/xdp-packet-processing/ebpf-poc/attach_upf_uprobe.py --binary /path/to/upf_binary --function rte_eth_rx_burst
```

Or, if the symbol lives in the DPDK shared library discovered above:

```bash
sudo python3 /path/to/xdp-packet-processing/ebpf-poc/attach_upf_uprobe.py --binary /usr/lib/libdpdk.so --function rte_eth_rx_burst
```

6) Generate traffic and observe telemetry

Use pktgen-DPDK, another host with pktgen, or iperf3 to generate traffic through the UPF. The PoC will print per-PID packet totals periodically.

7) If the function name differs

If OMEC UPF uses a different RX function or an internal wrapper, identify the function(s) where packets are read and replace `--function` with the appropriate symbol name. Use `nm -D` or `objdump -T` to list symbols.

8) Troubleshooting

- If `attach_upf_uprobe.py` fails to attach, ensure you have the BCC Python package installed and are running as root.
- If you cannot find symbols, the binary may be statically linked or stripped. If stripped, probing by symbol name may not be possible; consider probing by address ranges or attach to a wrapper function that remains exported.

9) Security and safety

- Running BPF uprobes requires root privileges. Only run on test machines or in a lab environment.
- Building and running UPF on a packet-generating host can affect network connectivity; isolate test interfaces and cores.

10) Next steps

- After successful basic telemetry, extend probes to capture per-port/queue info by reading function arguments on entry and correlating on return. Document any DPDK struct offsets needed when attempting to read `rte_mbuf` content.
