# libbpf CO-RE PoC: recv_count

This folder contains a small libbpf CO-RE skeleton that implements the same
logic as the BCC PoC: attach an uprobes/uretprobes pair to a `RecvPackets`-like
function and increment a BPF map with returned packet counts. The provided
Makefile is a minimal example that expects a system with libbpf headers and
clang/llvm installed.

Notes:
- Building requires `libbpf` and kernel headers. Use your distro packages or
  the libbpf-bootstrap repository for a full build environment.
- This skeleton is intentionally small and will likely need adjustments for
  your environment and libbpf version.

Build:
  make

Run (example):
  sudo ./recv_count <pid> <symbol> --duration 60 --out /tmp/recv_count.csv

The userspace loader will open the BPF object, attach uprobes to the target
symbol, and periodically read the map contents and write a CSV.
