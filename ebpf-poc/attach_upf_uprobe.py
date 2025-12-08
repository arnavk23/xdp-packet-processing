"""
attach_upf_uprobe.py

BCC-based PoC that attaches an uprobe and uretprobe to a given user-space binary function
(e.g., DPDK's `rte_eth_rx_burst`). On return, it reads the function's return value (number of packets)
and aggregates counts per PID and per-CPU.

Run as root. Example:
  sudo python3 attach_upf_uprobe.py --binary /usr/local/bin/upf --function rte_eth_rx_burst

Requirements: bcc (python3-bcc)
"""

from bcc import BPF
import signal
import argparse
import time
import sys
from collections import defaultdict
from datetime import datetime
import os


DEFAULT_FUNCTION = "rte_eth_rx_burst"


def make_bpf_text(sample_rate=0):
    # BPF program: map `counts` keyed by PID (u32) storing u64 packet totals.
    # SAMPLE_RATE controls low-rate sampling of packet header pointers (1/sample_rate).
    return r"""
    #include <uapi/linux/ptrace.h>

    #define SAMPLE_RATE @@SAMPLE_RATE@@

    BPF_HASH(counts, u32, u64);
    BPF_HASH(arg_map, u32, u64); // store pointer to mbuf array per pid
    BPF_HASH(ptr_counts, u64, u64); // count observed first-mbuf pointers
    BPF_HASH(call_count, u32, u64);

    int trace_entry(struct pt_regs *ctx) {
        // save first argument (mbufs array pointer) for sampling on return
        u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
        u64 mbufs = 0;
#ifdef __x86_64__
        mbufs = PT_REGS_PARM1(ctx);
#else
        mbufs = PT_REGS_PARM1(ctx);
#endif
        arg_map.update(&pid, &mbufs);
        return 0;
    }

    int trace_return(struct pt_regs *ctx) {
        u64 ret = PT_REGS_RC(ctx);
        // Use TGID (process id) as the key: high 32 bits of pid_tgid
        u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
        u64 *cur = counts.lookup(&pid);
        if (cur) {
            __sync_fetch_and_add(cur, ret);
        } else {
            counts.update(&pid, &ret);
        }

        // low-rate sampling of first mbuf pointer (experimental)
        if (SAMPLE_RATE > 0) {
            u64 zero = 0;
            u64 one = 1;
            u64 *cc = call_count.lookup(&pid);
            if (cc) {
                __sync_fetch_and_add(cc, one);
            } else {
                call_count.update(&pid, &one);
                cc = call_count.lookup(&pid);
            }
            if (cc) {
                u64 val = *cc;
                if ((val % SAMPLE_RATE) == 0) {
                    u64 *pmb = arg_map.lookup(&pid);
                    if (pmb && ret > 0) {
                        u64 mbuf_arr = *pmb;
                        u64 first_mbuf = 0;
                        // read first pointer from the user-space mbuf array
                        bpf_probe_read_user(&first_mbuf, sizeof(first_mbuf), (void *)mbuf_arr);
                        if (first_mbuf) {
                            u64 *pc = ptr_counts.lookup(&first_mbuf);
                            if (pc) {
                                __sync_fetch_and_add(pc, one);
                            } else {
                                ptr_counts.update(&first_mbuf, &one);
                            }
                        }
                    }
                }
            }
        }

        return 0;
    }
""".replace('@@SAMPLE_RATE@@', str(sample_rate))


def parse_args():
    p = argparse.ArgumentParser(description="Attach uprobe/uretprobe to DPDK function and collect simple telemetry")
    p.add_argument('--binary', '-b', required=True, help='Path to the DPDK/UPF binary to attach to')
    p.add_argument('--function', '-f', default=DEFAULT_FUNCTION, help='Function symbol to probe (default: rte_eth_rx_burst)')
    p.add_argument('--interval', '-i', type=int, default=1, help='Print interval in seconds')
    p.add_argument('--sample-rate', '-s', type=int, default=0, help='Low-rate sampling: 1 in N calls to sample packet headers (experimental)')
    p.add_argument('--try-shared', dest='try_shared', action='store_true', help='If symbol not in binary, try shared libs linked by the binary')
    p.add_argument('--timeout', type=int, default=10, help='Seconds to wait for first observation before warning and exit if none are seen')
    p.add_argument('--duration', type=int, default=0, help='Total seconds to run the probe; 0 means run indefinitely')
    p.add_argument('--log-csv', dest='log_csv', help='Path to append timestamped CSV lines: iso_timestamp,pid,total')
    return p.parse_args()


def main():
    args = parse_args()

    stop_requested = False

    def _signal_handler(signum, frame):
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    bpf_text = make_bpf_text(args.sample_rate)
    b = BPF(text=bpf_text)
    ptr_counts = None
    samplesf = None
    if args.sample_rate and args.sample_rate > 0:
        try:
            ptr_counts = b.get_table('ptr_counts')
        except Exception:
            ptr_counts = None

    def try_attach_to(path):
        try:
            b.attach_uprobe(name=path, sym=args.function, fn_name=b'trace_entry')
            b.attach_uretprobe(name=path, sym=args.function, fn_name=b'trace_return')
            print(f"Successfully attached to symbol {args.function} in {path}")
            return True
        except Exception as e:
            return False

    attached = False

    if try_attach_to(args.binary):
        attached = True
    elif args.try_shared:
        import subprocess
        try:
            out = subprocess.check_output(["ldd", args.binary], text=True)
        except Exception as e:
            print(f"ldd failed on {args.binary}: {e}")
            out = ''

        # Parse paths from ldd output
        libs = []
        for line in out.splitlines():
            parts = line.strip().split('=>')
            if len(parts) == 2:
                right = parts[1].strip().split()[0]
                if right and right != 'not':
                    libs.append(right)
        for lib in libs:
            if try_attach_to(lib):
                attached = True
                break

    if not attached:
        print("Failed to attach probes to the requested symbol. Try running with --try-shared or check symbol visibility.")
        sys.exit(1)

    counts = b.get_table('counts')

    print(f"Attached probes for {args.function}. Printing totals every {args.interval}s. Ctrl-C to quit.")
    try:
        waited = 0
        elapsed = 0
        csvf = None
        if args.log_csv:
            try:
                # Ensure directory exists
                d = os.path.dirname(args.log_csv)
                if d and not os.path.exists(d):
                    os.makedirs(d, exist_ok=True)
                need_header = not os.path.exists(args.log_csv) or os.path.getsize(args.log_csv) == 0
                csvf = open(args.log_csv, 'a', buffering=1)
                if need_header:
                    # Write a simple header with interval metadata. Prefixed with '#' so parsers can skip it.
                    try:
                        csvf.write(f"# interval_seconds={args.interval}\n")
                        csvf.write("timestamp,pid,total,interval_seconds\n")
                    except Exception:
                        pass
            except Exception as e:
                print(f"Failed to open CSV log '{args.log_csv}': {e}")
                csvf = None
        # prepare samples file for pointer samples if requested
        if args.sample_rate and args.sample_rate > 0 and args.log_csv:
            samples_path = args.log_csv + '.samples'
            try:
                need_h = not os.path.exists(samples_path) or os.path.getsize(samples_path) == 0
                samplesf = open(samples_path, 'a', buffering=1)
                if need_h:
                    try:
                        samplesf.write('# pointer_samples\n')
                        samplesf.write('timestamp,ptr_hex,count\n')
                    except Exception:
                        pass
            except Exception:
                samplesf = None
        # Main polling loop. Supports a total run duration and will exit cleanly on signals.
        while True:
            if stop_requested:
                print("Stop requested via signal; detaching and exiting")
                break
            time.sleep(args.interval)
            elapsed += args.interval
            if args.duration and args.duration > 0 and elapsed >= args.duration:
                print(f"Reached total duration {args.duration}s; detaching and exiting")
                break
            totals = defaultdict(int)
            for k, v in counts.items():
                pid = k.value
                totals[pid] += v.value

            if not totals:
                if waited < args.timeout:
                    waited += args.interval
                    print("No observations yet.")
                    # continue waiting until timeout or first observation
                    continue
                else:
                    print("Warning: no observations after timeout. Either traffic is not reaching the probed function or the symbol doesn't match. Exiting.")
                    # Exit if we've waited long enough and still have no data
                    break

            ts = datetime.utcnow().isoformat() + 'Z'
            print("--- telemetry (pid -> total packets) ---")
            for pid, total in sorted(totals.items(), key=lambda x: -x[1]):
                print(f"pid {pid}: {total} pkts")
                if csvf:
                    try:
                        csvf.write(f"{ts},{pid},{total},{args.interval}\n")
                    except Exception:
                        # best-effort logging; don't fail the main loop
                        pass

            # export any pointer samples collected in BPF (experimental)
            if ptr_counts and samplesf:
                try:
                    for k, v in ptr_counts.items():
                        ptr = k.value
                        cnt = v.value
                        try:
                            samplesf.write(f"{ts},{hex(ptr)},{cnt}\n")
                        except Exception:
                            pass
                    # clear the map after reading
                    try:
                        ptr_counts.clear()
                    except Exception:
                        # best-effort
                        pass
                except Exception:
                    pass
            print('---------------------------------------')

    except KeyboardInterrupt:
        print("Detaching and exiting")
    finally:
        try:
            if 'csvf' in locals() and csvf:
                csvf.close()
        except Exception:
            pass


if __name__ == '__main__':
    main()
