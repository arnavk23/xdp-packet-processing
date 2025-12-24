#!/usr/bin/env python3
"""
attach_upf_uprobe_flowtag.py

BCC-based script to attach uprobes to DPDK UPF, collect per-flow (5-tuple) packet counts using eBPF.
Extends the original attach_upf_uprobe.py with flow-level tagging.

Usage:
  sudo python3 attach_upf_uprobe_flowtag.py --binary /path/to/upf_binary

Requires: bcc, root privileges, and a DPDK binary exporting rte_eth_rx_burst.
"""
from bcc import BPF, USDT
import argparse
import socket
import struct
import time

parser = argparse.ArgumentParser(description="Attach eBPF uprobes to DPDK UPF for per-flow tagging.")
parser.add_argument('--binary', required=True, help='Path to DPDK UPF binary')
parser.add_argument('--pid', type=int, help='Target process PID (optional)')
parser.add_argument('--duration', type=int, default=30, help='Duration to run (seconds)')
args = parser.parse_args()

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

struct flow_key {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8  proto;
};
BPF_HASH(flow_cnt, struct flow_key, u64);

int count_rx(struct pt_regs *ctx) {
    // args: struct rte_mbuf **rx_pkts, ...
    void *mbufs = (void *)PT_REGS_PARM1(ctx);
    int nb_pkts = PT_REGS_RC(ctx);
    #pragma unroll
    for (int i = 0; i < 4; i++) { // Only sample first 4 packets per burst for demo
        void *mbuf_ptr = 0;
        bpf_probe_read_user(&mbuf_ptr, sizeof(mbuf_ptr), (void **)(mbufs + i * sizeof(void *)));
        if (!mbuf_ptr) continue;
        void *pkt_ptr = 0;
        bpf_probe_read_user(&pkt_ptr, sizeof(pkt_ptr), mbuf_ptr + 128); // offset: mbuf->buf_addr (approx)
        struct ethhdr eth;
        bpf_probe_read_user(&eth, sizeof(eth), pkt_ptr);
        if (eth.h_proto != __constant_htons(ETH_P_IP)) continue;
        struct iphdr iph;
        bpf_probe_read_user(&iph, sizeof(iph), pkt_ptr + sizeof(eth));
        struct flow_key key = {};
        key.src_ip = iph.saddr;
        key.dst_ip = iph.daddr;
        key.proto = iph.protocol;
        if (iph.protocol == IPPROTO_TCP) {
            struct tcphdr tcph;
            bpf_probe_read_user(&tcph, sizeof(tcph), pkt_ptr + sizeof(eth) + sizeof(iph));
            key.src_port = tcph.source;
            key.dst_port = tcph.dest;
        } else if (iph.protocol == IPPROTO_UDP) {
            struct udphdr udph;
            bpf_probe_read_user(&udph, sizeof(udph), pkt_ptr + sizeof(eth) + sizeof(iph));
            key.src_port = udph.source;
            key.dst_port = udph.dest;
        }
        u64 *cnt = flow_cnt.lookup(&key);
        u64 one = 1;
        if (cnt) (*cnt)++;
        else flow_cnt.update(&key, &one);
    }
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_uprobe(name=args.binary, sym="rte_eth_rx_burst", fn_name="count_rx", pid=args.pid)
b.attach_uretprobe(name=args.binary, sym="rte_eth_rx_burst", fn_name="count_rx", pid=args.pid)

print("Collecting per-flow packet counts for %d seconds..." % args.duration)
time.sleep(args.duration)

print("\nFlow counts:")
flow_cnt = b.get_table("flow_cnt")
for k, v in flow_cnt.items():
    src_ip = socket.inet_ntoa(struct.pack('I', k.src_ip))
    dst_ip = socket.inet_ntoa(struct.pack('I', k.dst_ip))
    print(f"{src_ip}:{k.src_port} -> {dst_ip}:{k.dst_port} proto={k.proto} count={v.value}")
