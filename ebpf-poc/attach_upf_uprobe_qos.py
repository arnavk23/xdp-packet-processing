#!/usr/bin/env python3
"""
attach_upf_uprobe_qos.py

BCC-based script to attach uprobes to DPDK UPF, collect per-flow (5-tuple) packet counts and QoS metrics (DSCP, packet size) using eBPF.
Extends flow tagging with QoS analytics.

Usage:
  sudo python3 attach_upf_uprobe_qos.py --binary /path/to/upf_binary

Requires: bcc, root privileges, and a DPDK binary exporting rte_eth_rx_burst.
"""
from bcc import BPF, USDT
import argparse
import socket
import struct
import time

parser = argparse.ArgumentParser(description="Attach eBPF uprobes to DPDK UPF for per-flow QoS analytics.")
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
struct qos_stats {
    u64 pkt_count;
    u64 total_bytes;
    u64 dscp_hist[64];
};
BPF_HASH(flow_qos, struct flow_key, struct qos_stats);

int count_rx(struct pt_regs *ctx) {
    void *mbufs = (void *)PT_REGS_PARM1(ctx);
    int nb_pkts = PT_REGS_RC(ctx);
    #pragma unroll
    for (int i = 0; i < 4; i++) {
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
        u8 dscp = (iph.tos & 0xfc) >> 2;
        u64 pkt_len = iph.tot_len;
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
        struct qos_stats *stats = flow_qos.lookup(&key);
        struct qos_stats zero = {};
        if (!stats) {
            flow_qos.update(&key, &zero);
            stats = flow_qos.lookup(&key);
        }
        if (stats) {
            stats->pkt_count++;
            stats->total_bytes += pkt_len;
            if (dscp < 64) stats->dscp_hist[dscp]++;
        }
    }
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_uprobe(name=args.binary, sym="rte_eth_rx_burst", fn_name="count_rx", pid=args.pid)
b.attach_uretprobe(name=args.binary, sym="rte_eth_rx_burst", fn_name="count_rx", pid=args.pid)

print("Collecting per-flow QoS stats for %d seconds..." % args.duration)
time.sleep(args.duration)

print("\nFlow QoS stats:")
flow_qos = b.get_table("flow_qos")
for k, v in flow_qos.items():
    src_ip = socket.inet_ntoa(struct.pack('I', k.src_ip))
    dst_ip = socket.inet_ntoa(struct.pack('I', k.dst_ip))
    print(f"{src_ip}:{k.src_port} -> {dst_ip}:{k.dst_port} proto={k.proto} count={v.pkt_count} bytes={v.total_bytes}")
    dscp_summary = ', '.join([f"{i}:{v.dscp_hist[i]}" for i in range(64) if v.dscp_hist[i]])
    if dscp_summary:
        print(f"  DSCP histogram: {dscp_summary}")
