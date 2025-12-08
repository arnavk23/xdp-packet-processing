// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} pkt_count SEC(".maps");

struct args_t {
    void *ptrs;
};

SEC("uprobe/entry")
int probe_entry(struct pt_regs *ctx)
{
    // store nothing heavy here; we only mark the event present
    return 0;
}

SEC("uprobe/return")
int probe_return(struct pt_regs *ctx)
{
    // on return, the return value (number of packets) is usually in RAX
#ifdef __x86_64__
    long ret = PT_REGS_RC(ctx);
#else
    long ret = 0;
#endif
    if (ret <= 0)
        return 0;

    u32 key = 0;
    u64 *val = bpf_map_lookup_elem(&pkt_count, &key);
    if (!val)
        return 0;
    __sync_fetch_and_add(val, (u64)ret);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
