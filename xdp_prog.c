#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_redirect(struct xdp_md *ctx) {
    // Redirect all packets to user space via XDP_PASS (for AF_XDP)
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
