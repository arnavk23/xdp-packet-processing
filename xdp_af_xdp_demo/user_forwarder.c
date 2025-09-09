// user_forwarder.c: AF_XDP user-space packet forwarder
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <bpf/xsk.h>

#define NUM_FRAMES 4096
#define FRAME_SIZE 2048
#define IFACE "veth0"

int main() {
    printf("AF_XDP user-space forwarder: starting up...\n");

    struct xsk_umem *umem = NULL;
    struct xsk_socket *xsk = NULL;
    struct xsk_umem_info {
        void *buffer;
        struct xsk_umem *umem;
        struct xsk_ring_prod fill_q;
        struct xsk_ring_cons comp_q;
    } umem_info;
    struct xsk_socket_info {
        struct xsk_socket *xsk;
        struct xsk_ring_cons rx;
        struct xsk_ring_prod tx;
        int fd;
    } xsk_info;

    // Allocate UMEM buffer
    void *buffer = NULL;
    if (posix_memalign(&buffer, getpagesize(), NUM_FRAMES * FRAME_SIZE)) {
        fprintf(stderr, "Failed to allocate UMEM buffer\n");
        return 1;
    }

    // Create UMEM
    if (xsk_umem__create(&umem, buffer, NUM_FRAMES * FRAME_SIZE, &umem_info.fill_q, &umem_info.comp_q, NULL)) {
        fprintf(stderr, "xsk_umem__create failed\n");
        return 1;
    }
    umem_info.buffer = buffer;
    umem_info.umem = umem;

    // Create AF_XDP socket
    int ifindex = if_nametoindex(IFACE);
    if (!ifindex) {
        fprintf(stderr, "Interface %s not found\n", IFACE);
        return 1;
    }
    if (xsk_socket__create(&xsk, IFACE, 0, umem, &xsk_info.rx, &xsk_info.tx, NULL)) {
        fprintf(stderr, "xsk_socket__create failed\n");
        return 1;
    }
    xsk_info.xsk = xsk;
    xsk_info.fd = xsk_socket__fd(xsk);

    printf("AF_XDP socket bound to %s. Ready to receive packets.\n", IFACE);

    // Main packet loop (demo: just receive and count)
    uint64_t rx_cnt = 0;
    while (rx_cnt < 10) { // receive 10 packets for demo
        uint32_t idx_rx = 0;
        int rcvd = xsk_ring_cons__peek(&xsk_info.rx, 1, &idx_rx);
        if (!rcvd) {
            usleep(1000);
            continue;
        }
        struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk_info.rx, idx_rx);
        void *pkt = (uint8_t *)umem_info.buffer + desc->addr;
        printf("Received packet %lu, length %u\n", rx_cnt + 1, desc->len);
        xsk_ring_cons__release(&xsk_info.rx, 1);
        rx_cnt++;
    }

    printf("Demo complete. Received %lu packets.\n", rx_cnt);
    xsk_socket__delete(xsk);
    xsk_umem__delete(umem);
    free(buffer);
    return 0;
}
