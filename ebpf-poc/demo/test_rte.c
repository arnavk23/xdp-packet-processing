/* Synthetic DPDK-like test program used for the eBPF PoC.
 * Exports a non-inlined symbol `rte_eth_rx_burst` and calls it
 * repeatedly so uprobes can observe it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

/* Prevent inlining so the symbol exists at runtime for uprobes. */
int __attribute__((noinline)) rte_eth_rx_burst(void) {
    int v = rand() % 65;
    return v;
}

int main(int argc, char **argv) {
    srand(0xdeadbeef);
    printf("test_rte: pid=%d starting loop\\n", getpid());
    fflush(stdout);
    while (1) {
        int r = rte_eth_rx_burst();
        usleep(50000); /* 50ms */
        static int cnt = 0;
        if (++cnt % 20 == 0) {
            printf("test_rte: called rte_eth_rx_burst -> %d\\n", r);
            fflush(stdout);
        }
    }
    return 0;
}
