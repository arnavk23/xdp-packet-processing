/* userspace loader for recv_count.bpf.o
 * Minimal example: open object, attach uprobe and uretprobe to symbol and print map
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile sig_atomic_t exiting = 0;
static void sig_handler(int sig) { exiting = 1; }

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <pid> <symbol>\n", argv[0]);
        return 1;
    }
    pid_t pid = atoi(argv[1]);
    const char *symbol = argv[2];

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct bpf_object *obj = NULL;
    struct bpf_program *prog_entry, *prog_ret;
    struct bpf_link *link_entry = NULL, *link_ret = NULL;
    int map_fd = -1;

    obj = bpf_object__open_file("recv_count.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    prog_entry = bpf_object__find_program_by_name(obj, "probe_entry");
    prog_ret = bpf_object__find_program_by_name(obj, "probe_return");
    if (!prog_entry || !prog_ret) {
        fprintf(stderr, "Could not find programs in object\n");
        goto cleanup;
    }

    // attach uprobes to the target pid executable
    char exe_path[PATH_MAX];
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);

    link_entry = bpf_program__attach_uprobe(prog_entry, false, pid, exe_path, symbol);
    if (!link_entry) {
        fprintf(stderr, "Failed to attach entry uprobe\n");
        goto cleanup;
    }
    link_ret = bpf_program__attach_uprobe(prog_ret, true, pid, exe_path, symbol);
    if (!link_ret) {
        fprintf(stderr, "Failed to attach return uprobe\n");
        goto cleanup;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "pkt_count");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map fd\n");
        goto cleanup;
    }

    printf("Attached. Printing totals every 1s. Ctrl-C to quit.\n");
    while (!exiting) {
        sleep(1);
        long long total = 0;
        u32 key = 0;
        unsigned long long val;
        if (bpf_map_lookup_elem(map_fd, &key, &val) == 0) {
            total = (long long)val;
        }
        printf("total=%lld\n", total);
    }

cleanup:
    if (link_entry)
        bpf_link__destroy(link_entry);
    if (link_ret)
        bpf_link__destroy(link_ret);
    if (obj)
        bpf_object__close(obj);
    return 0;
}
