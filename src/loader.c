#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <sys/resource.h>
#include "procmon.skel.h"
#include "event.h"

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz);
static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt);

static volatile sig_atomic_t exiting = 0;

struct perf_buffer *pb;

static void handle_signal(int sig) {
    exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct event *e = data;

    if (e->event_type == 2) { // open
        printf("{\"pid\": %u, \"comm\": \"%s\", \"event_type\": \"open\", \"filename\": \"%s\"}\n",
               e->pid, e->comm, e->filename);
    } else {
        printf("{\"pid\": %u, \"comm\": \"%s\", \"event_type\": \"%s\"}\n",
               e->pid, e->comm,
               e->event_type == 0 ? "exec" : "exit");
    }
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

static void bump_memlock_rlimit(void) {
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        exit(1);
    }
}

int main() {
    struct procmon_bpf *skel;

    bump_memlock_rlimit();

    skel = procmon_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    if (procmon_bpf__attach(skel)) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        procmon_bpf__destroy(skel);
        return 1;
    }

    struct perf_buffer_opts pb_opts = {
        .sample_cb = handle_event,
        .lost_cb = handle_lost_events,
    };
    
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8, &pb_opts);

    if (!pb) {
        fprintf(stderr, "Failed to open perf buffer\n");
        procmon_bpf__destroy(skel);
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("BPF programs loaded and attached. Monitoring process events...\n");

    while (!exiting) {
        int err = perf_buffer__poll(pb, 100);
        if (err < 0 && errno != EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

    perf_buffer__free(pb);
    procmon_bpf__destroy(skel);
    return 0;
}