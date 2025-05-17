#include "vmlinux.h"             // BTF 기반 타입 정보
#include <linux/bpf.h>           // BPF 프로그램 매크로/상수 정의
#include <bpf/bpf_helpers.h>     // helper function들
#include <bpf/bpf_tracing.h>     // tracepoint용
#include <bpf/bpf_core_read.h>   // bpf_core_read 등
#include "event.h"

char LICENSE[] SEC("license") = "GPL";

struct trace_event_raw_sched_process_exec;
struct trace_event_raw_sched_process_exit;

// PERF 이벤트 맵 정의
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 128);
} events SEC(".maps");

// sys_enter_openat tracepoint용 구조체 정의
struct sys_enter_args {
    __u64 unused;
    __u64 id;
    __u64 args[6];
};

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct event evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.event_type = 0;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_exit *ctx) {
    struct event evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.event_type = 1;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_openat") // file open log 가져오기
int handle_open(struct sys_enter_args *ctx) {
    struct event evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.event_type = 2;  // 0: exec, 1: exit, 2: open

    // 파일 경로는 syscall 인자로부터 추출
    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_str(evt.filename, sizeof(evt.filename), filename);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}