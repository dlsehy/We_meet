#include "vmlinux.h"             // BTF 기반 타입 정보
#include <bpf/bpf_helpers.h>     // helper function들
#include <bpf/bpf_tracing.h>     // tracepoint용
#include <bpf/bpf_core_read.h>   // bpf_core_read 등
#include <bpf/bpf_endian.h>
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

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    evt.ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.event_type = 0;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}


SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_exit *ctx) {
    struct event evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    evt.ppid = BPF_CORE_READ(task, real_parent, tgid);
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

    bpf_printk("📂 open: pid=%d file=%s\n", evt.pid, evt.filename); // 디버깅

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}
SEC("kprobe/tcp_connect")
int handle_tcp_connect(struct pt_regs *ctx, struct sock *sk) {
    struct event evt = {};
    __u16 dport;
    __u32 daddr;

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.event_type = 3;

    sk = (struct sock *)PT_REGS_PARM1(ctx);

    bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

    evt.dport = __bpf_ntohs(dport);
    evt.daddr = daddr;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}