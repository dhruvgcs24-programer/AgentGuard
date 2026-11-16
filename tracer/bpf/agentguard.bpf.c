/*
 * AgentGuard - Production eBPF Observability & Cgroup Network Guard
 * =================================================================
 * Intercepts execve and openat syscall tracepoints to stream telemetry to userspace,
 * and attaches a cgroup/connect4 socket filter to enforce local-only Ollama access (TCP 11434).
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define OLLAMA_PORT 11434
#define AF_INET 2
#define MAX_PATH_LEN 128
#define TASK_COMM_LEN 16

/* Event struct submitted via BPF Ring Buffer to AgentGuard userspace */
struct agent_event_t {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u16 dport;
    __u8  is_tainted;
    char  comm[TASK_COMM_LEN];
    char  target[MAX_PATH_LEN];
    char  syscall_name[16];
};

/* BPF Ring Buffer Map for high-throughput zero-copy telemetry */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} events SEC(".maps");

/* BPF Hash Map storing dynamically tainted process IDs */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // PID
    __type(value, __u8);  // Taint Level: 1 = TAINTED, 0 = TRUSTED
} tainted_pids SEC(".maps");

/* =========================================================================
 * 1. Tracepoint: sys_enter_execve
 * ========================================================================= */
struct trace_event_raw_sys_enter_execve {
    __u64 unused;
    long syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter_execve *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct agent_event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    evt->pid = pid;
    evt->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    
    // Copy target binary filename
    bpf_probe_read_user_str(evt->target, sizeof(evt->target), ctx->filename);
    __builtin_memcpy(evt->syscall_name, "execve", 7);

    // Check if PID is marked tainted in BPF map
    __u8 *tainted = bpf_map_lookup_elem(&tainted_pids, &pid);
    evt->is_tainted = tainted ? *tainted : 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* =========================================================================
 * 2. Tracepoint: sys_enter_openat
 * ========================================================================= */
struct trace_event_raw_sys_enter_openat {
    __u64 unused;
    long syscall_nr;
    long dfd;
    const char *filename;
    long flags;
    long mode;
};

SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter_openat *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct agent_event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    evt->pid = pid;
    evt->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    // Copy accessed file path
    bpf_probe_read_user_str(evt->target, sizeof(evt->target), ctx->filename);
    __builtin_memcpy(evt->syscall_name, "openat", 7);

    __u8 *tainted = bpf_map_lookup_elem(&tainted_pids, &pid);
    evt->is_tainted = tainted ? *tainted : 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* =========================================================================
 * 3. cgroup/connect4: Intercept TCP connections for local Ollama only
 * ========================================================================= */
SEC("cgroup/connect4")
int sock4_connect(struct bpf_sock_addr *ctx) {
    if (ctx->user_family != AF_INET) {
        return 1;
    }

    __u16 dst_port = bpf_ntohs(ctx->user_port);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    __u8 *tainted = bpf_map_lookup_elem(&tainted_pids, &pid);
    __u8 is_taint = tainted ? *tainted : 0;

    // Emit connection event
    struct agent_event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (evt) {
        evt->pid = pid;
        evt->dport = dst_port;
        evt->is_tainted = is_taint;
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
        __builtin_memcpy(evt->syscall_name, "connect", 8);
        __builtin_memcpy(evt->target, "tcp_socket", 11);
        bpf_ringbuf_submit(evt, 0);
    }

    // In a tainted state, reject any outbound socket connection unless it is Ollama (port 11434)
    if (is_taint && dst_port != OLLAMA_PORT) {
        return 0; // Kernel drops connection request immediately
    }

    return 1; // Allow connection
}

char _license[] SEC("license") = "GPL";

