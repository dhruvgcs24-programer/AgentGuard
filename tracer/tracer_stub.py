"""
AgentGuard - Tracer Module (P1: Kernel Observability & eBPF)
============================================================
Simulates BCC/bpftrace event stream tracking system calls (execve, openat, connect),
maintains process-tree ancestry, and defines cgroup/sockops hooks for socket inspection
(e.g., local Ollama port 11434).
"""

import os
import sys
import time
import json
import random
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

# Default shared event log path
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
EVENT_LOG_FILE = os.path.join(DATA_DIR, "events.jsonl")

# C-code representation of the eBPF programs for WSL2 / Linux kernel
EBPF_CGROUP_SOCK_OPS_C = r"""
// AgentGuard eBPF C Hook: Intercept socket connection requests for Ollama cgroup
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define OLLAMA_PORT 11434
#define AF_INET 2

struct event_t {
    __u32 pid;
    __u32 ppid;
    __u32 daddr;
    __u16 dport;
    char comm[16];
    __u8 is_tainted;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("cgroup/connect4")
int sock4_connect(struct bpf_sock_addr *ctx) {
    if (ctx->user_family != AF_INET) {
        return 1; // Allow non-IPv4 for now
    }

    __u16 dst_port = bpf_ntohs(ctx->user_port);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 1;

    evt->pid = pid;
    evt->dport = dst_port;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    // If destination is Ollama (11434) and process state is flagged TAINTED in map,
    // we can either block (return 0) or emit telemetry for Landlock/Broker.
    bpf_ringbuf_submit(evt, 0);
    return 1;
}

char _license[] SEC("license") = "GPL";
"""

@dataclass
class KernelTraceEvent:
    timestamp: str
    pid: int
    ppid: int
    comm: str
    syscall: str
    target: str
    port: Optional[int]
    status: str       # "ALLOWED", "AUDIT_VIOLATION", "BLOCKED"
    agent_state: str  # "TRUSTED", "TAINTED"
    details: str

class ProcessTreeTracker:
    """Tracks PID hierarchy (Agent -> Tool Broker -> Subprocess / Worker)"""
    def __init__(self):
        self.tree: Dict[int, Dict[str, Any]] = {}

    def register_process(self, pid: int, ppid: int, comm: str, state: str = "TRUSTED"):
        self.tree[pid] = {
            "pid": pid,
            "ppid": ppid,
            "comm": comm,
            "state": state,
            "children": [],
            "created_at": time.time()
        }
        if ppid in self.tree:
            self.tree[ppid]["children"].append(pid)

    def set_taint(self, pid: int, cascade: bool = True):
        """Mark a process as TAINTED and cascade to all children in the tree."""
        if pid in self.tree:
            self.tree[pid]["state"] = "TAINTED"
            if cascade:
                for child_pid in self.tree[pid]["children"]:
                    self.set_taint(child_pid, cascade=True)

    def get_state(self, pid: int) -> str:
        return self.tree.get(pid, {}).get("state", "TRUSTED")

    def get_tree_dump(self) -> Dict[int, Dict[str, Any]]:
        return self.tree


class BPFTracerStub:
    """
    Simulates / Interfaces BCC / bpftrace event stream.
    When running in full WSL2 with root, it can load actual BCC hooks.
    When run in development/testing mode, it emits high-fidelity synthetic/live events.
    """
    def __init__(self, log_path: str = EVENT_LOG_FILE):
        self.log_path = log_path
        self.tree_tracker = ProcessTreeTracker()
        self._ensure_log_dir()

        # Seed initial agent hierarchy
        agent_pid = 2001
        broker_pid = 2002
        self.tree_tracker.register_process(agent_pid, 1, "ollama_agent", "TRUSTED")
        self.tree_tracker.register_process(broker_pid, agent_pid, "tool_broker", "TRUSTED")

    def _ensure_log_dir(self):
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def log_event(self, event: KernelTraceEvent):
        """Append trace event to JSON Lines file for dashboard and policy ingestion."""
        self._ensure_log_dir()
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(event)) + "\n")

    def emit_syscall(self, pid: int, comm: str, syscall: str, target: str,
                     agent_state: str, status: str = "ALLOWED",
                     port: Optional[int] = None, details: str = "") -> KernelTraceEvent:
        event = KernelTraceEvent(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            pid=pid,
            ppid=self.tree_tracker.tree.get(pid, {}).get("ppid", 1000),
            comm=comm,
            syscall=syscall,
            target=target,
            port=port,
            status=status,
            agent_state=agent_state,
            details=details
        )
        self.log_event(event)
        return event

    def simulate_event_stream(self, count: int = 10, interval_sec: float = 0.5):
        """Generates a realistic stream of kernel observability events."""
        print(f"[*] Starting eBPF Tracer Event Stream ({count} events)...")
        print(f"[*] Writing to log file: {self.log_path}")

        scenarios = [
            # Benign syscalls in TRUSTED state
            (2002, "tool_broker", "execve", "/usr/bin/python3", "TRUSTED", "ALLOWED", None, "Tool process execution"),
            (2003, "python3", "openat", "/workspace/project/main.py", "TRUSTED", "ALLOWED", None, "Read project source"),
            (2003, "python3", "connect", "127.0.0.1", "TRUSTED", "ALLOWED", 11434, "Local Ollama model query"),
            (2003, "python3", "openat", "/workspace/output/result.txt", "TRUSTED", "ALLOWED", None, "Write tool result"),
            # Transition to TAINTED
            (2001, "ollama_agent", "execve", "prompt_evaluator", "TAINTED", "ALLOWED", None, "Prompt injection detected"),
            # Policy violations under TAINTED state
            (2004, "bash", "openat", "/etc/shadow", "TAINTED", "BLOCKED", None, "Landlock FS denial: Access outside allowed subtree"),
            (2004, "bash", "connect", "198.51.100.4", "TAINTED", "BLOCKED", 4444, "Landlock NET denial: Port not in TCP allowlist"),
            (2004, "curl", "connect", "127.0.0.1", "TAINTED", "ALLOWED", 11434, "Ollama API access allowed (TCP port 11434)"),
            (2004, "bash", "openat", "/home/user/.ssh/id_rsa", "TAINTED", "AUDIT_VIOLATION", None, "Audit mode alert: Unauthorized credential access"),
            (2005, "cat", "openat", "/tmp/agent_output.log", "TAINTED", "ALLOWED", None, "Temporary file read")
        ]

        for i in range(count):
            item = scenarios[i % len(scenarios)]
            evt = self.emit_syscall(
                pid=item[0],
                comm=item[1],
                syscall=item[2],
                target=item[3],
                agent_state=item[4],
                status=item[5],
                port=item[6],
                details=item[7]
            )
            print(f"[{evt.timestamp}] [eBPF] {evt.syscall:<7} comm={evt.comm:<12} pid={evt.pid} state={evt.agent_state:<7} status={evt.status:<15} target={evt.target}")
            time.sleep(interval_sec)

    def print_ebpf_source_header(self):
        """Displays the C hook code utilized for eBPF cgroup network socket enforcement."""
        print("=== eBPF cgroup/sockops C Program Template ===")
        print(EBPF_CGROUP_SOCK_OPS_C.strip())
        print("===============================================")

if __name__ == "__main__":
    tracer = BPFTracerStub()
    if "--show-c" in sys.argv:
        tracer.print_ebpf_source_header()
    else:
        tracer.simulate_event_stream(count=8, interval_sec=0.2)

