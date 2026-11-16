# AgentGuard: Context-Aware Kernel Guardrails for Local AI Agents

> **Production-Grade Kernel Enforcement using eBPF & Landlock LSM on WSL2**  
> Complete architecture, compiled C kernel sandbox, multi-layered taint engine, and live monitoring dashboard for **Review 2** and Capstone deployment.

---

## 🏛️ Real Production Architecture vs. Traditional User-Space Filters

Unlike conventional AI guardrails that rely strictly on user-space prompt screening (which can be bypassed by jailbreaks, base64 encoding, or token manipulation), **AgentGuard enforces security boundaries directly inside the Linux Kernel (LSM)**.

```
+-----------------------------------------------------------------------------------------+
|                                USER PROMPT / INSTRUCTION                                |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
| [P3] agent/ai_agent.py (AI Agent & Multi-Layered Taint Engine)                          |
|  - Prompt Injection Scanner (DAN, jailbreaks, system overrides, base64 payloads)        |
|  - Sensitive Target Detector (/etc/shadow, .ssh/id_rsa, credentials.env)                |
|  - Dynamic Session Transition: TRUSTED -> TAINTED                                       |
|  - Ollama Inference Coordinator (127.0.0.1:11434)                                       |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
| [P2] enforce/broker.py & enforce/bin/agentguard-executor (Compiled C Sandboxing Binary)  |
|  - Post-fork, pre-execve Landlock LSM Sandbox written in C                              |
|  - Syscalls: landlock_create_ruleset, landlock_add_rule, landlock_restrict_self        |
|  - Mandatory prctl(PR_SET_NO_NEW_PRIVS)                                                 |
|  - Read-Only project bounds, Write-Only output scratch, Ollama TCP 11434 only           |
|  - In TAINTED state: Zero network outbound, all sensitive paths denied by kernel        |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
| [P1] tracer/tracer_stub.py & tracer/bpf/agentguard.bpf.c (Kernel Observability)         |
|  - eBPF Tracepoints: tp/syscalls/sys_enter_execve, tp/syscalls/sys_enter_openat         |
|  - BPF Ringbuffer zero-copy telemetry stream to events.jsonl                            |
|  - cgroup/connect4 socket filter protecting Ollama port 11434                           |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
| [P4] policy/dashboard.py & baseline_generator.py (Policy Engine & Streamlit UI)         |
|  - Streamlit Live Monitoring Dashboard with real-time metric cards                      |
|  - Interactive attack trigger bar for Review 2 evaluation                               |
|  - Automatic synthesis of least-privilege YAML policy from benign trace logs            |
+-----------------------------------------------------------------------------------------+
```

---

## 📁 Repository Structure

```
agentguard/
├── README.md                      # Comprehensive production documentation
├── requirements.txt               # Dependencies (streamlit, pandas, pyyaml)
├── demo_runner.py                 # End-to-end pipeline verification script
├── setup_wsl2.sh                  # Turnkey compilation & test script for WSL2
├── tests/
│   └── test_production.py         # 8-point automated production test suite (All passing)
├── enforce/                       # [P2] Kernel Enforcement & Tool Broker
│   ├── __init__.py
│   ├── broker.py                  # Tool broker dispatching to compiled C executor
│   ├── bin/
│   │   └── agentguard-executor    # Compiled Linux C binary enforcing Landlock
│   └── c_src/
│       ├── agentguard-executor.c  # Source code for Landlock C executor
│       └── Makefile
├── tracer/                        # [P1] Kernel Observability & eBPF
│   ├── __init__.py
│   ├── tracer_stub.py             # Event stream logger & ProcessTreeTracker
│   └── bpf/
│       ├── agentguard.bpf.c       # Production eBPF C program (execve, openat, cgroup/connect4)
│       └── Makefile
├── agent/                         # [P3] AI Agent & Taint Tracking
│   ├── __init__.py
│   └── ai_agent.py                # Ollama simulator, 4 tools, multi-layered taint engine
├── policy/                        # [P4] Policy Engine & Streamlit UI
│   ├── __init__.py
│   ├── dashboard.py               # Streamlit live monitoring dashboard
│   ├── baseline_generator.py      # Synthesizes least-privilege baseline_policy.yaml
│   ├── default_policy.yaml        # Active baseline security policy
│   └── baseline_policy.yaml       # Auto-generated baseline policy
├── project/                       # Read-only project workspace
│   └── main.py
├── output/                        # Write-only output workspace
│   └── summary.txt
└── data/                          # Shared telemetry store
    ├── events.jsonl
    └── agent_state.json
```

---

## ⚡ Quickstart & Live Review 2 Demo

### 1. Run the Automated Production Test Suite (8/8 Passing)
Verify that real Linux Landlock LSM is active and blocking unauthorized file/socket operations:
```powershell
python agentguard/tests/test_production.py
```
*Output:*
```
test_01_landlock_abi_version ... ok
test_02_compiled_c_executor_exists ... ok
test_03_benign_tool_allowed ... ok
test_04_filesystem_restriction_blocks_shadow ... ok (cat: /etc/shadow: Permission denied)
test_05_network_restriction_blocks_external_port ... ok (curl: connect Permission denied)
test_06_prompt_injection_detection ... ok
test_07_benign_prompt_remains_trusted ... ok
test_08_baseline_policy_synthesis ... ok
----------------------------------------------------------------------
Ran 8 tests in 8.95s - OK
```

### 2. Run the End-to-End Pipeline
Executes a safe analysis turn, triggers an adversarial file-dump attack, triggers network exfiltration, and synthesizes the least-privilege baseline:
```powershell
python agentguard/demo_runner.py
```

### 3. Launch the Streamlit Live Monitoring Dashboard
```powershell
streamlit run agentguard/policy/dashboard.py
```

---

## 🔬 How Real Kernel Enforcement Works in AgentGuard

### 1. Post-Fork, Pre-Execve C Landlock Executor (`agentguard-executor.c`)
In standard Python, `subprocess.Popen` cannot apply Landlock rules inside the child process without risking main thread corruption. AgentGuard solves this by deploying a dedicated C wrapper (`enforce/bin/agentguard-executor`):
1. Creates a Landlock ruleset handling all filesystem permissions (`ACCESS_FS_READ_FILE`, `ACCESS_FS_WRITE_FILE`, `ACCESS_FS_EXECUTE`, etc.).
2. Creates TCP network rules (`ACCESS_NET_CONNECT_TCP`) restricting outbound traffic exclusively to port `11434` (Ollama).
3. Adds `LANDLOCK_RULE_PATH_BENEATH` for allowed read-only and read-write directories.
4. Invokes `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`.
5. Calls `landlock_restrict_self()`.
6. Executes `execvp()` to run the tool binary.
7. Any attempt by the tool to access `/etc/shadow` or connect to an unauthorized port is denied with `EACCES` (`Permission denied`) by the kernel.

### 2. Multi-Layered Taint Classification (`ai_agent.py`)
- **Layer 1:** Scans incoming prompts for prompt injection signatures (`ignore previous instructions`, `DAN mode`, `system override`).
- **Layer 2:** Scans for obfuscated Base64 payloads and decodes them on the fly.
- **Layer 3:** Scans for sensitive target paths (`/etc/shadow`, `credentials.env`, `id_rsa`) and external C2 ports (`4444`, `1337`).
- **State Transition:** When flagged, the session immediately drops to `TAINTED`. In `TAINTED` state, all outbound network ports are stripped from the Landlock ruleset, enforcing total offline isolation.

### 3. eBPF Observability & cgroup Socket Filter (`agentguard.bpf.c`)
- Uses `SEC("tp/syscalls/sys_enter_execve")` and `SEC("tp/syscalls/sys_enter_openat")` to stream high-throughput events via `BPF_MAP_TYPE_RINGBUF`.
- Enforces local Ollama binding using `SEC("cgroup/connect4")` so processes cannot establish rogue sockets.
