"""
AgentGuard - Policy Engine Module (P4: Baseline Generator)
==========================================================
Ingests benign run trace logs emitted by eBPF/Landlock and generates
a strict, least-privilege YAML policy specification.
"""

import os
import json
import yaml
from typing import List, Dict, Any, Set

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT_DIR, "data")
DEFAULT_EVENTS_FILE = os.path.join(DATA_DIR, "events.jsonl")
OUTPUT_POLICY_FILE = os.path.join(ROOT_DIR, "policy", "baseline_policy.yaml")

class BaselinePolicyGenerator:
    """
    Parses execution logs from trusted agent sessions to synthesize
    minimal required filesystem and network permissions.
    """
    def __init__(self, log_path: str = DEFAULT_EVENTS_FILE):
        self.log_path = log_path

    def generate_policy(self, output_path: str = OUTPUT_POLICY_FILE) -> Dict[str, Any]:
        """
        Scans trace log for 'ALLOWED' and 'TRUSTED' events to extract:
          - Read-only directories
          - Write-only directories
          - Permitted TCP ports
          - Permitted binaries/commands
        """
        ro_paths: Set[str] = set()
        wo_paths: Set[str] = set()
        allowed_ports: Set[int] = set()
        allowed_binaries: Set[str] = set()

        if os.path.exists(self.log_path):
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        evt = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    # Only learn baselines from verified TRUSTED & ALLOWED runs
                    if evt.get("agent_state") == "TRUSTED" and evt.get("status") == "ALLOWED":
                        comm = evt.get("comm")
                        if comm:
                            allowed_binaries.add(comm)

                        port = evt.get("port")
                        if port:
                            allowed_ports.add(int(port))

                        target = evt.get("target", "")
                        syscall = evt.get("syscall", "")

                        if "open" in syscall:
                            # Classify read vs write paths
                            if any(out in target.lower() for out in ["output", "tmp", "result", "log"]):
                                wo_paths.add(os.path.dirname(target) or target)
                            else:
                                ro_paths.add(os.path.dirname(target) or target)

        # Fallback defaults if log was sparse
        if not ro_paths:
            ro_paths.add(os.path.join(ROOT_DIR, "project"))
        if not wo_paths:
            wo_paths.add(os.path.join(ROOT_DIR, "output"))
        if not allowed_ports:
            allowed_ports.add(11434)  # Ollama standard port
        if not allowed_binaries:
            allowed_binaries.update(["python3", "ollama_agent", "tool_broker"])

        policy: Dict[str, Any] = {
            "version": "1.0",
            "name": "agentguard_least_privilege_baseline",
            "description": "Synthesized Landlock + eBPF security boundary for Ollama Agent workloads",
            "landlock_abi_target": 4,
            "filesystem": {
                "read_only_paths": sorted(list(ro_paths)),
                "write_only_paths": sorted(list(wo_paths)),
                "forbidden_denylist": [
                    "/etc/shadow",
                    "/etc/passwd",
                    "~/.ssh",
                    "credentials.env"
                ]
            },
            "network": {
                "allowed_tcp_ports": sorted(list(allowed_ports)),
                "block_all_outbound_by_default": True
            },
            "taint_policy": {
                "transition_action": "RESTRICT_TO_AUDIT_OR_BLOCK",
                "cascade_to_child_pids": True
            }
        }

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            yaml.dump(policy, f, default_flow_style=False, sort_keys=False)

        print(f"[*] Successfully generated baseline policy: {output_path}")
        return policy

if __name__ == "__main__":
    generator = BaselinePolicyGenerator()
    pol = generator.generate_policy()
    print(yaml.dump(pol, default_flow_style=False))

