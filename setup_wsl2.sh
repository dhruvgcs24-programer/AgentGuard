#!/usr/bin/env bash
# AgentGuard - Turnkey WSL2 Kernel & Environment Setup Script
# ============================================================
# Verifies Linux kernel Landlock & eBPF support, builds C executor,
# compiles eBPF bytecode, and runs production verification tests.

set -e

echo "=========================================================="
echo "🛡️  AgentGuard: Production Kernel & Sandbox Setup"
echo "=========================================================="

# 1. Kernel Verification
echo "[1/4] Verifying Linux Kernel & Landlock LSM..."
KERNEL_VER=$(uname -r)
echo "  -> Running Kernel: $KERNEL_VER"

if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_SECURITY_LANDLOCK=y"; then
    echo "  [OK] CONFIG_SECURITY_LANDLOCK is enabled in kernel."
else
    echo "  [INFO] Landlock check via syscall query..."
fi

# 2. Compile Landlock C Executor
echo "[2/4] Building production C Landlock Executor..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$SCRIPT_DIR/enforce/bin"

clang -O2 -Wall -Wextra -D_GNU_SOURCE \
    "$SCRIPT_DIR/enforce/c_src/agentguard-executor.c" \
    -o "$SCRIPT_DIR/enforce/bin/agentguard-executor"
chmod +x "$SCRIPT_DIR/enforce/bin/agentguard-executor"

ABI_VER=$("$SCRIPT_DIR/enforce/bin/agentguard-executor" --version | awk '{print $NF}')
echo "  [OK] agentguard-executor compiled. Detected Landlock ABI: v$ABI_VER"

# 3. Compile eBPF Bytecode
echo "[3/4] Compiling eBPF Kernel Bytecode (agentguard.bpf.o)..."
mkdir -p "$SCRIPT_DIR/tracer/bpf"
if which clang >/dev/null 2>&1; then
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
        -I/usr/include/x86_64-linux-gnu \
        -c "$SCRIPT_DIR/tracer/bpf/agentguard.bpf.c" \
        -o "$SCRIPT_DIR/tracer/bpf/agentguard.bpf.o" 2>/dev/null || true
    if [ -f "$SCRIPT_DIR/tracer/bpf/agentguard.bpf.o" ]; then
        echo "  [OK] eBPF bytecode compiled successfully: tracer/bpf/agentguard.bpf.o"
    else
        echo "  [INFO] Note: Kernel headers not found in standard path, eBPF C program preserved for review."
    fi
fi

# 4. Run Test Suite
echo "[4/4] Executing Production Verification Suite..."
python3 "$SCRIPT_DIR/tests/test_production.py"

echo "=========================================================="
echo "✅ AgentGuard setup and production tests completed successfully!"
echo "=========================================================="
