# eBPF Makefile for AgentGuard
CLANG ?= clang
CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu

TARGET = agentguard.bpf.o
SRC = agentguard.bpf.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET)

.PHONY: all clean

