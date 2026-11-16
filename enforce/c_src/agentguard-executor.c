/*
 * AgentGuard - Production Landlock Sandboxing Executor (C Implementation)
 * =======================================================================
 * This binary acts as the isolated execution wrapper for AI Agent tools.
 * It is invoked post-fork and pre-execve to configure the Linux kernel's
 * Landlock LSM ruleset and PR_SET_NO_NEW_PRIVS before execvp() replaces
 * the process image.
 *
 * Supported Features:
 *   - Read-only directory allowlisting (LANDLOCK_RULE_PATH_BENEATH)
 *   - Write-only / Read-Write directory allowlisting
 *   - TCP port filtering (LANDLOCK_RULE_NET_PORT, Landlock ABI v4+)
 *   - PR_SET_NO_NEW_PRIVS enforcement
 *   - Strict "enforce" vs soft "audit" modes
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <linux/prctl.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif

#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif

#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

#ifndef LANDLOCK_RULE_PATH_BENEATH
#define LANDLOCK_RULE_PATH_BENEATH 1
#endif

#ifndef LANDLOCK_RULE_NET_PORT
#define LANDLOCK_RULE_NET_PORT 2
#endif

/* Filesystem Access Rights */
#define ACCESS_FS_EXECUTE     (1ULL << 0)
#define ACCESS_FS_WRITE_FILE  (1ULL << 1)
#define ACCESS_FS_READ_FILE   (1ULL << 2)
#define ACCESS_FS_READ_DIR    (1ULL << 3)
#define ACCESS_FS_REMOVE_DIR  (1ULL << 4)
#define ACCESS_FS_REMOVE_FILE (1ULL << 5)
#define ACCESS_FS_MAKE_CHAR   (1ULL << 6)
#define ACCESS_FS_MAKE_DIR    (1ULL << 7)
#define ACCESS_FS_MAKE_REG    (1ULL << 8)
#define ACCESS_FS_MAKE_SOCK   (1ULL << 9)
#define ACCESS_FS_MAKE_FIFO   (1ULL << 10)
#define ACCESS_FS_MAKE_BLOCK  (1ULL << 11)
#define ACCESS_FS_MAKE_SYM    (1ULL << 12)
#define ACCESS_FS_REFER       (1ULL << 13)
#define ACCESS_FS_TRUNCATE    (1ULL << 14)

/* Network Access Rights (ABI v4+) */
#define ACCESS_NET_BIND_TCP    (1ULL << 0)
#define ACCESS_NET_CONNECT_TCP (1ULL << 1)

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

struct landlock_ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;
};

struct landlock_path_beneath_attr {
    uint64_t allowed_access;
    int32_t parent_fd;
};

struct landlock_net_port_attr {
    uint64_t allowed_access;
    uint64_t port;
};

static int landlock_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size, uint32_t flags) {
    return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static int landlock_add_rule(int ruleset_fd, int rule_type, const void *rule_attr, uint32_t flags) {
    return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
}

static int landlock_restrict_self(int ruleset_fd, uint32_t flags) {
    return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

static int get_landlock_abi_version(void) {
    return landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
}

static int add_path_rule(int ruleset_fd, const char *path, uint64_t access) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        return -1; // Silently skip missing optional paths
    }

    struct stat st;
    if (fstat(fd, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            /* Strip directory-only rights for regular files to prevent EINVAL */
            access &= ~(ACCESS_FS_READ_DIR | ACCESS_FS_REMOVE_DIR | ACCESS_FS_MAKE_DIR);
        }
    }

    struct landlock_path_beneath_attr path_attr = {
        .allowed_access = access,
        .parent_fd = fd,
    };
    int ret = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0);
    close(fd);
    return ret;
}

static int add_net_rule(int ruleset_fd, uint64_t port, uint64_t access) {
    struct landlock_net_port_attr net_attr = {
        .allowed_access = access,
        .port = port,
    };
    return landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &net_attr, 0);
}

void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options] -- <command> [args...]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --ro <path>         Allow read-only filesystem access to <path>\n");
    fprintf(stderr, "  --rw <path>         Allow read-write filesystem access to <path>\n");
    fprintf(stderr, "  --allow-port <port> Allow outbound TCP connection to <port> (e.g. 11434 for Ollama)\n");
    fprintf(stderr, "  --mode <mode>       'enforce' (default) or 'audit'\n");
    fprintf(stderr, "  --version           Print Landlock ABI version\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--version") == 0) {
        int abi = get_landlock_abi_version();
        printf("Landlock ABI Version: %d\n", abi);
        return 0;
    }

    int abi = get_landlock_abi_version();
    if (abi < 1) {
        fprintf(stderr, "[AgentGuard-Executor] Fatal: Kernel Landlock LSM not active (ABI: %d).\n", abi);
        return 1;
    }

    const char *mode = "enforce";
    char *ro_paths[64];
    int ro_count = 0;
    char *rw_paths[64];
    int rw_count = 0;
    uint64_t allowed_ports[16];
    int port_count = 0;
    int cmd_idx = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            cmd_idx = i + 1;
            break;
        } else if (strcmp(argv[i], "--ro") == 0 && i + 1 < argc) {
            ro_paths[ro_count++] = argv[++i];
        } else if (strcmp(argv[i], "--rw") == 0 && i + 1 < argc) {
            rw_paths[rw_count++] = argv[++i];
        } else if (strcmp(argv[i], "--allow-port") == 0 && i + 1 < argc) {
            allowed_ports[port_count++] = (uint64_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode = argv[++i];
        }
    }

    if (cmd_idx < 0 || cmd_idx >= argc) {
        fprintf(stderr, "[AgentGuard-Executor] Error: Missing target command after '--'\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Standard system directories needed for binary loader and runtime */
    const char *default_system_ro[] = {
        "/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/bin", "/bin", "/etc/ld.so.cache", "/etc/alternatives"
    };

    uint64_t fs_handled = ACCESS_FS_EXECUTE | ACCESS_FS_WRITE_FILE | ACCESS_FS_READ_FILE |
                          ACCESS_FS_READ_DIR | ACCESS_FS_REMOVE_DIR | ACCESS_FS_REMOVE_FILE |
                          ACCESS_FS_MAKE_CHAR | ACCESS_FS_MAKE_DIR | ACCESS_FS_MAKE_REG |
                          ACCESS_FS_MAKE_SOCK | ACCESS_FS_MAKE_FIFO | ACCESS_FS_MAKE_BLOCK |
                          ACCESS_FS_MAKE_SYM;
    if (abi >= 2) fs_handled |= ACCESS_FS_REFER;
    if (abi >= 3) fs_handled |= ACCESS_FS_TRUNCATE;

    uint64_t net_handled = 0;
    if (abi >= 4) {
        net_handled = ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP;
    }

    struct landlock_ruleset_attr attr = {
        .handled_access_fs = fs_handled,
        .handled_access_net = net_handled,
    };

    int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (ruleset_fd < 0) {
        fprintf(stderr, "[AgentGuard-Executor] Failed to create Landlock ruleset: %s\n", strerror(errno));
        return 1;
    }

    /* 1. Add standard system library paths */
    uint64_t ro_access = ACCESS_FS_EXECUTE | ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR;
    for (size_t i = 0; i < sizeof(default_system_ro)/sizeof(default_system_ro[0]); i++) {
        add_path_rule(ruleset_fd, default_system_ro[i], ro_access);
    }

    /* 2. Add user-specified read-only directories */
    for (int i = 0; i < ro_count; i++) {
        add_path_rule(ruleset_fd, ro_paths[i], ro_access);
    }

    /* 3. Add user-specified read-write directories */
    uint64_t rw_access = fs_handled;
    for (int i = 0; i < rw_count; i++) {
        add_path_rule(ruleset_fd, rw_paths[i], rw_access);
    }

    /* 4. Add allowed TCP ports (ABI v4+) */
    if (abi >= 4) {
        for (int i = 0; i < port_count; i++) {
            add_net_rule(ruleset_fd, allowed_ports[i], ACCESS_NET_CONNECT_TCP);
        }
    }

    /* Set PR_SET_NO_NEW_PRIVS */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "[AgentGuard-Executor] Failed to set PR_SET_NO_NEW_PRIVS: %s\n", strerror(errno));
        close(ruleset_fd);
        return 1;
    }

    /* Restrict self if in 'enforce' mode */
    if (strcmp(mode, "enforce") == 0) {
        if (landlock_restrict_self(ruleset_fd, 0) != 0) {
            fprintf(stderr, "[AgentGuard-Executor] Failed to enforce Landlock restrictions: %s\n", strerror(errno));
            close(ruleset_fd);
            return 1;
        }
    } else {
        fprintf(stderr, "[AgentGuard-Executor] Running in AUDIT mode: restrictions not locked.\n");
    }

    close(ruleset_fd);

    /* Execute the requested command */
    execvp(argv[cmd_idx], &argv[cmd_idx]);

    /* If execvp returns, an error occurred */
    fprintf(stderr, "[AgentGuard-Executor] Failed to execute '%s': %s\n", argv[cmd_idx], strerror(errno));
    return 127;
}
