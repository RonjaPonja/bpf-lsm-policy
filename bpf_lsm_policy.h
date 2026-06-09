#ifndef __BPF_LSM_POLICY_H__
#define __BPF_LSM_POLICY_H__

#ifdef __BPF__

#include <linux/types.h>
#include <bpf/bpf_helpers.h>

/* The BPF-side only variable (set by loader) */
volatile const __u8 enforce_mode = 0;

#define BPF_LSM_DECISION(error_code, fmt, ...) ({                \
    int _ret;                                                    \
    if (enforce_mode) {                                          \
        bpf_printk("LSM [ENFORCE]: " fmt, ##__VA_ARGS__);        \
        _ret = error_code;                                       \
    } else {                                                     \
        bpf_printk("LSM [DRY-RUN]: " fmt, ##__VA_ARGS__);        \
        _ret = 0;                                                \
    }                                                            \
    _ret;                                                        \
})

#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* * 1. Global User-Space Variable
 * Holds the state of the policy for the loader process.
 * Defaults to 0 (Permissive).
 */
static bool BPF_LSM_ENFORCED = false;

/*
 * 2. Init Function
 * Call this ONCE at the start of main().
 * It reads the env var and updates the global variable above.
 */
static inline void bpf_lsm_init_env() {
    const char *val = getenv("BPF_LSM_POLICY_ENFORCE");
    if (val && strcmp(val, "1") == 0) {
        BPF_LSM_ENFORCED = true;
        printf("[Loader] ENV DETECTED: Policy set to ENFORCE\n");
    } else {
        BPF_LSM_ENFORCED = false;
        printf("[Loader] ENV DEFAULT: Policy set to PERMISSIVE (Dry-Run)\n");
    }
}

#define BPF_LSM_SYNC_SKEL(skel) do { \
    (skel)->rodata->enforce_mode = BPF_LSM_ENFORCED; \
} while(0)

#endif /* __BPF__ */
#endif /* __BPF_LSM_POLICY_H__ */