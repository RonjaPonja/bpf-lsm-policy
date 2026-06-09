#!/bin/bash
#
# Regression test for the bpffs-umount bypass: unmounting the bpffs that
# holds the policy's pinned LSM links would drop the last reference on
# those links, silently detaching the policy from the kernel's LSM hook
# chain. restrict_bpffs_umount blocks umount of any bpffs while loaded.
#
# Probes both directions:
#   1. umount /sys/fs/bpf must fail with EPERM.
#   2. After the umount attempt, BPF_PROG_LOAD with type=lsm must still
#      be denied -- if it succeeds, the policy is no longer enforcing.

set -e

POLICY_PIN_DIR="/sys/fs/bpf/bpf_lsm_policy"
PROBE_SRC="$(mktemp --suffix=.bpf.c)"
PROBE_OBJ="${PROBE_SRC%.c}.o"

cleanup() {
	log_info "Running cleanup"
	rm -f "$PROBE_SRC" "$PROBE_OBJ" /tmp/lsm-probe-pin
}
trap cleanup EXIT SIGINT SIGTERM

if [ ! -e "$POLICY_PIN_DIR/restrict_bpffs_umount" ]; then
	log_error "Policy missing restrict_bpffs_umount; a prior step must run \`make load\`"
	exit 1
fi

log_info "Probe 1: umount /sys/fs/bpf (expecting EPERM)"
set +e
umount /sys/fs/bpf 2>&1
RC=$?
set -e
if [ $RC -eq 0 ]; then
	log_error "BYPASS: umount of /sys/fs/bpf succeeded; policy was unloaded"
	# Best-effort remount so subsequent steps in the same VM don't break.
	mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
	exit 1
fi
log_success "umount of /sys/fs/bpf was blocked (exit $RC)"

log_info "Probe 2: confirm BPF_PROG_LOAD type=lsm is still denied"
cat >"$PROBE_SRC" <<'EOF'
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Opaque -- we only need the argument shape for the lsm/file_open
 * hook signature, never deref. */
struct file;

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/file_open")
int BPF_PROG(probe_lsm, struct file *file) { return 0; }
EOF
# Same -idirafter dance as Makefile so <asm/types.h> resolves under
# the BPF target's restricted include search.
CLANG_SYS_INCLUDES=$(clang -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')
clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 $CLANG_SYS_INCLUDES \
	-c "$PROBE_SRC" -o "$PROBE_OBJ"

rm -f /tmp/lsm-probe-pin
set +e
bpftool prog load "$PROBE_OBJ" /tmp/lsm-probe-pin type lsm 2>&1 | tail -3
RC=${PIPESTATUS[0]}
set -e
if [ $RC -eq 0 ]; then
	log_error "BYPASS: a new LSM program loaded; restrict_bpf_load is no longer enforcing"
	exit 1
fi
log_success "BPF_PROG_LOAD of an LSM program was denied as expected"
