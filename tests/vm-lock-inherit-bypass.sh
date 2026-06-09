#!/bin/bash
#
# Regression test for the inherited-child-release bypass of the system VM
# lock. Expects the bpf-lsm-policy LSM to already be loaded in enforce mode
# (the prior workflow step takes care of that, and the policy lockdown
# prevents us from reloading it within the same VM boot anyway).
#
# Builds the C harness which forks an Observer process BEFORE the parent
# touches KVM, has the parent acquire the lock, forks an Exploiter child
# that inherits the owner flag, and then checks that the Observer is still
# denied KVM_CREATE_VM after the Exploiter exits.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS_SRC="$SCRIPT_DIR/vm-lock-inherit-bypass.c"
HARNESS_BIN="$SCRIPT_DIR/vm-lock-inherit-bypass"
POLICY_PIN_DIR="/sys/fs/bpf/bpf_lsm_policy"

cleanup() {
	log_info "Running cleanup"
	rm -f "$HARNESS_BIN"
}
trap cleanup EXIT SIGINT SIGTERM

if [ ! -e "$POLICY_PIN_DIR/restrict_kvm_create" ]; then
	log_error "Policy not loaded ($POLICY_PIN_DIR/restrict_kvm_create missing); a prior step must run \`make load\`"
	exit 1
fi
log_info "Detected loaded policy at $POLICY_PIN_DIR"

log_info "Compiling harness"
clang -O2 -Wall -Wextra -o "$HARNESS_BIN" "$HARNESS_SRC"

log_info "Running inherited-child-release bypass harness"
set +e
"$HARNESS_BIN"
RC=$?
set -e

case "$RC" in
	0)
		log_success "Observer was correctly denied; bypass is fixed"
		;;
	1)
		log_error "BYPASS: Observer created a VM while the parent still held the lock"
		exit 1
		;;
	*)
		log_error "Harness setup failure (exit $RC); check /dev/kvm availability and policy state"
		exit 1
		;;
esac
