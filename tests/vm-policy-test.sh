#!/bin/bash
set -e

log_info "Active Enforcement Level: ${BPF_LSM_POLICY_ENFORCE:-0}"

KERNEL_URL="http://ftp.debian.org/debian/dists/bookworm/main/installer-amd64/current/images/netboot/debian-installer/amd64/linux"
KERNEL_FILE="vmlinuz-debian"

kill_vms() {
    if [ -f vm1.pid ]; then
        kill $(cat vm1.pid) 2>/dev/null || true
        rm -f vm1.pid
    fi
    if [ -f vm2.pid ]; then
        kill $(cat vm2.pid) 2>/dev/null || true
        rm -f vm2.pid
    fi
}

cleanup() {
    log_info "Running cleanup"
    kill_vms
    rm -f init.c init minimal_initrd.img vm1.img vm2.img vm1.log vm2.log "$KERNEL_FILE"
    make uninstall >/dev/null 2>&1 || true
    make clean >/dev/null 2>&1 || true
}
trap cleanup EXIT SIGINT SIGTERM

make
make install
# Push the requested mode into systemd's environment so the systemd-managed
# loader picks it up via PassEnvironment=BPF_LSM_POLICY_ENFORCE.
systemctl set-environment BPF_LSM_POLICY_ENFORCE="${BPF_LSM_POLICY_ENFORCE:-0}"
make load

if [ ! -f "$KERNEL_FILE" ]; then
    wget -q -O "$KERNEL_FILE" "$KERNEL_URL"
fi

log_info "Creating a minimal initrd image"
cat <<EOF > init.c
#include <stdio.h>
#include <unistd.h>
int main() {
    printf("SUCCESS: The VM is alive!\n");
    fflush(stdout);
    while(1) { sleep(3600); }
    return 0;
}
EOF

clang -static -o init init.c
echo init | cpio -o --format=newc > minimal_initrd.img

log_info "Creating dummy VM images"
dd if=/dev/zero of=vm1.img bs=1M count=1 2>/dev/null
dd if=/dev/zero of=vm2.img bs=1M count=1 2>/dev/null

run_scenario() {
    local vm1_mode=$1
    local vm2_mode=$2
    local vm1_flags=""
    local vm2_flags=""

    echo "::group:: Test Scenario: VM1 ($vm1_mode) | VM2 ($vm2_mode)"

    if [ "$vm1_mode" == "KVM" ]; then vm1_flags="-enable-kvm"; fi
    if [ "$vm2_mode" == "KVM" ]; then vm2_flags="-enable-kvm"; fi

    log_info "Starting First VM ($vm1_mode)..."
    qemu-system-x86_64 -kernel "$KERNEL_FILE" -initrd minimal_initrd.img $vm1_flags \
        -append "console=ttyS0 rdinit=/init panic=0" -drive file=vm1.img,format=raw,index=0,media=disk \
        -display none -serial file:vm1.log -m 512 -daemonize -pidfile vm1.pid

    if ! kill -0 $(cat vm1.pid) 2>/dev/null; then
        log_error "First VM ($vm1_mode) failed to start!"
        cat vm1.log
        exit 1
    fi
    log_info "First VM ($vm1_mode) is running"

    log_info "Starting Second VM ($vm2_mode)"
    set +e
    timeout 5s qemu-system-x86_64 -kernel "$KERNEL_FILE" -initrd minimal_initrd.img $vm2_flags \
        -append "console=ttyS0 rdinit=/init panic=0" -drive file=vm2.img,format=raw,index=0,media=disk \
        -display none -serial file:vm2.log -m 512 -pidfile vm2.pid
    local EXIT_CODE=$?
    set -e

    if [ "${BPF_LSM_POLICY_ENFORCE:-0}" == "1" ]; then
        if [ $EXIT_CODE -eq 124 ] || [ $EXIT_CODE -eq 0 ]; then
            log_error "Second VM ($vm2_mode) was allowed to start, but LSM should have blocked it!"
            exit 1
        else
            log_success "Second VM ($vm2_mode) was successfully blocked by LSM (Exit Code: $EXIT_CODE)."
        fi
    else
        if [ $EXIT_CODE -eq 124 ] || [ $EXIT_CODE -eq 0 ]; then
            log_success "Second VM ($vm2_mode) started successfully (No LSM interference)."
        else
            log_error "Second VM ($vm2_mode) failed to start, but LSM is OFF!"
            exit 1
        fi
    fi
    kill_vms
    sleep 1
    echo "::endgroup::"
}

run_scenario "KVM" "KVM" || true
run_scenario "KVM" "Software" || true
run_scenario "Software" "KVM" || true
run_scenario "Software" "Software" || true
log_success "All scenarios executed successfully!"