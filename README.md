# BPF LSM Policy

This project implements a security policy using the Linux Security Module (LSM) framework with BPF (Berkeley Packet Filter). It provides a mechanism to enforce system-wide policies, demonstrated with a lock on KVM virtual machine creation.

## Description

The project consists of a user-space loader and BPF programs that are attached to LSM hooks. The primary goal is to load a set of security policies and then "lock down" the system to prevent these policies from being altered or unloaded.

### Components

*   **`bpf_lsm_policy_loader`**: The user-space application responsible for loading, attaching, and pinning the BPF programs. It creates a directory at `/sys/fs/bpf/bpf_lsm_policy` where the BPF links are pinned.
*   **`vm.bpf.c`**: A BPF program that enforces a system-wide lock on KVM virtual machine creation.
    *   `restrict_kvm_create`: Attached to the `lsm/file_ioctl` hook, it allows only one process to create a KVM VM. Once a process creates a VM, no other process can do so until the original process (and any children that inherited the owner flag) exit.
    *   `release_vm_lock_on_exit`: Attached to the `tp_btf/sched_process_exit` tracepoint, it synchronously drops an owner reference from inside `do_exit()`. The LSM `task_free` hook would otherwise run from an RCU callback, briefly letting another process steal the lock between the real owner exiting and the policy noticing.
    *   `release_vm_lock_on_free`: Attached to `lsm/task_free` as a fallback for the bad-fork path where `copy_process()` fails after `task_alloc` ran but before the task is ever scheduled, so `sched_process_exit` never fires.
*   **`restrict.bpf.c`**: A BPF program designed to finalize the security policy and prevent tampering.
    *   `restrict_inode_unlink`: Attached to the `lsm/inode_unlink` hook, it prevents the unlinking (deletion) of pinned BPF LSM links from the bpffs filesystem. This makes the loaded LSM policies persistent until the next reboot.
    *   `restrict_bpffs_umount`: Attached to the `lsm/sb_umount` hook, it blocks unmounting any bpffs while the policy is loaded. Without this, unmounting `/sys/fs/bpf` would tear down the inodes that hold our pinned links, dropping the last references and silently detaching the policy.
    *   `restrict_bpf_load`: Attached to the `lsm/bpf` hook, it prevents any new BPF programs of type `BPF_PROG_TYPE_LSM` from being loaded, effectively locking the LSM policy.
*   **`bpf_lsm_policy_loader.service`**: A systemd service file to run the `bpf_lsm_policy_loader` at boot time, ensuring the policy is applied automatically.

### Policy Enforcement

The policy can run in two modes:

*   **Permissive (Dry-Run)**: This is the default mode. The BPF programs will log policy violations (e.g., trying to create a second VM) via `bpf_printk`, but will not actually block the operation.
*   **Enforce**: In this mode, policy violations are actively blocked with an `EPERM` (Permission denied) error.

The mode is controlled by the `BPF_LSM_POLICY_ENFORCE` environment variable.

#### Enabling Enforcement Mode at Boot

To enable enforcement mode for the systemd service at boot, you can pass the following parameter to the kernel command line:

```
systemd.setenv=BPF_LSM_POLICY_ENFORCE=1
```

This sets the environment variable for the `systemd` manager. The included service file is configured to pass this variable to the `bpf_lsm_policy_loader` process, which will then activate the enforcement policy.

#### Enabling Enforcement Mode Manually

If you are running the loader manually, you can enable enforcement mode by setting the environment variable in your shell:

```bash
export BPF_LSM_POLICY_ENFORCE=1
sudo /usr/local/sbin/bpf_lsm_policy_loader
```

## Getting Started

### Prerequisites

*   A Linux kernel with BPF and LSM support.
*   The kernel must be compiled with `CONFIG_BPF_LSM=y`.
*   The bpffs filesystem must be mounted at `/sys/fs/bpf`.
*   `clang`, `libbpf-dev`, and `bpftool` must be installed.

### Building

To build the project, simply run `make`:

```bash
make
```

This will compile the BPF programs, generate the BPF skeletons, and build the `bpf_lsm_policy_loader` executable.

### Kernel types

The BPF programs declare only the kernel fields they touch in `kernel_types.bpf.h`, using `__attribute__((preserve_access_index))`. libbpf rewrites the offsets at load time against the running kernel's BTF (CO-RE), so the build does not need a `vmlinux.h` dump and runs against any kernel that exposes BTF for the structs we use (task_struct, file, inode, dentry, super_block, vfsmount, linux_binprm, bpf_link, bpf_prog).

### Installation and Activation

To install the loader and the systemd service, run:

```bash
sudo make install
```

This will:
1.  Install the `bpf_lsm_policy_loader` binary to `/usr/local/sbin/`.
2.  Install the `bpf_lsm_policy_loader.service` file to `/etc/systemd/system/`.

To enable and start the service, run the `load` target:

```bash
sudo make load
```

This will reload the systemd daemon, enable the service to start on boot, and start it immediately. You can check the status with:

```bash
systemctl status bpf_lsm_policy_loader.service
```

### Uninstallation

To stop the service and remove the installed files, run:

```bash
sudo make uninstall
```
