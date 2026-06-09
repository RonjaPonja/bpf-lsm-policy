#include <linux/bpf.h>
#include <linux/errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "kernel_types.bpf.h"
#include "bpf_lsm_policy.h"

char LICENSE[] SEC("license") = "GPL";

#define KVM_CREATE_VM 0xAE01

/* Refcount of live tasks that hold (or inherited) the VM lock. The lock is
 * "free" only when the count is 0; a binary flag would let an inherited child
 * release the lock for the still-running root acquirer.
 */
__u64 vm_owner_count = 0;
/* Can be extended / generalized if there are more emulators
 * installed.
 */
unsigned long qemu_inode = 0;

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, bool);
} is_vm_owner SEC(".maps");

/* Per-hook helpers operate on the slot pointer so each hook does at most
 * one bpf_task_storage_get per task it touches. */
static __always_inline bool *vm_owner_slot(struct task_struct *task, bool create)
{
	__u64 flags = create ? BPF_LOCAL_STORAGE_GET_F_CREATE : 0;
	return bpf_task_storage_get(&is_vm_owner, task, 0, flags);
}

static __always_inline bool slot_is_owner(bool *slot)
{
	return slot && *slot;
}

/* Atomically claim the global count for this slot. -EPERM on contention. */
static __always_inline int claim_vm_lock(bool *slot)
{
	if (__sync_val_compare_and_swap(&vm_owner_count, 0, 1))
		return -EPERM;
	*slot = true;
	return 0;
}

/* Add an inherited reference for a freshly created child slot. */
static __always_inline void inherit_vm_lock(bool *slot)
{
	*slot = true;
	__sync_fetch_and_add(&vm_owner_count, 1);
}

/* Drop one owner reference; returns the new count. */
static __always_inline __u64 release_vm_owner(bool *slot)
{
	*slot = false;
	return __sync_sub_and_fetch(&vm_owner_count, 1);
}

/* The policy intercepts at various phases of the VM creation life-cycle.
 * It's expected that the system has some form of trusted execution
 * and can restrict the number of "VM launchers".
 */
static __always_inline int try_acquire_vm_lock(void)
{
	bool *slot = vm_owner_slot(bpf_get_current_task_btf(), true);

	if (!slot)
		return -ENOMEM;
	if (*slot)
		return 0;
	return claim_vm_lock(slot);
}

/* For KVM accelerated VMs, there's a stronger guarantee that does
 * not rely on incercepting emulator execution.
 */
SEC("lsm/file_ioctl")
int BPF_PROG(restrict_kvm_create, struct file *file, unsigned int cmd,
	     unsigned long arg)
{
	int err;

	if (cmd != KVM_CREATE_VM)
		return 0;

	err = try_acquire_vm_lock();
	if (err)
		return BPF_LSM_DECISION(
			err,
			"KVM_CREATE_VM: Denied. System-wide VM lock is active.\n");

	return 0;
}

/* Emulated VMs look just like any user-space programs, these are restricted by
 * restricting the number of emulator instances that can be alive on the system.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(restrict_qemu, struct linux_binprm *bprm)
{
	__u64 ino = bprm->file->f_inode->i_ino;
	int err;

	if (qemu_inode == 0 || ino != qemu_inode)
		return 0;

	err = try_acquire_vm_lock();
	if (err)
		return BPF_LSM_DECISION(
			err,
			"BPRM_CHECK: Denied. Software VM blocked by system lock.\n");

	return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(vm_task_alloc, struct task_struct *task, unsigned long clone_flags)
{
	bool *parent_slot = vm_owner_slot(bpf_get_current_task_btf(), false);
	bool *child_slot;

	if (!slot_is_owner(parent_slot))
		return 0;

	child_slot = vm_owner_slot(task, true);
	/* Defensive: skip if task_alloc somehow fires twice for this task. */
	if (!child_slot || *child_slot)
		return 0;

	inherit_vm_lock(child_slot);
	return 0;
}

/* Drop the ref synchronously from do_exit(). lsm/task_free fires from an
 * RCU callback, so observers could see the lock free for a grace period
 * before the next acquirer arrives; sched_process_exit runs in the exiting
 * task's context before it becomes a zombie. */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(release_vm_lock_on_exit, struct task_struct *task, bool group_dead)
{
	bool *slot = vm_owner_slot(task, false);

	if (slot_is_owner(slot) && release_vm_owner(slot) == 0)
		bpf_printk("KVM_CREATE_VM: Lock released (last owner PID %d exited)\n",
			   task->pid);
	return 0;
}

/* Fallback for the bad-fork path: copy_process() can fail after
 * security_task_alloc has already bumped the ref, in which case the task
 * never runs and sched_process_exit never fires. task_free still runs
 * (synchronously, from the cleanup goto chain) so the count stays balanced.
 */
SEC("lsm/task_free")
void BPF_PROG(release_vm_lock_on_free, struct task_struct *task)
{
	bool *slot = vm_owner_slot(task, false);

	if (slot_is_owner(slot))
		release_vm_owner(slot);
}
