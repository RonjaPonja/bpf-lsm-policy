#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <errno.h>
#include "bpf_lsm_policy.h"

#define BPF_FS_MAGIC 0xCAFE4A11

const volatile int dry_run = 1;

char LICENSE[] SEC("license") = "GPL";

extern const void bpf_link_iops __ksym;
extern const void bpf_link_fops __ksym;

/* The policy loader pins the policy as links in /sys/fs/bpf
 * Unlinke other links, tracing and LSM links cannot be detached with BPF_LINK_DETACH
 * or modify BPF_LINK_UPDATE, the only way to unload this policy would be to
 * unlink the pinned file in bpffs.
 */
SEC("lsm/inode_unlink")
int BPF_PROG(restrict_inode_unlink, struct inode *dir, struct dentry *dentry)
{
    struct inode *inode= dentry->d_inode;
    struct bpf_link *link;

    if (dentry->d_sb->s_magic != BPF_FS_MAGIC)
        return 0;

    if (inode && inode->i_op != &bpf_link_iops)
        return 0;

    link = (struct bpf_link *)BPF_CORE_READ(inode, i_private);
    if (!link)
        return 0;

    if (BPF_CORE_READ(link, prog, type) == BPF_PROG_TYPE_LSM)
        return BPF_LSM_DECISION(-EPERM, "bpf_lsm: intercepted unlink of LSM link\n");

    return 0;
}

/* Loads any further LSM programs from being loaded, thus needs to be the last program
 * to be attached.
 */
SEC("lsm/bpf")
int BPF_PROG(restrict_bpf_load, int cmd, union bpf_attr *attr, unsigned int size)
{
    if (cmd == BPF_PROG_LOAD) {
        if (attr->prog_type == BPF_PROG_TYPE_LSM)
            return BPF_LSM_DECISION(-EPERM, "bpf_lsm: Blocked loading of new LSM program\n");
    }

    return 0;
}

/* Unmounting the bpffs that holds our pinned LSM links tears down the
 * inodes that keep those links alive, dropping the last reference and
 * silently detaching the policy from the kernel's LSM hook chain. Block
 * umount of any bpffs while the policy is loaded; the loader's own
 * bpffs at /sys/fs/bpf is meant to be a permanent system filesystem.
 */
SEC("lsm/sb_umount")
int BPF_PROG(restrict_bpffs_umount, struct vfsmount *mnt, int flags)
{
    if (BPF_CORE_READ(mnt, mnt_sb, s_magic) != BPF_FS_MAGIC)
        return 0;

    return BPF_LSM_DECISION(-EPERM, "bpf_lsm: intercepted umount of bpffs\n");
}
