#ifndef __BPF_LSM_POLICY_KERNEL_TYPES_H__
#define __BPF_LSM_POLICY_KERNEL_TYPES_H__

/* Minimal CO-RE-relocatable subsets of the kernel structs this policy
 * touches. preserve_access_index makes direct field accesses
 * CO-RE-relocatable, so libbpf rewrites the offsets at load time
 * against the running kernel's BTF -- this file does not need to track
 * upstream layout changes.
 *
 * Add a field here only when a policy hook actually reads it.
 */

#include <linux/types.h>
#include <linux/bpf.h>

struct task_struct {
	int pid;
	int tgid;
} __attribute__((preserve_access_index));

struct super_block {
	unsigned long s_magic;
} __attribute__((preserve_access_index));

/* Opaque; we only take its address via the bpf_link_iops ksym and
 * compare pointer identity, never dereference. */
struct inode_operations;

struct inode {
	unsigned long i_ino;
	const struct inode_operations *i_op;
	void *i_private;
} __attribute__((preserve_access_index));

struct dentry {
	struct inode *d_inode;
	struct super_block *d_sb;
} __attribute__((preserve_access_index));

struct file {
	struct inode *f_inode;
} __attribute__((preserve_access_index));

struct vfsmount {
	struct super_block *mnt_sb;
} __attribute__((preserve_access_index));

struct linux_binprm {
	struct file *file;
} __attribute__((preserve_access_index));

struct bpf_prog {
	enum bpf_prog_type type;
} __attribute__((preserve_access_index));

struct bpf_link {
	struct bpf_prog *prog;
} __attribute__((preserve_access_index));

#endif /* __BPF_LSM_POLICY_KERNEL_TYPES_H__ */
