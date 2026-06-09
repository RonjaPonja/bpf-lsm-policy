#ifndef __BPF_LSM_POLICY_KERNEL_TYPES_H__
#define __BPF_LSM_POLICY_KERNEL_TYPES_H__

/* Minimal CO-RE-relocatable subsets of the kernel structs this policy
 * touches. The __core marker tells clang to emit a CO-RE relocation
 * for every field access, so libbpf rewrites the offsets at load time
 * against the running kernel's BTF -- this file does not need to track
 * upstream layout changes.
 *
 * Add a field here only when a policy hook actually reads it.
 */

#include <linux/types.h>
#include <linux/bpf.h>

#define __core __attribute__((preserve_access_index))

struct task_struct {
	int pid;
	int tgid;
} __core;

struct super_block {
	unsigned long s_magic;
} __core;

/* Opaque; we only take its address via the bpf_link_iops ksym and
 * compare pointer identity, never dereference. */
struct inode_operations;

struct inode {
	unsigned long i_ino;
	const struct inode_operations *i_op;
	void *i_private;
} __core;

struct dentry {
	struct inode *d_inode;
	struct super_block *d_sb;
} __core;

struct file {
	struct inode *f_inode;
} __core;

struct vfsmount {
	struct super_block *mnt_sb;
} __core;

struct linux_binprm {
	struct file *file;
} __core;

struct bpf_prog {
	enum bpf_prog_type type;
} __core;

struct bpf_link {
	struct bpf_prog *prog;
} __core;

#endif /* __BPF_LSM_POLICY_KERNEL_TYPES_H__ */
