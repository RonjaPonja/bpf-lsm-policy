#include "bpf_lsm_policy.h"
#include "vm.skel.h"
#include "restrict.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PIN_PATH "/sys/fs/bpf/bpf_lsm_policy"

#define PIN_LINK(skel, member) ({								        \
	int __err = 0;										                \
	struct bpf_link *__link = (skel)->links.member;				        \
	const char *__path = PIN_PATH "/" #member;					        \
														                \
	if (!__link) {										                \
		fprintf(stderr, "Error: Link '%s' is NULL\n", #member);		    \
		__err = -EINVAL;								                \
	} else {											                \
		__err = bpf_link__pin(__link, __path);				            \
		if (__err) {									                \
			fprintf(stderr, "Error: Failed to pin '%s': %d\n",		    \
				#member, __err);						                \
		} else {										                \
			printf("Info: Pinned link '%s' -> %s\n", #member, __path);	\
		}												                \
	}													                \
	__err;												                \
})

#define UNPIN_LINK(skel, member) do {               \
    if ((skel)->links.member)                       \
        bpf_link__unpin((skel)->links.member);      \
} while (0)

static struct vm_bpf *vm_policy_init(void)
{
	struct vm_bpf *skel;
	struct stat st;
	int err;

    skel = vm_bpf__open();
    if (!skel) {
        fprintf(stderr, "Error: Failed to open VM BPF skeleton\n");
        return NULL;
    }

	if (stat("/usr/bin/qemu-system-x86_64", &st) == 0) {
        skel->bss->qemu_inode = st.st_ino;
        printf("Info: Tracking QEMU emulator (Inode: %lu)\n", st.st_ino);
    } else {
        fprintf(stderr, "Warning: QEMU binary not found on disk. Software emulated VMs will not be blocked.\n");
    }

    BPF_LSM_SYNC_SKEL(skel);

    err = vm_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Error: Failed to load VM BPF: %d\n", err);
        goto cleanup;
    }

	err = vm_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Error: Failed to attach VM BPF: %d (%s)\n",
			err, strerror(-err));
		goto cleanup;
	}

	if (PIN_LINK(skel, restrict_kvm_create))
		goto cleanup;

	if (PIN_LINK(skel, release_vm_lock_on_exit))
		goto cleanup;

	if (PIN_LINK(skel, release_vm_lock_on_free))
		goto cleanup;

	if (PIN_LINK(skel, restrict_qemu))
		goto cleanup;

	if (PIN_LINK(skel, vm_task_alloc))
		goto cleanup;

	return skel;

cleanup:
	UNPIN_LINK(skel, restrict_kvm_create);
	UNPIN_LINK(skel, release_vm_lock_on_exit);
	UNPIN_LINK(skel, release_vm_lock_on_free);
	UNPIN_LINK(skel, restrict_qemu);
	UNPIN_LINK(skel, vm_task_alloc);
	vm_bpf__destroy(skel);
	return NULL;
}

static struct restrict_bpf *finalize_lsm_policy(void)
{
	struct restrict_bpf *skel;
	int err;

    skel = restrict_bpf__open();
    if (!skel) {
        fprintf(stderr, "Error: Failed to open Restrict BPF skeleton\n");
        return NULL;
    }

    bpf_program__set_autoattach(skel->progs.restrict_bpf_load, false);
    BPF_LSM_SYNC_SKEL(skel);

    err = restrict_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Error: Failed to load Restrict BPF: %d\n", err);
        goto cleanup;
    }
	err = restrict_bpf__attach(skel);
	if (err) {
		fprintf(stderr,
			"Error: Failed to attach Restrict BPF: %d (%s)\n", err,
			strerror(-err));
		goto cleanup;
	}

	if (PIN_LINK(skel, restrict_inode_unlink))
		goto cleanup;

	if (PIN_LINK(skel, restrict_bpffs_umount))
		goto cleanup;

	skel->links.restrict_bpf_load =
		bpf_program__attach(skel->progs.restrict_bpf_load);
	if (!skel->links.restrict_bpf_load) {
		err = -errno;
		fprintf(stderr,
			"Error: Failed to manually attach restrict_bpf_load: %d\n",
			err);
		goto cleanup;
	}

	if (PIN_LINK(skel, restrict_bpf_load))
		goto cleanup;

	return skel;

cleanup:
	UNPIN_LINK(skel, restrict_bpf_load);
	UNPIN_LINK(skel, restrict_bpffs_umount);
	UNPIN_LINK(skel, restrict_inode_unlink);
	restrict_bpf__destroy(skel);
	return NULL;
}

int main(int argc, char **argv)
{
	struct vm_bpf *vm_skel = NULL;
	struct restrict_bpf *restrict_skel = NULL;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	if (mkdir(PIN_PATH, 0755) != 0 && errno != EEXIST) {
		fprintf(stderr, "Error: Failed to create directory %s: %s\n",
			PIN_PATH, strerror(errno));
		return 1;
	}

    bpf_lsm_init_env();
	vm_skel = vm_policy_init();
	if (!vm_skel) {
		fprintf(stderr, "Fatal: VM policy initialization failed.\n");
		return 1;
	}

	restrict_skel = finalize_lsm_policy();
	if (!restrict_skel) {
		fprintf(stderr,
			"Fatal: LSM lockdown failed. Rolling back VM policies...\n");
		UNPIN_LINK(vm_skel, restrict_kvm_create);
		UNPIN_LINK(vm_skel, release_vm_lock_on_exit);
		UNPIN_LINK(vm_skel, release_vm_lock_on_free);
		UNPIN_LINK(vm_skel, restrict_qemu);
		UNPIN_LINK(vm_skel, vm_task_alloc);
		vm_bpf__destroy(vm_skel);
		return 1;
	}

	printf("\nSuccess: All LSM policies loaded, pinned, and system locked down.\n");

	vm_bpf__destroy(vm_skel);
	restrict_bpf__destroy(restrict_skel);

	return 0;
}