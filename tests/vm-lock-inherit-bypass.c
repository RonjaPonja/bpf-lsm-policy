/*
 * Regression test for the inherited-child-release bypass.
 *
 * A parent process grabs the system VM lock, then forks an Exploiter child
 * that inherits the owner flag via lsm/task_alloc. When the Exploiter exits,
 * the lsm/task_free hook used to unconditionally clear the global lock, even
 * though the parent (the real lock holder) was still alive. An "Observer"
 * process that was forked BEFORE the parent ever touched KVM could then race
 * in and acquire the lock cleanly.
 *
 * Exit codes:
 *   0  - Observer was correctly denied (policy enforced and intact).
 *   1  - Observer was allowed to create a VM (bypass succeeded).
 *   2  - Setup error (could not open /dev/kvm, parent could not acquire, ...).
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define EXIT_BYPASS 1
#define EXIT_SETUP_ERR 2

static int observer_main(int kvm_fd, int sync_fd)
{
	char buf;
	int vm_fd;

	/* Block until the parent signals that the Exploiter has died. The
	 * release runs from tp_btf/sched_process_exit inside do_exit(), so by
	 * the time waitpid() returns the refcount is already decremented and
	 * a single attempt is conclusive. */
	if (read(sync_fd, &buf, 1) != 1) {
		fprintf(stderr, "[observer] sync read failed: %s\n",
			strerror(errno));
		return EXIT_SETUP_ERR;
	}

	vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
	if (vm_fd >= 0) {
		fprintf(stderr,
			"[observer] BYPASS: created VM fd=%d while parent "
			"still holds the lock\n",
			vm_fd);
		close(vm_fd);
		return EXIT_BYPASS;
	}

	if (errno != EPERM) {
		fprintf(stderr,
			"[observer] unexpected errno=%d (%s); want EPERM\n",
			errno, strerror(errno));
		return EXIT_SETUP_ERR;
	}

	printf("[observer] denied with EPERM as expected\n");
	return EXIT_SUCCESS;
}

int main(void)
{
	int kvm_fd, parent_vm_fd, sync_pipe[2];
	pid_t observer_pid, exploiter_pid;
	int observer_status;

	kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm_fd < 0) {
		perror("open /dev/kvm");
		return EXIT_SETUP_ERR;
	}

	if (pipe(sync_pipe) < 0) {
		perror("pipe");
		return EXIT_SETUP_ERR;
	}

	/* Fork the Observer BEFORE the parent touches KVM, so the Observer
	 * has no inherited owner flag in BPF task storage. */
	observer_pid = fork();
	if (observer_pid < 0) {
		perror("fork observer");
		return EXIT_SETUP_ERR;
	}
	if (observer_pid == 0) {
		close(sync_pipe[1]);
		_exit(observer_main(kvm_fd, sync_pipe[0]));
	}
	close(sync_pipe[0]);

	/* Parent acquires the lock. */
	parent_vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
	if (parent_vm_fd < 0) {
		fprintf(stderr, "[parent] KVM_CREATE_VM failed: %s\n",
			strerror(errno));
		return EXIT_SETUP_ERR;
	}

	/* Fork the Exploiter; it inherits the owner flag via task_alloc and
	 * its task_free is what used to drop the global lock. */
	exploiter_pid = fork();
	if (exploiter_pid < 0) {
		perror("fork exploiter");
		return EXIT_SETUP_ERR;
	}
	if (exploiter_pid == 0) {
		int vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
		if (vm_fd >= 0)
			close(vm_fd);
		_exit(EXIT_SUCCESS);
	}

	if (waitpid(exploiter_pid, NULL, 0) < 0) {
		perror("waitpid exploiter");
		return EXIT_SETUP_ERR;
	}

	/* Wake the Observer now that the Exploiter has died. */
	if (write(sync_pipe[1], "x", 1) != 1) {
		perror("sync write");
		return EXIT_SETUP_ERR;
	}
	close(sync_pipe[1]);

	if (waitpid(observer_pid, &observer_status, 0) < 0) {
		perror("waitpid observer");
		return EXIT_SETUP_ERR;
	}

	close(parent_vm_fd);
	close(kvm_fd);

	if (!WIFEXITED(observer_status)) {
		fprintf(stderr, "[parent] observer died abnormally\n");
		return EXIT_SETUP_ERR;
	}
	return WEXITSTATUS(observer_status);
}
