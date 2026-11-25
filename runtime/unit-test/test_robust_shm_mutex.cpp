/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2026, bpftime contributors
 * All rights reserved.
 */
#include "catch2/catch_test_macros.hpp"
#if defined(__linux__)
#include "robust_shm_mutex.hpp"
#include <cerrno>
#include <new>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

namespace
{
bpftime::robust_shm_mutex *make_shared_mutex()
{
	void *p = mmap(nullptr, sizeof(bpftime::robust_shm_mutex),
		       PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	REQUIRE(p != MAP_FAILED);
	return new (p) bpftime::robust_shm_mutex();
}

pid_t fork_killed_holder(bpftime::robust_shm_mutex *m, bool reap_immediately)
{
	int notify[2];
	REQUIRE(pipe(notify) == 0);
	pid_t pid = fork();
	REQUIRE(pid >= 0);
	if (pid == 0) {
		close(notify[0]);
		if (!m->lock("test"))
			_exit(10);
		char ok = 1;
		if (write(notify[1], &ok, 1) != 1)
			_exit(11);
		close(notify[1]);
		if (!reap_immediately)
			raise(SIGKILL);
		for (;;)
			pause();
	}
	close(notify[1]);
	char ok = 0;
	REQUIRE(read(notify[0], &ok, 1) == 1);
	close(notify[0]);
	if (reap_immediately) {
		REQUIRE(kill(pid, SIGKILL) == 0);
		int status = 0;
		REQUIRE(waitpid(pid, &status, 0) == pid);
		REQUIRE(WIFSIGNALED(status));
		REQUIRE(WTERMSIG(status) == SIGKILL);
	}
	return pid;
}
} // namespace

TEST_CASE("robust SHM mutex taints permanently after a SIGKILLed holder",
	  "[robust_shm_mutex]")
{
	auto *m = make_shared_mutex();
	(void)fork_killed_holder(m, true);

	REQUIRE_FALSE(m->lock("test"));
	REQUIRE(errno == EBUSY);
	REQUIRE_FALSE(m->lock("test"));
	REQUIRE(errno == EBUSY);

	munmap(m, sizeof(*m));
}

TEST_CASE("robust SHM mutex recovers an unreaped zombie SIGKILLed holder",
	  "[robust_shm_mutex]")
{
	auto *m = make_shared_mutex();
	pid_t pid = fork_killed_holder(m, false);

	// Recover while child is still an unreaped zombie.
	REQUIRE(m->lock_and_recover());
	m->unlock();
	REQUIRE(m->lock_and_recover());
	m->unlock();

	int status = 0;
	REQUIRE(waitpid(pid, &status, 0) == pid);
	REQUIRE(WIFSIGNALED(status));
	munmap(m, sizeof(*m));
}
#endif
