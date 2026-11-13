// SPDX-License-Identifier: MIT
// Fault-injection tests for the fixed fault-PC -> recovery-PC probe-read
// backend. Only compiled when BPFTIME_PROBE_READ_SIGNAL=1.
#include "signal_probe.hpp"

#if BPFTIME_HAVE_SIGNAL_PROBE_BACKEND

#include "catch2/catch_test_macros.hpp"
#include <atomic>
#include <cerrno>
#include <cstring>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace
{
// Catch2 installs its own SIGSEGV fatal-condition handler around each case.
// Re-assert our disposition at case start so recovery is tested against the
// exact handler ordering a real embedding relies on; the Catch2 disposition
// becomes the previous one and stays chained for foreign faults.
struct signal_backend_fixture {
	signal_backend_fixture()
	{
		REQUIRE(bpftime::signal_probe::backend_available());
		bpftime::signal_probe::rearm_handler();
	}
};

constexpr uintptr_t kNonCanonical = 0x1824000000000000ULL;

int process_vm_fallback(void *dst, const void *src, size_t n)
{
	iovec local{ dst, n };
	iovec remote{ const_cast<void *>(src), n };
	return syscall(SYS_process_vm_readv, getpid(), &local, 1, &remote, 1,
		       0) == static_cast<ssize_t>(n) ?
		       1 :
		       0;
}
} // namespace

TEST_CASE_METHOD(signal_backend_fixture, "valid and cross-page copies succeed",
		 "[probe-read-signal]")
{
	char dst[32] = {};
	char src[32];
	std::memset(src, 0x5a, sizeof src);
	REQUIRE(bpftime::signal_probe::protected_copy(dst, src, 1) == 1);
	REQUIRE(bpftime::signal_probe::protected_copy(dst, src, sizeof src) ==
		1);
	REQUIRE(std::memcmp(dst, src, sizeof src) == 0);

	void *pages = mmap(nullptr, 8192, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	REQUIRE(pages != MAP_FAILED);
	static_cast<char *>(pages)[4095] = 0x11;
	static_cast<char *>(pages)[4096] = 0x22;
	char two[2] = {};
	REQUIRE(bpftime::signal_probe::protected_copy(
			two, static_cast<char *>(pages) + 4095, 2) == 1);
	REQUIRE(two[0] == 0x11 && two[1] == 0x22);
	REQUIRE(munmap(pages, 8192) == 0);
}

TEST_CASE_METHOD(signal_backend_fixture,
		 "null, unmapped, PROT_NONE and non-canonical pointers recover",
		 "[probe-read-signal]")
{
	char dst[16] = {};
	REQUIRE(bpftime::signal_probe::protected_copy(dst, nullptr, 8) == 0);
	REQUIRE(bpftime::signal_probe::protected_copy(
			dst, reinterpret_cast<void *>(kNonCanonical), 8) == 0);

	void *p = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	REQUIRE(p != MAP_FAILED);
	munmap(p, 4096);
	REQUIRE(bpftime::signal_probe::protected_copy(dst, p, 16) == 0);

	void *q = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	REQUIRE(q != MAP_FAILED);
	REQUIRE(mprotect(q, 4096, PROT_NONE) == 0);
	REQUIRE(bpftime::signal_probe::protected_copy(dst, q, 16) == 0);
	REQUIRE(munmap(q, 4096) == 0);
}

TEST_CASE_METHOD(signal_backend_fixture,
		 "read straddling a revoked page boundary recovers",
		 "[probe-read-signal]")
{
	char dst[4] = { 9, 9, 9, 9 };
	void *p = mmap(nullptr, 8192, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	REQUIRE(p != MAP_FAILED);
	REQUIRE(mprotect(static_cast<char *>(p) + 4096, 4096, PROT_NONE) == 0);
	REQUIRE(bpftime::signal_probe::protected_copy(
			dst, static_cast<char *>(p) + 4095, 2) == 0);
	REQUIRE(munmap(p, 8192) == 0);
}

TEST_CASE_METHOD(signal_backend_fixture,
		 "repeated recovery keeps working and errno is preserved",
		 "[probe-read-signal]")
{
	char dst[8];
	errno = 999;
	for (int i = 0; i < 100000; ++i)
		REQUIRE(bpftime::signal_probe::protected_copy(
			dst, reinterpret_cast<void *>(kNonCanonical), 8) == 0);
	REQUIRE(errno == 999);
	int src = 5;
	REQUIRE(bpftime::signal_probe::protected_copy(dst, &src, sizeof src) ==
		1);
	REQUIRE(errno == 999);
}

TEST_CASE_METHOD(signal_backend_fixture,
		 "concurrent threads each recover independently",
		 "[probe-read-signal]")
{
	constexpr int kThreads = 8;
	constexpr int kIters = 20000;
	std::atomic<int> good{ 0 };
	std::vector<std::thread> pool;
	for (int t = 0; t < kThreads; ++t) {
		pool.emplace_back([&] {
			char local_dst[16];
			int local = 42;
			int n = 0;
			for (int i = 0; i < kIters; ++i) {
				if (bpftime::signal_probe::protected_copy(
					    local_dst, &local, sizeof local) ==
				    1)
					++n;
				if (bpftime::signal_probe::protected_copy(
					    local_dst,
					    reinterpret_cast<void *>(
						    kNonCanonical),
					    8) != 0)
					std::abort();
			}
			good += n;
		});
	}
	for (auto &th : pool)
		th.join();
	REQUIRE(good.load() == kThreads * kIters);
}

TEST_CASE("foreign SIGSEGV keeps the previous host disposition",
	  "[probe-read-signal]")
{
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		rlimit no_core{ 0, 0 };
		setrlimit(RLIMIT_CORE, &no_core);
		struct sigaction sa = {};
		sa.sa_handler = [](int) { _exit(77); };
		sigemptyset(&sa.sa_mask);
		if (sigaction(SIGSEGV, &sa, nullptr) != 0)
			_exit(2);
		if (!bpftime::signal_probe::backend_available())
			_exit(3);
		bpftime::signal_probe::rearm_handler();
		char dst[8];
		if (bpftime::signal_probe::protected_copy(
			    dst, reinterpret_cast<void *>(0x1000),
			    sizeof dst) != 0)
			_exit(4);
		volatile int *foreign = reinterpret_cast<volatile int *>(0x1000);
		(void)*foreign; // must chain to the host handler -> exit 77
		_exit(5);
	}
	int status = 0;
	REQUIRE(waitpid(child, &status, 0) == child);
	REQUIRE(WIFEXITED(status));
	REQUIRE(WEXITSTATUS(status) == 77);
}

TEST_CASE("blocked SIGSEGV refuses the backend and the syscall fallback holds",
	  "[probe-read-signal]")
{
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		rlimit no_core{ 0, 0 };
		setrlimit(RLIMIT_CORE, &no_core);
		sigset_t mask, old;
		sigemptyset(&mask);
		sigaddset(&mask, SIGSEGV);
		if (pthread_sigmask(SIG_BLOCK, &mask, &old) != 0)
			_exit(2);
		char dst[8] = {};
		// A prior blocked attempt must not permanently disable the
		// backend, but while blocked the call has to refuse.
		if (bpftime::signal_probe::protected_copy(
			    dst, reinterpret_cast<void *>(kNonCanonical),
			    8) != -1)
			_exit(3);
		if (process_vm_fallback(
			    dst, reinterpret_cast<void *>(kNonCanonical), 8))
			_exit(4);
		if (pthread_sigmask(SIG_SETMASK, &old, nullptr) != 0)
			_exit(5);
		if (bpftime::signal_probe::protected_copy(
			    dst, reinterpret_cast<void *>(kNonCanonical),
			    8) != 0)
			_exit(6);
		_exit(0);
	}
	int status = 0;
	REQUIRE(waitpid(child, &status, 0) == child);
	REQUIRE(WIFEXITED(status));
	REQUIRE(WEXITSTATUS(status) == 0);
}

#endif // BPFTIME_HAVE_SIGNAL_PROBE_BACKEND
