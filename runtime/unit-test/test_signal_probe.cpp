// SPDX-License-Identifier: MIT
// Fault-injection tests for the sigsetjmp/SIGSEGV probe-read backend.
// Only built when BPFTIME_PROBE_READ_SIGNAL=1.
#include "signal_probe.hpp"

#if BPFTIME_HAVE_SIGNAL_PROBE_BACKEND

#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

namespace
{
// Catch2 (and other test frameworks) install their own SIGSEGV fatal-condition
// handler around each test case, moving it above our lazily-registered one.
// Re-assert our disposition at the start of every case so recovery is tested
// against the exact handler ordering a real embedding would rely on.
struct signal_backend_fixture {
	signal_backend_fixture()
	{
		REQUIRE(bpftime::signal_probe::backend_available());
		bpftime::signal_probe::rearm_handler();
	}
};
} // namespace

TEST_CASE_METHOD(signal_backend_fixture,
		 "valid copy succeeds", "[probe-read-signal]")
{
	char dst[32] = {};
	char src[32];
	memset(src, 0xAB, sizeof src);
	REQUIRE(bpftime::signal_probe::protected_copy(dst, src, sizeof src));
	REQUIRE(memcmp(dst, src, sizeof src) == 0);
}

TEST_CASE_METHOD(signal_backend_fixture,
		 "zero size is a no-op success", "[probe-read-signal]")
{
	REQUIRE(bpftime::signal_probe::protected_copy(nullptr, nullptr, 0));
}

TEST_CASE_METHOD(signal_backend_fixture,
		 "unmapped pointer returns false, no crash",
		 "[probe-read-signal]")
{
	char dst[16];
	REQUIRE_FALSE(bpftime::signal_probe::protected_copy(
		dst, (void *)0x1000, sizeof dst));
}

TEST_CASE_METHOD(signal_backend_fixture,
		 "non-canonical pointer returns false, no crash",
		 "[probe-read-signal]")
{
	// Garbage frame pointers on x86_64 are frequently non-canonical and
	// raise #GP -> SIGSEGV si_code=SI_KERNEL, not SEGV_MAPERR.
	char dst[16];
	REQUIRE_FALSE(bpftime::signal_probe::protected_copy(
		dst, (void *)0x1824548b48008b48ULL, sizeof dst));
}

TEST_CASE_METHOD(signal_backend_fixture,
		 "stale-but-mapped frame returns false",
		 "[probe-read-signal]")
{
	char dst[16];
	void *region = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	REQUIRE(region != MAP_FAILED);
	auto *frame = static_cast<uint64_t *>(region);
	frame[0] = 0x00005a5a00001000ULL; // mapped first read, bad saved fp later
	frame[1] = 0xdeadbeefULL;
	bool first = bpftime::signal_probe::protected_copy(dst, region, 16);
	REQUIRE(first);
	bool second = bpftime::signal_probe::protected_copy(
		dst, (void *)frame[0], 16);
	REQUIRE_FALSE(second);
	munmap(region, 4096);
}

TEST_CASE_METHOD(signal_backend_fixture,
		 "repeated recovery reuses jump buffer",
		 "[probe-read-signal]")
{
	char dst[16];
	int recovered = 0;
	for (int i = 0; i < 100000; i++)
		if (!bpftime::signal_probe::protected_copy(
			    dst, (void *)0x1000, sizeof dst))
			recovered++;
	REQUIRE(recovered == 100000);
	// The backend must still service valid copies afterwards.
	char src[16] = {};
	REQUIRE(bpftime::signal_probe::protected_copy(dst, src, sizeof dst));
}

TEST_CASE("unrelated SIGSEGV keeps host semantics", "[probe-read-signal]")
{
	// A fault raised outside the protected-copy window must NOT be
	// swallowed: the previously installed disposition runs. Verify in a
	// child so the fatal path does not kill the test runner.
	pid_t pid = fork();
	REQUIRE(pid >= 0);
	if (pid == 0) {
		struct sigaction sa = {};
		sa.sa_handler = [](int) { _exit(77); };
		sigemptyset(&sa.sa_mask);
		sigaction(SIGSEGV, &sa, nullptr);
		// Install the backend on top; it must chain to our handler for
		// any fault that is not inside a protected copy.
		REQUIRE(bpftime::signal_probe::backend_available());
		bpftime::signal_probe::rearm_handler();
		char dst[8];
		(void)bpftime::signal_probe::protected_copy(
			dst, (void *)0x1000, sizeof dst);
		// Now fault outside any protected window: our handler chains
		// to the user handler installed above.
		volatile int *p = (volatile int *)0x1000;
		(void)*p;
		_exit(0); // not reached
	}
	int status = 0;
	waitpid(pid, &status, 0);
	REQUIRE(WIFEXITED(status));
	REQUIRE(WEXITSTATUS(status) == 77);
}

#endif // BPFTIME_HAVE_SIGNAL_PROBE_BACKEND
