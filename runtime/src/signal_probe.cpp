// SPDX-License-Identifier: MIT
// Signal-recovery probe backend implementation.
#include "signal_probe.hpp"

#if BPFTIME_HAVE_SIGNAL_PROBE_BACKEND

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <setjmp.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <unistd.h>

namespace
{
// Annotation boundaries around the protected copy (see protected_copy).
extern "C" const char bpftime_probe_copy_begin[];
extern "C" const char bpftime_probe_copy_end[];

thread_local sigjmp_buf tls_jump;
thread_local volatile sig_atomic_t tls_active = 0;

struct sigaction previous_action;
bool handler_ready = false;
std::once_flag init_once;
bool init_succeeded = false;

// Dedicated per-thread signal stack. Workload fibers may run on small stacks
// (boost::fibers default fixedsize is ~128 KiB); without an alt stack the
// kernel cannot push the SA_SIGINFO frame on top of the deep probe call chain
// and force-kills the thread before the handler runs. SS_AUTODISARM keeps
// nested faults from re-entering the same alt stack.
thread_local stack_t tls_alt_stack = {};
thread_local bool tls_alt_installed = false;

bool ensure_alt_stack()
{
	if (tls_alt_installed)
		return true;
	const size_t sz = static_cast<size_t>(SIGSTKSZ) + 64 * 1024;
	void *mem = mmap(nullptr, sz, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (mem == MAP_FAILED)
		return false;
	tls_alt_stack.ss_sp = mem;
	tls_alt_stack.ss_size = sz;
	tls_alt_stack.ss_flags = 0;
	if (sigaltstack(&tls_alt_stack, nullptr) != 0) {
		munmap(mem, sz);
		return false;
	}
	tls_alt_installed = true;
	return true;
}

void sigsegv_handler(int sig, siginfo_t *info, void *context)
{
	// Recovery is allowed only inside the annotated copy window of this
	// thread. The window executes no workload code, so a SEGV here can
	// only come from the faulting source/destination copy itself.
	// Recover on ANY SIGSEGV while this thread is inside the protected
	// copy window. si_code cannot be used as the safety criterion: a
	// non-canonical userspace address (common garbage frame pointer on
	// x86_64) raises #GP, which Linux delivers as SIGSEGV si_code=SI_KERNEL
	// (128), not SEGV_MAPERR/SEGV_ACCERR. The tls_active window wraps only
	// our own memcpy and runs no workload code, so any fault here is a
	// probe-read fault by construction.
	if (tls_active) {
		tls_active = 0;
		// sigsetjmp(,1) saved the mask; siglongjmp restores it, so the
		// SIGSEGV-blocked state installed by the kernel on entry is
		// undone automatically.
		siglongjmp(tls_jump, 1);
	}
	// Not ours: restore the previous disposition and re-raise so real
	// application crashes (including fiber stack corruption elsewhere)
	// keep their original semantics.
	sigaction(sig, &previous_action, nullptr);
	raise(sig);
}

void initialize()
{
	// The disposition is process-wide; the alt stack is installed per
	// thread by protected_copy before arming a recovery.
	struct sigaction action = {};
	action.sa_sigaction = sigsegv_handler;
	action.sa_flags = SA_SIGINFO | SA_ONSTACK;
	sigemptyset(&action.sa_mask);
	handler_ready = sigaction(SIGSEGV, &action, &previous_action) == 0;
	init_succeeded = handler_ready;
}
} // namespace

namespace bpftime::signal_probe
{
bool backend_available()
{
	std::call_once(init_once, initialize);
	return init_succeeded;
}

void rearm_handler()
{
	// Re-run the same sigaction; previous_action is refreshed so a fault
	// outside our window still chains to whatever the host installed.
	initialize();
}

#if defined(__GNUC__) && !defined(__clang__)
__attribute__((noclone))
#endif
__attribute__((noinline)) bool
protected_copy(void *dst, const void *src, size_t size)
{
	if (size == 0)
		return true;
	if (!backend_available())
		return false;
	if (tls_active) // nested invocation: refuse rather than clobber jmpbuf
		return false;
	if (!ensure_alt_stack())
		return false;
	int saved_errno = errno;
	if (sigsetjmp(tls_jump, 1) != 0) {
		errno = saved_errno;
		return false; // recovered fault
	}
	tls_active = 1;
	void *(*volatile copy)(void *, const void *, size_t) = memcpy;
	asm volatile(".local bpftime_probe_copy_begin\n"
		     "bpftime_probe_copy_begin:" ::: "memory");
	copy(dst, src, size);
	asm volatile(".local bpftime_probe_copy_end\n"
		     "bpftime_probe_copy_end:" ::: "memory");
	tls_active = 0;
	errno = saved_errno;
	return true;
}
} // namespace bpftime::signal_probe

#endif // BPFTIME_HAVE_SIGNAL_PROBE_BACKEND
