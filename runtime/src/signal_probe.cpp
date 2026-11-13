// SPDX-License-Identifier: MIT
// Fixed fault-PC -> recovery-PC probe-read backend. The handler returns
// normally, so the kernel sigreturn restores the signal mask and register
// state: no setjmp, no mask bookkeeping and no syscall on the successful
// path. See signal_probe.hpp for the build and contract details.
#include "signal_probe.hpp"

#if BPFTIME_HAVE_SIGNAL_PROBE_BACKEND

#include <cerrno>
#include <cstdint>
#include <mutex>
#include <signal.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <unistd.h>

extern "C" {
int bpftime_pc_safe_copy_asm(void *dst, const void *src, size_t n);
extern const char bpftime_pc_probe_begin[];
extern const char bpftime_pc_probe_end[];
extern const char bpftime_pc_probe_recovery[];
}

namespace
{
struct sigaction prev_segv, prev_bus;
std::mutex init_mtx;
bool init_ok = false;
thread_local stack_t tls_alt = {};
thread_local bool tls_alt_owned = false;

// Reuse an application-provided enabled alt stack; only install our own when
// the thread has none. Small fiber stacks cannot hold the SA_SIGINFO frame.
bool ensure_alt_stack()
{
	if (tls_alt_owned)
		return true;
	stack_t cur;
	if (sigaltstack(nullptr, &cur) == 0 &&
	    !(cur.ss_flags & SS_DISABLE))
		return true;
	const size_t sz = static_cast<size_t>(SIGSTKSZ) + 64 * 1024;
	void *mem = mmap(nullptr, sz, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (mem == MAP_FAILED)
		return false;
	tls_alt = { mem, 0, sz };
	if (sigaltstack(&tls_alt, nullptr) != 0) {
		munmap(mem, sz);
		return false;
	}
	tls_alt_owned = true;
	return true;
}

// Foreign faults keep the host's exact semantics: invoke a previous
// SA_SIGINFO handler directly with the original siginfo/ucontext, otherwise
// restore the saved disposition and re-raise so its action runs unchanged.
void chain_previous(int sig, siginfo_t *info, void *ctx,
		    const struct sigaction &prev)
{
	if (prev.sa_flags & SA_SIGINFO) {
		prev.sa_sigaction(sig, info, ctx);
		return;
	}
	if (prev.sa_handler == SIG_DFL || prev.sa_handler == SIG_IGN) {
		sigaction(sig, &prev, nullptr);
		raise(sig);
		return;
	}
	prev.sa_handler(sig);
}

void fault_handler(int sig, siginfo_t *info, void *ctx)
{
	auto *uc = static_cast<ucontext_t *>(ctx);
	auto *rip = reinterpret_cast<const char *>(
		uc->uc_mcontext.gregs[REG_RIP]);
	// Exact PC membership; si_code deliberately ignored because a
	// non-canonical userspace address raises #GP delivered as
	// SIGSEGV si_code=SI_KERNEL, not SEGV_MAPERR/ACCERR.
	if (rip >= bpftime_pc_probe_begin && rip < bpftime_pc_probe_end) {
		uc->uc_mcontext.gregs[REG_RIP] =
			reinterpret_cast<greg_t>(bpftime_pc_probe_recovery);
		return; // normal return -> sigreturn restores mask
	}
	chain_previous(sig, info, ctx,
		       sig == SIGSEGV ? prev_segv : prev_bus);
}

bool initialize()
{
	// Linux force_sig for a synchronous fault resets the disposition to
	// SIG_DFL when the signal is blocked, killing the process before our
	// handler can run. Refuse while SIGSEGV/SIGBUS is blocked so the
	// caller uses process_vm_readv; a later availability check retries.
	sigset_t cur;
	if (pthread_sigmask(SIG_SETMASK, nullptr, &cur) != 0 ||
	    sigismember(&cur, SIGSEGV) == 1 ||
	    sigismember(&cur, SIGBUS) == 1)
		return init_ok = false;
	struct sigaction sa = {};
	sa.sa_sigaction = fault_handler;
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
	sigemptyset(&sa.sa_mask);
	init_ok = sigaction(SIGSEGV, &sa, &prev_segv) == 0 &&
		  sigaction(SIGBUS, &sa, &prev_bus) == 0;
	return init_ok;
}
} // namespace

namespace bpftime::signal_probe
{
bool backend_available()
{
	if (init_ok)
		return true;
	std::lock_guard<std::mutex> guard(init_mtx);
	if (!init_ok)
		initialize();
	return init_ok;
}

void rearm_handler()
{
	std::lock_guard<std::mutex> guard(init_mtx);
	initialize(); // current disposition becomes the new previous one
}

int protected_copy(void *dst, const void *src, size_t n)
{
	if (n == 0)
		return 1;
	if (!backend_available() || !ensure_alt_stack())
		return -1; // caller must use its safe fallback
	int saved_errno = errno;
	int rc = bpftime_pc_safe_copy_asm(dst, src, n);
	errno = saved_errno;
	return rc;
}
} // namespace bpftime::signal_probe

#endif // BPFTIME_HAVE_SIGNAL_PROBE_BACKEND
