// SPDX-License-Identifier: MIT
// Scoped signal-recovery backend for fault-safe host memory copies.
//
// Generic contract (no product-specific assumptions): the backend works on
// arbitrary process addresses and arbitrary byte lengths through the same
// helper ABI as the syscall-based backend. It does not know who calls the
// BPF helper, what data is sampled, or how the destination buffer is used.
//
// Build: -DBPFTIME_PROBE_READ_SIGNAL=ON (Linux x86_64 only in this revision;
// another architecture needs its own annotated copy region and fault table).
#pragma once

#include <cstddef>

#if defined(__linux__) && defined(__x86_64__) && \
	defined(BPFTIME_PROBE_READ_SIGNAL)
#define BPFTIME_HAVE_SIGNAL_PROBE_BACKEND 1
#else
#define BPFTIME_HAVE_SIGNAL_PROBE_BACKEND 0
#endif

namespace bpftime::signal_probe
{
// Copy n bytes from src to dst without a fault-precheck data syscall.
//
// Returns:
//   1  the whole copy succeeded,
//   0  a synchronous source/destination access fault was recovered and the
//      caller must report -EFAULT; the destination buffer may then contain a
//      partial copy (a fault after earlier bytes were stored), so callers
//      must not assume atomicity or any destination content on failure,
//  -1  the backend is unavailable in this thread (for example SIGSEGV or
//      SIGBUS is blocked or the signal stack could not be installed); the
//      caller must use its compile-time safe fallback.
//
// Lifecycle: the SIGSEGV/SIGBUS disposition is installed only for the
// duration of the copy and the previous disposition is restored before
// returning; no process-wide handler is left behind. Nested copies and
// concurrent threads share one refcounted installation. The steady-state
// copy still pays the disposition install/restore syscalls; it is not a
// syscall-free path. A recovered fault additionally involves kernel
// exception delivery and sigreturn.
//
// Supported signal scope: synchronous access faults with si_code
// SEGV_MAPERR, SEGV_ACCERR or SI_KERNEL (the last covers x86_64
// non-canonical #GP) for SIGSEGV, and BUS_ADRERR/BUS_OBJERR for SIGBUS,
// delivered at an exact protected load/store PC. Every other signal --
// including asynchronous SIGSEGV such as kill/tkill -- is forwarded to the
// previous disposition with its original siginfo and ucontext.
int protected_copy(void *dst, const void *src, size_t n) noexcept;

// True when the calling thread can use the backend right now. The result is
// cached per thread after the first feasible check; a blocked-mask result is
// never cached so a later unblocked call retries automatically.
bool backend_available() noexcept;
} // namespace bpftime::signal_probe
