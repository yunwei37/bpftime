// SPDX-License-Identifier: MIT
// Fault-safe probe-read backend based on a fixed fault-PC -> recovery-PC
// redirect (async-profiler SafeAccess style). A process-wide SIGSEGV/SIGBUS
// handler recovers only faults whose instruction pointer lies inside the
// annotated copy region; foreign faults keep the host's previous
// disposition. The successful path performs no syscall and no setjmp.
//
// Build: -DBPFTIME_PROBE_READ_SIGNAL=ON (Linux x86_64 only in this revision;
// AArch64 needs its own annotated copy region).
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
// Lazily install the disposition and the per-thread signal stack.
// Returns false while SIGSEGV/SIGBUS is blocked (Linux force_sig would
// reset a blocked synchronous fault to SIG_DFL) so the caller can use the
// process_vm_readv fallback instead; a later call retries initialization.
bool backend_available();

// Re-install the disposition after a host component installed its own
// SIGSEGV/SIGBUS handler on top of ours. The current disposition becomes
// the new previous one and keeps being chained for foreign faults.
void rearm_handler();

// Copy n bytes from src to dst without any fault-precheck syscall.
// Returns: 1 copy succeeded;
//          0 a source/destination fault was recovered (maps to -EFAULT);
//         -1 backend unavailable (caller MUST use its safe fallback).
int protected_copy(void *dst, const void *src, size_t n);
} // namespace bpftime::signal_probe
