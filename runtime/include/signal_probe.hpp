// SPDX-License-Identifier: MIT
// Experimental signal-recovery probe backend (isolation option 4).
//
// Self-contained alternative to upstream PR #702: no Frida Gum dependency.
// A process-wide SIGSEGV handler recovers only faults that occur while the
// thread is inside an annotated protected copy; any SIGSEGV outside that
// window keeps the host's default fatal semantics. Recovery is per-thread
// via thread_local sigjmp_buf, so unrelated threads are never disturbed.
//
// Build: -DBPFTIME_PROBE_READ_SIGNAL=1
#pragma once

#include <cstddef>

#if defined(__linux__) && (defined(__x86_64__) || defined(__aarch64__)) &&  \
	defined(BPFTIME_PROBE_READ_SIGNAL)
#define BPFTIME_HAVE_SIGNAL_PROBE_BACKEND 1
#else
#define BPFTIME_HAVE_SIGNAL_PROBE_BACKEND 0
#endif

namespace bpftime::signal_probe
{
bool backend_available();

// Re-install the SIGSEGV disposition. The backend initializes lazily on first
// use and assumes it stays the active handler; a host (or test framework) that
// installs its own SIGSEGV handler afterwards can call this to move the
// protected-copy handler back on top. Idempotent and cheap.
void rearm_handler();

// Copy size bytes from src to dst without any fault-precheck syscall.
// Returns true on success; false when a SIGSEGV was raised by the copy and
// recovered (the BPF helper maps this to -EFAULT).
bool protected_copy(void *dst, const void *src, size_t size);
} // namespace bpftime::signal_probe
