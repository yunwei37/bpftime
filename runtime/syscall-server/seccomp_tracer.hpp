/* SPDX-License-Identifier: MIT
 *
 * Entry point for the seccomp USER_NOTIF tracer installed by the rootless
 * syscall-server (loader constructor and __libc_start_main interposer).
 * Arming is on by default for a preloaded syscall server;
 * BPFTIME_RUN_WITH_KERNEL is the explicit opt-out because kernel mode handles
 * the intercepted syscalls natively.
 */
#ifndef BPFTIME_SECCOMP_TRACER_HPP
#define BPFTIME_SECCOMP_TRACER_HPP

namespace bpftime
{
namespace seccomp
{
// Install the seccomp user-notification tracer. Returns false when kernel
// mode is requested or the filter/listener could not be installed; failures
// fail open and leave the host running with ordinary syscalls.
bool install_seccomp_tracer();
} // namespace seccomp
} // namespace bpftime

#endif
