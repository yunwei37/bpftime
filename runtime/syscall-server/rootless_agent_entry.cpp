/* SPDX-License-Identifier: MIT
 *
 * Rootless entry point compiled into bpftime-syscall-server.
 *
 * ARCHITECTURE INVARIANT — DO NOT BREAK:
 * On the rootless path this single shared object owns the whole interception
 * lifecycle. It must not dlopen or otherwise reach any attach/ component
 * (frida/capstone/text-segment transformer). The in-process uprobe
 * text-segment mode keeps using the transformer separately and is untouched.
 *
 * We interpose __libc_start_main (a normal libc symbol, available after the
 * loader has initialized pthread) rather than using a library constructor:
 * the seccomp worker threads must be fully startable before the filter is
 * installed, which cannot be guaranteed at constructor time.
 */
#if defined(__linux__) && defined(__x86_64__)
#include "seccomp_tracer.hpp"
#include <dlfcn.h>
#include <spdlog/spdlog.h>
#include <string>

using bpftime_main_func_t = int (*)(int, char **, char **);

extern "C" int __libc_start_main(bpftime_main_func_t main, int argc,
				 char **argv, int (*init)(int, char **, char **),
				 void (*fini)(void), void (*rtld_fini)(void),
				 void *stack_end)
{
	auto *orig = reinterpret_cast<int (*)(bpftime_main_func_t, int, char **,
					      int (*)(int, char **, char **),
					      void (*)(void), void (*)(void),
					      void *)>(
		dlsym(RTLD_NEXT, "__libc_start_main"));

	// Load the agent runtime (shared-memory/maps/programs). Plain dlopen in
	// the current namespace; this is runtime, not attach. Failure is logged
	// and non-fatal so the host process keeps running (fail open).
	if (const char *agent_so = getenv("AGENT_SO"); agent_so != nullptr) {
		if (dlopen(agent_so, RTLD_NOW | RTLD_LOCAL) == nullptr) {
			SPDLOG_ERROR("rootless: failed to load agent {}: {}",
				     agent_so, dlerror());
		}
	}

	// Install the seccomp USER_NOTIF filter with workers started first.
	// No-op unless BPFTIME_GO_SECCOMP is set, preserving the env gate.
	bpftime::seccomp::install_seccomp_tracer();

	return orig(main, argc, argv, init, fini, rtld_fini, stack_end);
}
#endif
