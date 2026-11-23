#include "spdlog/cfg/env.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/stdout_sinks.h"
#include "spdlog/spdlog.h"
#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <frida-gum.h>
#include <mutex>
#include <optional>
#include "agent_defaults.hpp"
#include "text_segment_transformer.hpp"

#include <string>
#include <thread>

using main_func_t = int (*)(int, char **, char **);

static main_func_t orig_main_func = nullptr;

// Whether syscall server was injected using frida. Defaults to true. If
// __libc_start_main was called, it will be set to false
static bool injected_with_frida = true;
extern "C" void bpftime_agent_main(const gchar *data, gboolean *stay_resident);
extern "C" int64_t call_orig_syscall(int64_t sys_nr, int64_t arg1,
				      int64_t arg2, int64_t arg3, int64_t arg4,
				      int64_t arg5, int64_t arg6,
				      int64_t user_ip, int64_t user_sp,
				      int64_t user_bp);

extern "C" int bpftime_hooked_main(int argc, char **argv, char **envp)
{
	int stay_resident = 0;
	bpftime_agent_main("", &stay_resident);
	int ret = orig_main_func(argc, argv, envp);
	return ret;
}

extern "C" int __libc_start_main(int (*main)(int, char **, char **), int argc,
				 char **argv,
				 int (*init)(int, char **, char **),
				 void (*fini)(void), void (*rtld_fini)(void),
				 void *stack_end)
{
	injected_with_frida = false;
	orig_main_func = main;
	using this_func_t = decltype(&__libc_start_main);
	this_func_t orig = (this_func_t)dlsym(RTLD_NEXT, "__libc_start_main");

	return orig(bpftime_hooked_main, argc, argv, init, fini, rtld_fini,
		    stack_end);
}

extern "C" void bpftime_agent_main(const gchar *data, gboolean *stay_resident)
{
	auto logger = spdlog::stderr_color_mt("stderr");
	spdlog::set_default_logger(logger);
	spdlog::cfg::load_env_levels();
	/* We don't want to our library to be unloaded after we return. */
	*stay_resident = TRUE;

	const char *agent_so_env = getenv("AGENT_SO");
	std::string resolved_agent_so;
	const char *agent_so = nullptr;
	if (agent_so_env != nullptr && agent_so_env[0] != '\0') {
		agent_so = agent_so_env;
	} else if (std::string(data) != "") {
		SPDLOG_INFO("Using agent path from frida data..");
		agent_so = data;
	} else {
		// Default: the agent ships in the same directory as this
		// transformer, so no AGENT_SO setup is required for a
		// plain LD_PRELOAD deployment.
		resolved_agent_so = bpftime::resolve_agent_so_path(
			agent_so_env,
			reinterpret_cast<const void *>(&bpftime_agent_main));
		if (resolved_agent_so.empty()) {
			SPDLOG_ERROR(
				"Could not find libbpftime-agent.so next to the transformer; set AGENT_SO to its path");
			return;
		}
		SPDLOG_INFO("Using sibling agent {}", resolved_agent_so);
		agent_so = resolved_agent_so.c_str();
	}
	SPDLOG_DEBUG("Using agent {}", agent_so);
	cs_arch_register_x86();
	SPDLOG_DEBUG("Loading dynamic library..");
	// dlopen() in the current link namespace is the default; the isolated
	// dlmopen() namespace stays available via BPFTIME_AGENT_USE_DLMOPEN.
	const bool use_same_namespace = bpftime::agent_should_use_dlopen();
	void *next_handle =
		use_same_namespace ?
			dlopen(agent_so, RTLD_NOW | RTLD_LOCAL) :
			dlmopen(LM_ID_NEWLM, agent_so, RTLD_NOW | RTLD_LOCAL);
	if (next_handle == nullptr) {
		SPDLOG_ERROR("Failed to open agent: {}", dlerror());
		return;
	}
	// Set the `injected_with_frida` flag when the agent exports it. The
	// syscall-server does not, so a missing symbol only skips the assignment;
	// returning here would also skip seccomp setup and break rootless tracing.
	bool *injected_with_frida__agent =
		(bool *)dlsym(next_handle, "injected_with_frida");
	if (injected_with_frida__agent)
		*injected_with_frida__agent = injected_with_frida;
	else
		SPDLOG_WARN("Agent does not expose injected_with_frida");
	auto entry_func = (void (*)(syscall_hooker_func_t *))dlsym(
		next_handle, "_bpftime__setup_syscall_trace_callback");

	if (entry_func) {
		syscall_hooker_func_t orig_syscall_hooker_func =
			bpftime::get_call_hook();
		entry_func(&orig_syscall_hooker_func);
		bpftime::set_call_hook(orig_syscall_hooker_func);
	} else if (auto dispatcher = (syscall_hooker_func_t)dlsym(
			   next_handle,
			   "bpftime_syscall_server__dispatch_raw_syscall");
		   dispatcher) {
		bpftime::set_call_hook(dispatcher);
	} else {
		SPDLOG_CRITICAL(
			"Malformed agent so: no syscall callback entry point");
		return;
	}
	// This transformer serves the in-process uprobe text-segment path only.
	// Rootless seccomp capture is owned by bpftime-syscall-server now; do not
	// install it here (loading frida/capstone on that path was the hang).
	// BPFTIME_SKIP_TEXT_SEGMENT_TRACER is an explicit rootless opt-out: the
	// unprivileged bundle captures syscalls through seccomp USER_NOTIF in the
	// syscall-server and memory events through the agent frida uprobe, so no
	// process needs the global text-segment syscall rewrite. That rewrite hangs
	// in torch/CUDA init (futex deadlock, GPU stays at 0%). The classic
	// in-process frida deployment leaves this unset and keeps the full rewrite.
	if (getenv("BPFTIME_SKIP_TEXT_SEGMENT_TRACER") == nullptr) {
		bpftime::setup_syscall_tracer();
		SPDLOG_DEBUG("Transformer exiting, syscall trace is usable now");
	} else {
		SPDLOG_INFO("Rootless opt-out: skipping text-segment syscall tracer");
	}
}
