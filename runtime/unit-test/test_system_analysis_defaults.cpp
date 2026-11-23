/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2026, eunomia-bpf org
 * All rights reserved.
 *
 * Coverage for the zero-configuration rootless defaults in syscall_context:
 *
 *  - BPF_RAW_TRACEPOINT_OPEN("sys_enter") is emulated with a synthetic fd in
 *    userspace mode even when no ptregs offset env var is set;
 *  - BPF_MAP_LOOKUP_ELEM on the system_analysis map completes the synthetic
 *    stack frame using the built-in 4096 pt_regs offset, while an explicit
 *    env override keeps working;
 *  - BPFTIME_RUN_WITH_KERNEL routes both operations to the real kernel (they
 *    fail for an shm-only fd, which proves the gate deterministically);
 *  - an unknown ioctl on the mocked path logs at debug level instead of warn.
 */
#include "catch2/catch_test_macros.hpp"

#if defined(__linux__)
#include "bpftime_shm.hpp"
#include "syscall_context.hpp"
#include "spdlog/sinks/callback_sink.h"
#include "spdlog/spdlog.h"
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <linux/bpf.h>
#include <string>
#include <unistd.h>
#include <vector>

namespace
{
// Mirrors the private layout in syscall_context.cpp.
struct system_analysis_compat_value {
	uint64_t address;
	uint32_t pid;
	int32_t error;
	uint8_t code[128];
};

constexpr uint64_t SYNTHETIC_STACK_BASE = 1ULL << 20;

struct shm_test_fixture {
	std::string shm_name;
	bool initialized = false;

	shm_test_fixture()
	{
		shm_name = "bpftime-sys-analysis-defaults-" +
			   std::to_string(getpid());
		REQUIRE(setenv("BPFTIME_GLOBAL_SHM_NAME", shm_name.c_str(),
				1) == 0);
		bpftime_destroy_global_shm();
		bpftime_initialize_global_shm(
			bpftime::shm_open_type::SHM_REMOVE_AND_CREATE);
		initialized = true;
	}

	~shm_test_fixture()
	{
		if (initialized) {
			bpftime_destroy_global_shm();
			bpftime_initialize_global_shm(
				bpftime::shm_open_type::SHM_NO_CREATE);
		}
		unsetenv("BPFTIME_GLOBAL_SHM_NAME");
	}
};

int
create_analysis_map(const char *name)
{
	bpftime::bpf_map_attr attr{};
	attr.type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(system_analysis_compat_value);
	attr.max_ents = 1;
	int fd = bpftime_maps_create(-1, name, attr);
	REQUIRE(fd >= 0);
	return fd;
}

void
seed_analysis_value(int map_fd, uint32_t pid, uint64_t address)
{
	system_analysis_compat_value value{};
	value.pid = pid;
	value.address = address;
	uint32_t key = 0;
	REQUIRE(bpftime_map_update_elem(map_fd, &key, &value, 0) == 0);
}
} // namespace

TEST_CASE("sys_enter raw tracepoint opens without any env configuration",
	  "[syscall-server][system-analysis]")
{
	shm_test_fixture fixture;
	syscall_context ctx;
	unsetenv("BPFTIME_SYSTEM_ANALYSIS_PTREGS_OFFSET");
	unsetenv("BPFTIME_RUN_WITH_KERNEL");

	union bpf_attr attr{};
	attr.raw_tracepoint.name =
		reinterpret_cast<uint64_t>("sys_enter");
	long fd = ctx.handle_sysbpf(BPF_RAW_TRACEPOINT_OPEN, &attr,
				   sizeof(attr));
	REQUIRE(fd >= 0);
	REQUIRE(close(static_cast<int>(fd)) == 0);
}

TEST_CASE("system_analysis lookup uses the built-in 4096 offset by default",
	  "[syscall-server][system-analysis]")
{
	shm_test_fixture fixture;
	syscall_context ctx;
	unsetenv("BPFTIME_SYSTEM_ANALYSIS_PTREGS_OFFSET");
	unsetenv("BPFTIME_RUN_WITH_KERNEL");

	const int map_fd = create_analysis_map("system_analysis");
	seed_analysis_value(map_fd, 4321, 100);

	union bpf_attr attr{};
	uint32_t key = 0;
	system_analysis_compat_value result{};
	attr.map_fd = static_cast<uint32_t>(map_fd);
	attr.key = reinterpret_cast<uint64_t>(&key);
	attr.value = reinterpret_cast<uint64_t>(&result);
	REQUIRE(ctx.handle_sysbpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) ==
		0);
	REQUIRE(result.pid == 0);
	REQUIRE(result.address == SYNTHETIC_STACK_BASE + 4096);
	uint64_t code_base = 0;
	memcpy(&code_base, result.code, sizeof(code_base));
	REQUIRE(code_base == SYNTHETIC_STACK_BASE);
}

TEST_CASE("ptregs offset env override still takes effect",
	  "[syscall-server][system-analysis]")
{
	shm_test_fixture fixture;
	syscall_context ctx;
	REQUIRE(setenv("BPFTIME_SYSTEM_ANALYSIS_PTREGS_OFFSET", "8192", 1) ==
		0);
	unsetenv("BPFTIME_RUN_WITH_KERNEL");

	const int map_fd = create_analysis_map("system_analysis");
	seed_analysis_value(map_fd, 4321, 100);

	union bpf_attr attr{};
	uint32_t key = 0;
	system_analysis_compat_value result{};
	attr.map_fd = static_cast<uint32_t>(map_fd);
	attr.key = reinterpret_cast<uint64_t>(&key);
	attr.value = reinterpret_cast<uint64_t>(&result);
	REQUIRE(ctx.handle_sysbpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) ==
		0);
	REQUIRE(result.address == SYNTHETIC_STACK_BASE + 8192);
	unsetenv("BPFTIME_SYSTEM_ANALYSIS_PTREGS_OFFSET");
}

TEST_CASE("unrelated maps are left untouched by the analysis completion",
	  "[syscall-server][system-analysis]")
{
	shm_test_fixture fixture;
	syscall_context ctx;
	unsetenv("BPFTIME_SYSTEM_ANALYSIS_PTREGS_OFFSET");
	unsetenv("BPFTIME_RUN_WITH_KERNEL");

	const int map_fd = create_analysis_map("plain_map");
	seed_analysis_value(map_fd, 4321, 100);

	union bpf_attr attr{};
	uint32_t key = 0;
	system_analysis_compat_value result{};
	attr.map_fd = static_cast<uint32_t>(map_fd);
	attr.key = reinterpret_cast<uint64_t>(&key);
	attr.value = reinterpret_cast<uint64_t>(&result);
	REQUIRE(ctx.handle_sysbpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) ==
		0);
	REQUIRE(result.pid == 4321);
	REQUIRE(result.address == 100);
}

TEST_CASE("kernel mode passes the analysis operations through",
	  "[syscall-server][system-analysis]")
{
	// run_with_kernel is read from the environment when the context is
	// constructed, so the variable must be set first.
	REQUIRE(setenv("BPFTIME_RUN_WITH_KERNEL", "1", 1) == 0);
	shm_test_fixture fixture;
	syscall_context ctx;

	SECTION("raw tracepoint open reaches the real kernel")
	{
		union bpf_attr attr{};
		attr.raw_tracepoint.name =
			reinterpret_cast<uint64_t>("sys_enter");
		long fd = ctx.handle_sysbpf(BPF_RAW_TRACEPOINT_OPEN, &attr,
					   sizeof(attr));
		// Unprivileged processes cannot open a kernel raw tracepoint;
		// the deterministic fact under test is that emulation was
		// skipped, not a particular errno.
		REQUIRE(fd < 0);
	}

	SECTION("map lookup reaches the real kernel for an shm-only fd")
	{
		const int map_fd = create_analysis_map("system_analysis");
		seed_analysis_value(map_fd, 4321, 100);
		union bpf_attr attr{};
		uint32_t key = 0;
		system_analysis_compat_value result{};
		attr.map_fd = static_cast<uint32_t>(map_fd);
		attr.key = reinterpret_cast<uint64_t>(&key);
		attr.value = reinterpret_cast<uint64_t>(&result);
		REQUIRE(ctx.handle_sysbpf(BPF_MAP_LOOKUP_ELEM, &attr,
					  sizeof(attr)) < 0);
		// Passthrough means the local buffer is never written by the
		// emulation completion path.
		REQUIRE(result.pid == 0);
		REQUIRE(result.address == 0);
	}
	unsetenv("BPFTIME_RUN_WITH_KERNEL");
}

TEST_CASE("unknown ioctl on the mocked path logs at debug level",
	  "[syscall-server][system-analysis]")
{
	shm_test_fixture fixture;
	syscall_context ctx;
	unsetenv("BPFTIME_RUN_WITH_KERNEL");

	auto previous_logger = spdlog::default_logger();
	std::vector<spdlog::level::level_enum> levels;
	auto sink = std::make_shared<spdlog::sinks::callback_sink_mt>(
		[&levels](const spdlog::details::log_msg &msg) {
			levels.push_back(msg.level);
		});
	auto logger = std::make_shared<spdlog::logger>(
		"system-analysis-defaults-test", sink);
	logger->set_level(spdlog::level::debug);
	spdlog::set_default_logger(logger);

	// An ordinary file fd cannot understand this request; the mocked path
	// still logs its passthrough decision before returning ENOTTY.
	errno = 0;
	int pipe_fds[2];
	REQUIRE(pipe(pipe_fds) == 0);
	const int res = ctx.handle_ioctl(pipe_fds[0], 0x7f00deadUL, 0);
	const int saved_errno = errno;
	REQUIRE(res < 0);
	REQUIRE(saved_errno == ENOTTY);
	close(pipe_fds[0]);
	close(pipe_fds[1]);

	spdlog::set_default_logger(previous_logger);
	bool saw_warn = false;
	for (auto level : levels)
		if (level == spdlog::level::warn ||
		    level == spdlog::level::err ||
		    level == spdlog::level::critical)
			saw_warn = true;
	REQUIRE_FALSE(saw_warn);
	REQUIRE(std::find(levels.begin(), levels.end(),
			  spdlog::level::debug) != levels.end());
}
#endif
