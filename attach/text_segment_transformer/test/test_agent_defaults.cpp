/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2026, eunomia-bpf org
 * All rights reserved.
 *
 * Zero-configuration defaults for the text-segment transformer:
 *
 *  - an explicit non-empty AGENT_SO always wins;
 *  - without it the agent is located next to the transformer via dladdr;
 *  - a missing sibling is reported as an empty path;
 *  - dlopen is the default loader, with BPFTIME_AGENT_USE_DLMOPEN as the
 *    isolated-namespace opt-out.
 */
#include "catch2/catch_test_macros.hpp"
#include "../agent_defaults.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace
{
std::string
fixture_directory()
{
	std::string path(BPFTIME_AGENT_DEFAULTS_FIXTURE_LIBRARY);
	auto slash = path.find_last_of('/');
	REQUIRE(slash != std::string::npos);
	return path.substr(0, slash + 1);
}

void *
load_fixture_and_anchor(void **anchor_out)
{
	void *handle = dlopen(BPFTIME_AGENT_DEFAULTS_FIXTURE_LIBRARY,
			      RTLD_NOW | RTLD_LOCAL);
	REQUIRE(handle != nullptr);
	void *anchor = dlsym(handle, "bpftime_agent_defaults_anchor");
	REQUIRE(anchor != nullptr);
	*anchor_out = anchor;
	return handle;
}
} // namespace

TEST_CASE("explicit AGENT_SO overrides the sibling default",
	  "[agent-transformer][defaults]")
{
	REQUIRE(bpftime::resolve_agent_so_path(
			"/some/where/libbpftime-agent.so",
			reinterpret_cast<const void *>(&fixture_directory)) ==
		"/some/where/libbpftime-agent.so");
}

TEST_CASE("empty AGENT_SO falls back to the sibling agent",
	  "[agent-transformer][defaults]")
{
	const std::string sibling =
		fixture_directory() + bpftime::DEFAULT_AGENT_LIBRARY_NAME;
	::unlink(sibling.c_str());

	void *anchor = nullptr;
	void *handle = load_fixture_and_anchor(&anchor);

	SECTION("missing sibling yields an empty path")
	{
		REQUIRE(bpftime::resolve_agent_so_path("", anchor).empty());
		REQUIRE(bpftime::resolve_agent_so_path(nullptr, anchor).empty());
	}

	SECTION("present sibling is resolved from the anchor directory")
	{
		{
			std::ofstream created(sibling);
			REQUIRE(created.good());
		}
		REQUIRE(chmod(sibling.c_str(), 0644) == 0);
		REQUIRE(bpftime::resolve_agent_so_path("", anchor) ==
			sibling);
		REQUIRE(bpftime::resolve_agent_so_path(nullptr, anchor) ==
			sibling);
		::unlink(sibling.c_str());
	}

	dlclose(handle);
}

TEST_CASE("loader namespace defaults to dlopen",
	  "[agent-transformer][defaults]")
{
	unsetenv("BPFTIME_AGENT_USE_DLMOPEN");
	REQUIRE(bpftime::agent_should_use_dlopen());
	REQUIRE(setenv("BPFTIME_AGENT_USE_DLMOPEN", "1", 1) == 0);
	REQUIRE_FALSE(bpftime::agent_should_use_dlopen());
	unsetenv("BPFTIME_AGENT_USE_DLMOPEN");
}
