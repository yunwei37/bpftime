/* SPDX-License-Identifier: MIT
 *
 * Default agent library resolution for the text-segment transformer.
 *
 * A preloaded libbpftime-agent-transformer.so ships next to
 * libbpftime-agent.so, so the agent path and the loader namespace are
 * derived automatically instead of requiring AGENT_SO or a loader env var
 * on every invocation. The helpers are header-only and depend only on
 * libc/libdl so unit tests can include them without the frida-gum link.
 */
#include <cstdlib>
#ifndef BPFTIME_AGENT_DEFAULTS_HPP
#define BPFTIME_AGENT_DEFAULTS_HPP

#include <dlfcn.h>
#include <string>
#include <unistd.h>

namespace bpftime
{

constexpr const char *DEFAULT_AGENT_LIBRARY_NAME = "libbpftime-agent.so";

// Resolve the agent shared object to load:
//  1. an explicit, non-empty AGENT_SO value always wins;
//  2. otherwise locate the directory of the shared object that owns
//     `anchor` (an address inside libbpftime-agent-transformer.so) and use
//     the sibling libbpftime-agent.so;
//  3. return an empty string when the sibling does not exist or the own
//     object cannot be located.
inline std::string
resolve_agent_so_path(const char *agent_so_env, const void *anchor)
{
	if (agent_so_env != nullptr && agent_so_env[0] != '\0')
		return std::string(agent_so_env);

	Dl_info info{};
	if (dladdr(anchor, &info) == 0 || info.dli_fname == nullptr ||
	    info.dli_fname[0] == '\0')
		return {};

	std::string own_path(info.dli_fname);
	auto slash = own_path.find_last_of('/');
	if (slash == std::string::npos)
		return {};
	std::string candidate = own_path.substr(0, slash + 1) +
				DEFAULT_AGENT_LIBRARY_NAME;
	if (access(candidate.c_str(), R_OK) != 0)
		return {};
	return candidate;
}

// dlopen() in the current namespace is the safe default: the agent shares
// the preloaded runtime's symbols and dependencies. dlmopen() into a new
// link map remains available through BPFTIME_AGENT_USE_DLMOPEN for the
// isolated-namespace deployment it was designed for.
inline bool
agent_should_use_dlopen()
{
	return getenv("BPFTIME_AGENT_USE_DLMOPEN") == nullptr;
}

} // namespace bpftime

#endif
