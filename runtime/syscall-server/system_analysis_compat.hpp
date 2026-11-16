/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#pragma once

#include <functional>
#include <optional>

// Forward declaration: the complete union comes from <linux/bpf.h> on Linux.
union bpf_attr;

namespace bpftime::system_analysis_compat {

// True when the private system-analysis profiler handshake is enabled via
// BPFTIME_SYSTEM_ANALYSIS_* environment variables.
bool enabled();

// Complete a looked-up "system_analysis" map value with the synthetic stack
// slot and instruction bytes requested by the env-driven handshake. No-op for
// every other map and when the handshake is disabled.
void maybe_complete_map_value(int map_fd, void *value);

// Intercept BPF_RAW_TRACEPOINT_OPEN for the handshake. Returns a mocked fd
// when the request belongs to the compat protocol; nullopt tells the caller
// to run the original kernel syscall.
std::optional<int>
try_open_raw_tracepoint(const union bpf_attr *attr,
			const std::function<int()> &create_mock_fd);

} // namespace bpftime::system_analysis_compat
