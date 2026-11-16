/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */

// The system-analysis profiler speaks a private handshake over standard bpf
// syscalls: environment variables select a map named "system_analysis", whose
// looked-up values get synthetic stack slots and instruction bytes, and a
// BPF_RAW_TRACEPOINT_OPEN on "sys_enter" is answered with a mocked fd.
// Keeping that protocol in its own translation unit prevents the generic
// syscall server from carrying product-specific address and opcode policies.

#include "system_analysis_compat.hpp"

#include "bpftime_shm.hpp"
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#if __linux__
#include <linux/bpf.h>
#endif

namespace bpftime::system_analysis_compat {

namespace {

constexpr const char *PTREGS_OFFSET_ENV =
	"BPFTIME_SYSTEM_ANALYSIS_PTREGS_OFFSET";
#if defined(__x86_64__)
constexpr const char *TPBASE_ADDRESS_ENV =
	"BPFTIME_SYSTEM_ANALYSIS_TPBASE_ADDRESS";
constexpr const char *TPBASE_OFFSET_ENV =
	"BPFTIME_SYSTEM_ANALYSIS_TPBASE_OFFSET";
#endif

struct system_analysis_compat_value {
	uint64_t address;
	uint32_t pid;
	int32_t error;
	uint8_t code[128];
};

} // namespace

bool enabled()
{
	if (getenv(PTREGS_OFFSET_ENV) != nullptr)
		return true;
#if defined(__x86_64__)
	return getenv(TPBASE_ADDRESS_ENV) != nullptr &&
	       getenv(TPBASE_OFFSET_ENV) != nullptr;
#else
	return false;
#endif
}

void maybe_complete_map_value(int map_fd, void *value)
{
#if __linux__
	const char *offset_text = getenv(PTREGS_OFFSET_ENV);
#if defined(__x86_64__)
	const char *tpbase_address_text = getenv(TPBASE_ADDRESS_ENV);
	const char *tpbase_offset_text = getenv(TPBASE_OFFSET_ENV);
#else
	const char *tpbase_address_text = nullptr;
	const char *tpbase_offset_text = nullptr;
#endif
	if (offset_text == nullptr &&
	    (tpbase_address_text == nullptr || tpbase_offset_text == nullptr))
		return;
	bpftime::bpf_map_attr map_attr;
	const char *map_name = nullptr;
	bpftime::bpf_map_type map_type;
	int saved_errno = errno;
	if (bpftime_map_get_info(map_fd, &map_attr, &map_name, &map_type) <
		    0 ||
	    map_name == nullptr || strcmp(map_name, "system_analysis") != 0 ||
	    map_attr.value_size < sizeof(system_analysis_compat_value)) {
		errno = saved_errno;
		return;
	}
	auto *analysis = static_cast<system_analysis_compat_value *>(value);
#if defined(__x86_64__)
	if (tpbase_address_text != nullptr && tpbase_offset_text != nullptr) {
		char *address_end = nullptr;
		char *offset_end = nullptr;
		errno = 0;
		unsigned long long address =
			strtoull(tpbase_address_text, &address_end, 0);
		unsigned long offset =
			strtoul(tpbase_offset_text, &offset_end, 0);
		if (errno == 0 && address_end != tpbase_address_text &&
		    *address_end == '\0' && offset_end != tpbase_offset_text &&
		    *offset_end == '\0' && offset <= UINT32_MAX &&
		    analysis->pid != 0 && analysis->address == address) {
			memset(analysis->code, 0, sizeof(analysis->code));
			analysis->code[0] = 0x48;
			analysis->code[1] = 0x89;
			analysis->code[2] = 0xb7;
			uint32_t encoded_offset = (uint32_t)offset;
			memcpy(&analysis->code[3], &encoded_offset,
			       sizeof(encoded_offset));
			analysis->address = 0;
			analysis->error = 0;
			analysis->pid = 0;
			errno = saved_errno;
			return;
		}
	}
#endif
	if (offset_text == nullptr)
		return;
	char *end = nullptr;
	errno = 0;
	unsigned long offset = strtoul(offset_text, &end, 0);
	if (errno != 0 || end == offset_text || *end != '\0' ||
	    offset > UINT32_MAX)
		return;
	if (analysis->pid == 0 || analysis->address >= 4096) {
		errno = saved_errno;
		return;
	}
	constexpr uint64_t stack_base = 1ULL << 20;
	memcpy(analysis->code, &stack_base, sizeof(stack_base));
	analysis->address = stack_base + offset;
	analysis->error = 0;
	analysis->pid = 0;
	errno = saved_errno;
#else
	(void)map_fd;
	(void)value;
#endif
}

std::optional<int>
try_open_raw_tracepoint(const union bpf_attr *attr,
			const std::function<int()> &create_mock_fd)
{
#if __linux__
	if (!enabled())
		return std::nullopt;
	const char *name =
		reinterpret_cast<const char *>(attr->raw_tracepoint.name);
	if (name == nullptr || strcmp(name, "sys_enter") != 0)
		return std::nullopt;
	return create_mock_fd();
#else
	(void)attr;
	(void)create_mock_fd;
	return std::nullopt;
#endif
}

} // namespace bpftime::system_analysis_compat
