#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace bpftime::cpu_clock
{

struct replay_context {
	uint64_t pid_tgid;
	uint64_t timestamp_ns;
	uintptr_t stack_begin;
	uintptr_t stack_end;
	uintptr_t sampled_sp;
	std::span<const std::byte> stack;
};

inline thread_local const replay_context *current_sample = nullptr;

class replay_scope
{
	const replay_context *previous;

public:
	explicit replay_scope(const replay_context &sample)
		: previous(current_sample)
	{
		current_sample = &sample;
	}

	~replay_scope()
	{
		current_sample = previous;
	}
};

} // namespace bpftime::cpu_clock
