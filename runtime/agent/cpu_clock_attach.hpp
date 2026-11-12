#pragma once

#if defined(__linux__) && defined(__x86_64__)

#include "base_attach_impl.hpp"
#include "bpftime_shm.hpp"
#include "cpu_clock_replay.hpp"
#include "cpu_clock_ring.hpp"

#include <dirent.h>
#include <pthread.h>
#include <sys/user.h>

#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <thread>

namespace bpftime::cpu_clock
{

struct clock_config : attach::attach_private_data {
	uint64_t period = 0;
	int cpu = -1;
	int perf_fd = -1;

	int initialize_from_string(const std::string_view &value) override
	{
		const auto first = value.find(':');
		const auto last = value.rfind(':');
		if (first == std::string_view::npos || first == last)
			return -EINVAL;
		const auto parse = [](std::string_view field, auto &out) {
			const auto [end, error] = std::from_chars(field.data(),
				field.data() + field.size(), out);
			return error == std::errc{} && end == field.data() + field.size();
		};
		if (!parse(value.substr(0, first), period) ||
		    !parse(value.substr(first + 1, last - first - 1), cpu) ||
		    !parse(value.substr(last + 1), perf_fd) ||
		    period < 1000000 || cpu < 0 || perf_fd < 0)
			return -EINVAL;
		return 0;
	}
};

class clock_attach : public attach::base_attach_impl
{
	struct event {
		clock_config config;
		attach::ebpf_run_callback callback;
	};
	struct thread_clock {
		std::unique_ptr<ring> input;
		uintptr_t stack_begin = 0;
		uintptr_t stack_end = 0;
	};

	const pid_t process_id = getpid();
	std::mutex events_mutex;
	std::map<int, event> events;
	std::atomic<bool> stopping = false;
	pthread_t worker = {};
	bool started = false;

	void reconcile_threads(std::map<pid_t, thread_clock> &clocks,
			       uint64_t period)
	{
		auto *tasks = opendir("/proc/self/task");
		if (!tasks)
			return;
		std::set<pid_t> alive;
		const auto worker_tid = syscall(SYS_gettid);
		while (auto *item = readdir(tasks)) {
			pid_t tid;
			const auto *end = item->d_name + std::strlen(item->d_name);
			const auto [last, error] = std::from_chars(item->d_name, end, tid);
			if (error != std::errc{} || last != end || tid == worker_tid)
				continue;
			alive.insert(tid);
			if (clocks.contains(tid))
				continue;
			auto input = std::make_unique<ring>();
			if (!input->open(tid, period)) {
				SPDLOG_WARN("Thread CPU clock open failed tid={} errno={}",
					    tid, errno);
				// Keep the failed entry until the TID disappears.
				input.reset();
			}
			clocks.emplace(tid, thread_clock{ std::move(input) });
		}
		closedir(tasks);
		std::erase_if(clocks, [&](const auto &entry) {
			return !alive.contains(entry.first);
		});
	}

	static bool resolve_stack(thread_clock &clock, uintptr_t sp)
	{
		if (sp >= clock.stack_begin && sp < clock.stack_end)
			return true;
		std::ifstream maps("/proc/self/maps");
		std::string line;
		while (std::getline(maps, line)) {
			uintptr_t low, high;
			char perms[5];
			if (std::sscanf(line.c_str(), "%lx-%lx %4s", &low, &high, perms) == 3 &&
			    perms[0] == 'r' && sp >= low && sp < high) {
				clock.stack_begin = low;
				clock.stack_end = high;
				return true;
			}
		}
		return false;
	}

	void dispatch(thread_clock &clock, const sample &sample)
	{
		const auto &r = sample.registers;
		const auto sp = r[PERF_REG_X86_SP];
		if (sample.pid != static_cast<uint32_t>(process_id) ||
		    !r[PERF_REG_X86_IP] || !resolve_stack(clock, sp) ||
		    sample.stack.size() > clock.stack_end - sp)
			return;
		struct user_regs_struct regs = {};
		regs.r15 = r[PERF_REG_X86_R15];
		regs.r14 = r[PERF_REG_X86_R14];
		regs.r13 = r[PERF_REG_X86_R13];
		regs.r12 = r[PERF_REG_X86_R12];
		regs.rbp = r[PERF_REG_X86_BP];
		regs.rbx = r[PERF_REG_X86_BX];
		regs.r11 = r[PERF_REG_X86_R11];
		regs.r10 = r[PERF_REG_X86_R10];
		regs.r9 = r[PERF_REG_X86_R9];
		regs.r8 = r[PERF_REG_X86_R8];
		regs.rax = r[PERF_REG_X86_AX];
		regs.rcx = r[PERF_REG_X86_CX];
		regs.rdx = r[PERF_REG_X86_DX];
		regs.rsi = r[PERF_REG_X86_SI];
		regs.rdi = r[PERF_REG_X86_DI];
		regs.orig_rax = static_cast<uint64_t>(-1);
		regs.rip = r[PERF_REG_X86_IP];
		regs.cs = r[PERF_REG_X86_CS];
		regs.eflags = r[PERF_REG_X86_FLAGS];
		regs.rsp = sp;
		regs.ss = r[PERF_REG_X86_SS];
		const replay_context context = {
			(static_cast<uint64_t>(sample.pid) << 32) | sample.tid,
			sample.timestamp_ns, clock.stack_begin, clock.stack_end, sp,
			sample.stack,
		};
		std::lock_guard lock(events_mutex);
		for (const auto &[id, event] : events) {
			if (event.config.cpu != static_cast<int>(sample.cpu) ||
			    !bpftime_thread_cpu_clock_enabled(event.config.perf_fd))
				continue;
			uint64_t result;
			replay_scope replay(context);
			event.callback(&regs, offsetof(user_regs_struct, fs_base), &result);
		}
	}

	void run()
	{
		attach::attach_callback_suppression_scope suppress_callbacks;
		std::map<pid_t, thread_clock> clocks;
		auto next_discovery = std::chrono::steady_clock::now();
		uint64_t active_period = 0;
		uint64_t lost = 0;
		while (!stopping.load(std::memory_order_acquire)) {
			uint64_t period = 0;
			{
				std::lock_guard lock(events_mutex);
				for (const auto &[id, event] : events) {
					if (bpftime_thread_cpu_clock_enabled(event.config.perf_fd)) {
						period = event.config.period;
						break;
					}
				}
			}
			const auto now = std::chrono::steady_clock::now();
			if (active_period != period) {
				clocks.clear();
				active_period = period;
				next_discovery = now;
			}
			if (period && now >= next_discovery) {
				reconcile_threads(clocks, period);
				next_discovery = now + std::chrono::milliseconds(200);
			}
			for (auto &[tid, clock] : clocks) {
				if (clock.input)
					lost += clock.input->drain([&](const sample &s) {
						dispatch(clock, s);
					});
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(15));
		}
		if (lost)
			SPDLOG_WARN("Thread CPU clock lost or rejected {} records", lost);
	}

public:
	int start()
	{
		if (getpid() != process_id)
			return -ENOTSUP;
		std::lock_guard lock(events_mutex);
		if (started || events.empty())
			return 0;
		const auto error = pthread_create(&worker, nullptr, [](void *data) -> void * {
			try {
				static_cast<clock_attach *>(data)->run();
			} catch (const std::exception &e) {
				SPDLOG_WARN("Thread CPU clock stopped: {}", e.what());
			}
			return nullptr;
		}, this);
		if (error != 0)
			return -error;
		started = true;
		return 0;
	}

	void shutdown()
	{
		if (started && getpid() == process_id) {
			stopping.store(true, std::memory_order_release);
			pthread_join(worker, nullptr);
			started = false;
		}
	}

	~clock_attach() override { shutdown(); }

	int detach_by_id(int id) override
	{
		if (getpid() != process_id)
			return 0;
		std::lock_guard lock(events_mutex);
		return events.erase(id) ? 0 : -ENOENT;
	}

	int create_attach_with_ebpf_callback(attach::ebpf_run_callback &&callback,
			const attach::attach_private_data &data, int) override
	{
		const auto &config = static_cast<const clock_config &>(data);
		if (getpid() != process_id)
			return -ENOTSUP;
		std::lock_guard lock(events_mutex);
		if (!events.empty() && events.begin()->second.config.period != config.period)
			return -EINVAL;
		const auto id = allocate_id();
		events.emplace(id, event{ config, std::move(callback) });
		return id;
	}
};

} // namespace bpftime::cpu_clock
#endif
