#pragma once

#include <asm/perf_regs.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>

namespace bpftime::cpu_clock
{

inline constexpr size_t stack_bytes = 8192;
inline constexpr size_t register_count = PERF_REG_X86_64_MAX;
inline constexpr uint64_t register_mask = ((1ULL << register_count) - 1) &
	~(0xfULL << PERF_REG_X86_DS);

struct sample {
	uint32_t pid;
	uint32_t tid;
	uint64_t timestamp_ns;
	uint32_t cpu;
	uint64_t period;
	std::array<uint64_t, register_count> registers;
	std::span<const std::byte> stack;
};

class ring
{
	int fd = -1;
	perf_event_mmap_page *metadata = nullptr;
	const std::byte *data = nullptr;
	size_t data_size = 0;
	size_t mmap_size = 0;
	uint64_t tail = 0;

	void copy(uint64_t offset, void *target, size_t count) const
	{
		auto out = static_cast<std::byte *>(target);
		const auto position = offset % data_size;
		const auto first = count < data_size - position ? count :
								  data_size - position;
		std::memcpy(out, data + position, first);
		if (first < count)
			std::memcpy(out + first, data, count - first);
	}

	template <class T> static bool take(std::span<const std::byte> &input, T &out)
	{
		if (input.size() < sizeof(out))
			return false;
		std::memcpy(&out, input.data(), sizeof(out));
		input = input.subspan(sizeof(out));
		return true;
	}

	static bool decode(std::span<const std::byte> record, sample &result)
	{
		uint32_t reserved;
		uint64_t abi;
		uint64_t size;
		if (!take(record, result.pid) || !take(record, result.tid) ||
		    !take(record, result.timestamp_ns) || !take(record, result.cpu) ||
		    !take(record, reserved) || !take(record, result.period) ||
		    !take(record, abi) || abi != PERF_SAMPLE_REGS_ABI_64)
			return false;
		for (size_t i = 0; i < register_count; i++) {
			if ((register_mask & (1ULL << i)) && !take(record, result.registers[i]))
				return false;
		}
		if (!take(record, size) ||
		    size == 0 || size > stack_bytes || size > record.size())
			return false;
		const auto stack = record.first(size);
		record = record.subspan(size);
		uint64_t copied;
		if (!take(record, copied) || copied == 0 || copied > size)
			return false;
		result.stack = stack.first(copied);
		return true;
	}

public:
	ring() = default;
	ring(const ring &) = delete;
	ring &operator=(const ring &) = delete;
	~ring()
	{
		if (metadata)
			syscall(SYS_munmap, metadata, mmap_size);
		if (fd >= 0)
			close(fd);
	}

	bool open(pid_t tid, uint64_t period_ns)
	{
		const long page_size = sysconf(_SC_PAGESIZE);
		if (page_size <= 0) {
			errno = EINVAL;
			return false;
		}
		perf_event_attr attr = {};
		attr.type = PERF_TYPE_SOFTWARE;
		attr.size = sizeof(attr);
		attr.config = PERF_COUNT_SW_CPU_CLOCK;
		attr.sample_period = period_ns;
		attr.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME |
				   PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD |
				   PERF_SAMPLE_REGS_USER | PERF_SAMPLE_STACK_USER;
		attr.disabled = 1;
		attr.exclude_kernel = 1;
		attr.exclude_hv = 1;
		attr.use_clockid = 1;
		attr.clockid = CLOCK_MONOTONIC;
		attr.sample_regs_user = register_mask;
		attr.sample_stack_user = stack_bytes;
		attr.wakeup_events = 1;
		fd = syscall(SYS_perf_event_open, &attr, tid, -1, -1,
			     PERF_FLAG_FD_CLOEXEC);
		if (fd < 0)
			return false;
		mmap_size = 17 * page_size;
		void *mapping = reinterpret_cast<void *>(
			syscall(SYS_mmap, nullptr, mmap_size, PROT_READ | PROT_WRITE,
				MAP_SHARED, fd, 0));
		if (mapping == MAP_FAILED)
			return false;
		metadata = static_cast<perf_event_mmap_page *>(mapping);
		if (metadata->data_offset >= mmap_size ||
		    metadata->data_size > mmap_size - metadata->data_offset ||
		    metadata->data_size < stack_bytes) {
			errno = EINVAL;
			return false;
		}
		data = static_cast<const std::byte *>(mapping) + metadata->data_offset;
		data_size = metadata->data_size;
		return ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) == 0;
	}

	template <class Consumer> size_t drain(Consumer &&consumer)
	{
		const auto head = __atomic_load_n(&metadata->data_head, __ATOMIC_ACQUIRE);
		size_t lost = 0;
		if (head - tail > data_size) {
			tail = head;
			lost++;
		}
		std::array<std::byte, stack_bytes + 512> bytes;
		while (head - tail >= sizeof(perf_event_header)) {
			perf_event_header header;
			copy(tail, &header, sizeof(header));
			if (header.size < sizeof(header) || header.size > head - tail) {
				tail = head;
				lost++;
				break;
			}
			if (header.type == PERF_RECORD_SAMPLE &&
			    header.size - sizeof(header) <= bytes.size()) {
				const auto length = header.size - sizeof(header);
				copy(tail + sizeof(header), bytes.data(), length);
				sample result = {};
				if (decode(std::span(bytes).first(length), result))
					consumer(result);
				else
					lost++;
			} else if (header.type == PERF_RECORD_LOST &&
				   header.size >= sizeof(header) + 2 * sizeof(uint64_t)) {
				uint64_t count;
				copy(tail + sizeof(header) + sizeof(uint64_t), &count, sizeof(count));
				lost += count;
			}
			tail += header.size;
		}
		__atomic_store_n(&metadata->data_tail, tail, __ATOMIC_RELEASE);
		return lost;
	}
};

} // namespace bpftime::cpu_clock
