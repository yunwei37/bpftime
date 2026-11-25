/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2026, bpftime contributors
 * All rights reserved.
 */
#ifndef ROBUST_SHM_MUTEX_HPP
#define ROBUST_SHM_MUTEX_HPP

#include "spdlog/spdlog.h"
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#if defined(__linux__)
#include <fcntl.h>
#include <sys/syscall.h>
#elif defined(__APPLE__)
#include <signal.h>
#endif

namespace bpftime
{
namespace detail
{

inline constexpr uint64_t SHM_MUTEX_TAINTED = uint64_t{ 1 } << 63;

inline void shm_cpu_relax() noexcept
{
#if defined(__x86_64__) || defined(__i386__)
	__builtin_ia32_pause();
#elif defined(__aarch64__) || defined(__arm__)
	asm volatile("yield" ::: "memory");
#else
	std::atomic_signal_fence(std::memory_order_seq_cst);
#endif
}

#if defined(__linux__)
inline char *append_str(char *dst, const char *s) noexcept
{
	while (*s)
		*dst++ = *s++;
	return dst;
}

inline char *append_u32(char *dst, uint32_t v) noexcept
{
	char tmp[16];
	int n = 0;
	do {
		tmp[n++] = static_cast<char>('0' + (v % 10));
		v /= 10;
	} while (v != 0);
	while (n > 0)
		*dst++ = tmp[--n];
	return dst;
}

// Allocation-free reader for /proc/<pid>/task/<tid>/stat.
// Returns -1 if the thread/process entry no longer exists, 0 if unreadable,
// or 1 with state_out and 19-bit non-zero start_tag populated.
inline int read_proc_thread_stat(uint32_t pid, uint32_t tid, char &state_out,
				 uint32_t &tag_out) noexcept
{
	char path[64];
	char *end = append_str(path, "/proc/");
	end = append_u32(end, pid);
	end = append_str(end, "/task/");
	end = append_u32(end, tid);
	end = append_str(end, "/stat");
	*end = '\0';

	int fd = ::open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT || errno == ESRCH) ? -1 : 0;
	char buf[512];
	ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
	::close(fd);
	if (n <= 0)
		return 0;
	buf[n] = '\0';

	const char *rparen = std::strrchr(buf, ')');
	if (!rparen || rparen[1] != ' ' || rparen[2] == '\0')
		return 0;
	state_out = rparen[2];
	tag_out = 0;

	const char *p = rparen + 2;
	for (int field = 3; field < 22; ++field) {
		while (*p != '\0' && *p != ' ')
			++p;
		while (*p == ' ')
			++p;
	}
	if (*p < '0' || *p > '9')
		return 1;
	uint64_t st = 0;
	while (*p >= '0' && *p <= '9')
		st = st * 10 + static_cast<uint64_t>(*p++ - '0');
	uint32_t tag =
		static_cast<uint32_t>((st ^ (st >> 19) ^ (st >> 38)) & 0x7FFFFu);
	tag_out = tag == 0 ? 1u : tag;
	return 1;
}
#endif

inline thread_local uint64_t shm_mutex_owner_token = 0;
inline std::atomic<int> shm_mutex_atfork_state{ 0 };

inline void reset_shm_mutex_owner_token_in_child() noexcept
{
	shm_mutex_owner_token = 0;
}

__attribute__((noinline)) inline uint64_t init_shm_owner_token_slow() noexcept
{
	const int saved_errno = errno;
	int st = shm_mutex_atfork_state.load(std::memory_order_acquire);
	if (st == 0) {
		int expected = 0;
		if (shm_mutex_atfork_state.compare_exchange_strong(
			    expected, 1, std::memory_order_acq_rel)) {
			int rc = pthread_atfork(
				nullptr, nullptr,
				reset_shm_mutex_owner_token_in_child);
			st = (rc == 0) ? 2 : -1;
			shm_mutex_atfork_state.store(
				st, std::memory_order_release);
		} else {
			while ((st = shm_mutex_atfork_state.load(
					std::memory_order_acquire)) == 1)
				shm_cpu_relax();
		}
	}

	uint64_t token = 1;
#if defined(__linux__)
	const uint32_t pid = static_cast<uint32_t>(::getpid()) & 0x3FFFFFu;
	const uint32_t tid =
		static_cast<uint32_t>(::syscall(SYS_gettid)) & 0x3FFFFFu;
	char proc_state = 0;
	uint32_t tag = 0;
	(void)read_proc_thread_stat(pid, tid, proc_state, tag);
	token = (static_cast<uint64_t>(tag & 0x7FFFFu) << 44) |
		(static_cast<uint64_t>(pid) << 22) |
		static_cast<uint64_t>(tid ? tid : 1u);
#elif defined(__APPLE__)
	uint64_t tid64 = 0;
	pthread_threadid_np(nullptr, &tid64);
	const uint32_t pid = static_cast<uint32_t>(::getpid()) & 0x3FFFFFu;
	const uint32_t tid = static_cast<uint32_t>(tid64) & 0x3FFFFFu;
	token = (static_cast<uint64_t>(pid) << 22) |
		static_cast<uint64_t>(tid ? tid : 1u);
#endif
	if (st == 2)
		shm_mutex_owner_token = token;
	errno = saved_errno;
	return token;
}

inline uint64_t current_shm_owner_token() noexcept
{
	uint64_t t = shm_mutex_owner_token;
	if (__builtin_expect(t != 0, 1))
		return t;
	return init_shm_owner_token_slow();
}

inline bool shm_owner_is_dead(uint64_t owner) noexcept
{
	if (owner == 0 || (owner & SHM_MUTEX_TAINTED) != 0)
		return false;
#if defined(__linux__)
	const uint32_t tid = static_cast<uint32_t>(owner & 0x3FFFFFu);
	const uint32_t pid = static_cast<uint32_t>((owner >> 22) & 0x3FFFFFu);
	const uint32_t want_tag =
		static_cast<uint32_t>((owner >> 44) & 0x7FFFFu);
	if (pid == 0 || tid == 0)
		return false;
	if (::syscall(SYS_tgkill, static_cast<int>(pid), static_cast<int>(tid),
		      0) != 0 &&
	    errno == ESRCH)
		return true;
	char state = 0;
	uint32_t live_tag = 0;
	int rc = read_proc_thread_stat(pid, tid, state, live_tag);
	if (rc < 0)
		return true;
	if (rc > 0) {
		if (state == 'Z' || state == 'X' || state == 'x')
			return true;
		if (want_tag != 0 && live_tag != 0 && live_tag != want_tag)
			return true;
	}
	return false;
#elif defined(__APPLE__)
	const uint32_t pid = static_cast<uint32_t>((owner >> 22) & 0x3FFFFFu);
	if (pid == 0)
		return false;
	return ::kill(static_cast<pid_t>(pid), 0) != 0 && errno == ESRCH;
#else
	return false;
#endif
}

} // namespace detail

// Process-shared, 8-byte atomic spinlock with dead-holder detection on the
// slow path. Fast path is a single CAS (0 -> cached owner token) and single
// release store (0), matching pthread_spinlock_t latency and throughput while
// avoiding glibc robust-list overhead. Only after sustained contention on an
// unchanged owner token does a waiter check owner liveness (including unreaped
// SIGKILL zombies and PID/TID reuse):
//   - lock_and_recover(): atomically claims the lock from the dead owner
//     (for structures like ringbuf whose critical section preserves invariants);
//   - lock(label): atomically latches TAINTED and fails closed with EBUSY
//     (for maps/containers whose state may be half-mutated).
class robust_shm_mutex {
	static_assert(std::atomic<uint64_t>::is_always_lock_free,
		      "robust_shm_mutex requires lock-free 64-bit atomics");
	std::atomic<uint64_t> state{ 0 };

	__attribute__((noinline)) bool
	lock_slow(uint64_t me, bool recover, const char *label) noexcept
	{
		const int saved_errno = errno;
		uint64_t tracked_owner = 0;
		uint32_t same_owner_yields = 0;

		for (;;) {
			for (int spin = 0; spin < 128; ++spin) {
				uint64_t cur =
					state.load(std::memory_order_relaxed);
				if (cur == 0) {
					if (state.compare_exchange_weak(
						    cur, me,
						    std::memory_order_acquire,
						    std::memory_order_relaxed)) {
						errno = saved_errno;
						return true;
					}
					continue;
				}
				if (!recover &&
				    (cur & detail::SHM_MUTEX_TAINTED) != 0) {
					errno = EBUSY;
					return false;
				}
				detail::shm_cpu_relax();
			}

			uint64_t cur = state.load(std::memory_order_acquire);
			if (cur == 0)
				continue;
			if (!recover &&
			    (cur & detail::SHM_MUTEX_TAINTED) != 0) {
				errno = EBUSY;
				return false;
			}
			if (cur != tracked_owner) {
				tracked_owner = cur;
				same_owner_yields = 0;
			}
			if (++same_owner_yields < 512) {
				sched_yield();
				continue;
			}

			if (detail::shm_owner_is_dead(cur)) {
				if (recover) {
					if (state.compare_exchange_strong(
						    cur, me,
						    std::memory_order_acquire,
						    std::memory_order_relaxed)) {
						errno = saved_errno;
						return true;
					}
					continue;
				}
				if (state.compare_exchange_strong(
					    cur, detail::SHM_MUTEX_TAINTED,
					    std::memory_order_acq_rel,
					    std::memory_order_relaxed)) {
					try {
						SPDLOG_ERROR(
							"SHM robust lock (guard '{}') owner died; latching tainted state, future lockers fail with EBUSY",
							label ? label :
								"unlabeled");
					} catch (...) {
					}
				}
				errno = EBUSY;
				return false;
			}

			// Owner is alive (e.g. preempted); sleep briefly before
			// re-polling so oversubscribed hosts do not burn CPU.
			timespec ts{ 0, 100000 }; // 100 us
			nanosleep(&ts, nullptr);
		}
	}

    public:
	constexpr robust_shm_mutex() noexcept = default;
	~robust_shm_mutex() = default;
	robust_shm_mutex(const robust_shm_mutex &) = delete;
	robust_shm_mutex &operator=(const robust_shm_mutex &) = delete;

	bool lock(const char *label = nullptr) noexcept
	{
		uint64_t me = detail::current_shm_owner_token();
		uint64_t expected = 0;
		if (__builtin_expect(
			    state.compare_exchange_strong(
				    expected, me, std::memory_order_acquire,
				    std::memory_order_relaxed),
			    1))
			return true;
		return lock_slow(me, false, label);
	}

	bool lock_and_recover() noexcept
	{
		uint64_t me = detail::current_shm_owner_token();
		uint64_t expected = 0;
		if (__builtin_expect(
			    state.compare_exchange_strong(
				    expected, me, std::memory_order_acquire,
				    std::memory_order_relaxed),
			    1))
			return true;
		return lock_slow(me, true, nullptr);
	}

	void unlock() noexcept
	{
		state.store(0, std::memory_order_release);
	}
};

class robust_shm_lock_guard {
	robust_shm_mutex *mutex;

    public:
	explicit robust_shm_lock_guard(robust_shm_mutex &m,
				       const char *label = nullptr) noexcept
		: mutex(m.lock(label) ? &m : nullptr)
	{
	}
	~robust_shm_lock_guard()
	{
		if (mutex)
			mutex->unlock();
	}
	bool owns_lock() const noexcept { return mutex != nullptr; }
	robust_shm_lock_guard(const robust_shm_lock_guard &) = delete;
	robust_shm_lock_guard &operator=(const robust_shm_lock_guard &) = delete;
};

} // namespace bpftime

#endif // ROBUST_SHM_MUTEX_HPP
