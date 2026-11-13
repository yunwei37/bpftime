// DIAGNOSTIC ONLY (branch diag-echild, never merge): trace SIGCHLD delivery,
// fork points and wait4 results to locate the ECHILD race behind PR #736.
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>

namespace
{
int diag_fd = STDERR_FILENO;

void diag_puts(const char *s)
{
	while (s && *s) {
		ssize_t r = write(diag_fd, s, 1);
		(void)r;
		s++;
	}
}
void diag_int(long long v)
{
	char buf[24];
	int i = 0;
	if (v < 0) {
		(void)!write(diag_fd, "-", 1);
		v = -v;
	}
	if (v == 0)
		buf[i++] = '0';
	while (v > 0) {
		buf[i++] = char('0' + v % 10);
		v /= 10;
	}
	while (i > 0)
		(void)!write(diag_fd, &buf[--i], 1);
}
void diag_line(const char *tag, long long a, long long b, long long c)
{
	diag_puts("ECHILD_DIAG ");
	diag_puts(tag);
	diag_puts(" pid=");
	diag_int((long long)getpid());
	diag_puts(" tid=");
	diag_int((long long)syscall(SYS_gettid));
	diag_puts(" a=");
	diag_int(a);
	diag_puts(" b=");
	diag_int(b);
	diag_puts(" c=");
	diag_int(c);
	diag_puts("\n");
}

struct sigaction old_action;

void diag_sigchld(int sig, siginfo_t *info, void *ctx)
{
	(void)sig;
	(void)ctx;
	diag_line("SIGCHLD", info ? (long long)info->si_pid : -1,
		  info ? (long long)info->si_code : -99,
		  info ? (long long)info->si_status : -99);
	auto dfl = reinterpret_cast<void *>(SIG_DFL);
	auto ign = reinterpret_cast<void *>(SIG_IGN);
	if (old_action.sa_flags & SA_SIGINFO) {
		auto h = reinterpret_cast<void *>(old_action.sa_sigaction);
		if (h && h != dfl && h != ign)
			old_action.sa_sigaction(sig, info, ctx);
	} else {
		auto h = reinterpret_cast<void *>(old_action.sa_handler);
		if (h && h != dfl && h != ign)
			old_action.sa_handler(sig);
	}
}

void atfork_prepare() { diag_line("ATFORK_PREPARE", 0, 0, 0); }
void atfork_parent() { diag_line("ATFORK_PARENT", 0, 0, 0); }
void atfork_child() { diag_line("ATFORK_CHILD", 0, 0, 0); }

struct diag_init_t {
	diag_init_t()
	{
		struct sigaction cur {};
		sigaction(SIGCHLD, nullptr, &cur);
		diag_line("INIT_SIGCHLD_STATE",
			  (long long)(intptr_t)cur.sa_handler,
			  (long long)cur.sa_flags, (long long)cur.sa_mask.__val[0]);
		struct sigaction na {};
		na.sa_sigaction = diag_sigchld;
		sigemptyset(&na.sa_mask);
		na.sa_flags = SA_SIGINFO | SA_RESTART;
		if (sigaction(SIGCHLD, &na, &old_action) != 0)
			diag_line("INIT_SIGACTION_FAIL", (long long)errno, 0, 0);
		pthread_atfork(atfork_prepare, atfork_parent, atfork_child);
		diag_line("INIT_DONE", (long long)getppid(), 0, 0);
		int maps = open("/proc/self/maps", O_RDONLY);
		if (maps >= 0) {
			char mb[4096];
			ssize_t n;
			while ((n = read(maps, mb, sizeof(mb))) > 0)
				(void)!write(diag_fd, mb, (size_t)n);
			close(maps);
		}
	}
} diag_init_instance;
} // namespace

extern "C" void echild_diag_wait4(long long pid, long long statusp,
				 long long options, long long rusage,
				 long long ret0, long long ret1)
{
	diag_line("WAIT4_ENTER", pid, options, statusp);
	diag_line("WAIT4_RETS", ret0, ret1, rusage);
}
extern "C" void echild_diag_note(const char *tag, long long a, long long b,
				 long long c)
{
	diag_line(tag, a, b, c);
}
