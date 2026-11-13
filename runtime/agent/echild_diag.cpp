// DIAGNOSTIC ONLY (branch diag-echild, never merge): scan the user stack for
// return addresses to find the C caller of libc wait4 across the
// omit-frame-pointer glibc leaf.
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>

namespace
{
int diag_fd = STDERR_FILENO;

char *emit_int(char *p, char *end, long long v)
{
	char buf[24]; int i = 0;
	if (v < 0) { if (p < end - 1) *p++ = '-'; v = -v; }
	if (v == 0) buf[i++] = '0';
	while (v > 0) { buf[i++] = char('0' + v % 10); v /= 10; }
	while (i > 0 && p < end - 1) *p++ = buf[--i];
	return p;
}
void emit_str(char *&p, char *end, const char *s)
{ while (s && *s && p < end - 1) *p++ = *s++; }
void diag_line(const char *tag, long long a, long long b, long long c)
{
	char buf[256]; char *p = buf; char *end = buf + sizeof(buf);
	p = emit_int(p, end, (long long)getpid());
	if (p < end - 1) *p++ = ' ';
	emit_str(p, end, tag);
	if (p < end - 1) *p++ = ' ';
	p = emit_int(p, end, a); if (p < end - 1) *p++ = ' ';
	p = emit_int(p, end, b); if (p < end - 1) *p++ = ' ';
	p = emit_int(p, end, c); if (p < end - 1) *p++ = '\n';
	(void)!write(diag_fd, buf, (size_t)(p - buf));
}

void scan_stack(const char *tag, long long pid_arg)
{
	diag_line(tag, pid_arg, 0, 0);
	volatile uintptr_t sp = (uintptr_t)__builtin_frame_address(0);
	// scan a 4KB window upward from current frame
	const int n = 512;
	for (int i = 0; i < n; ++i) {
		uintptr_t val = *(volatile uintptr_t *)(sp + (uintptr_t)i * 8);
		Dl_info info {};
		if (dladdr((void *)val, &info) && info.dli_sname &&
		    (strstr(info.dli_fname ? info.dli_fname : "", ".so") ||
		     strstr(info.dli_fname ? info.dli_fname : "", "timeout") ||
		     strstr(info.dli_fname ? info.dli_fname : "", "dd"))) {
			char buf[320]; char *p = buf; char *end = buf + sizeof(buf);
			p = emit_int(p, end, (long long)getpid());
			if (p < end - 1) *p++ = ' ';
			emit_str(p, end, "STACK");
			if (p < end - 1) *p++ = ' ';
			p = emit_int(p, end, i); if (p < end - 1) *p++ = ' ';
			emit_str(p, end, info.dli_sname);
			if (p < end - 1) *p++ = '+';
			p = emit_int(p, end, (long long)((char *)val - (char *)info.dli_saddr));
			if (info.dli_fname) { if (p < end - 1) *p++ = ' '; emit_str(p, end, info.dli_fname); }
			if (p < end - 1) *p++ = '\n';
			(void)!write(diag_fd, buf, (size_t)(p - buf));
		}
	}
}

struct sigaction old_action;
void diag_sigchld(int sig, siginfo_t *info, void *ctx)
{
	(void)sig; (void)ctx;
	diag_line("SIGCHLD", info ? (long long)info->si_pid : -1, -99, -99);
	auto dfl = reinterpret_cast<void *>(SIG_DFL);
	auto ign = reinterpret_cast<void *>(SIG_IGN);
	if (old_action.sa_flags & SA_SIGINFO) {
		auto h = reinterpret_cast<void *>(old_action.sa_sigaction);
		if (h && h != dfl && h != ign) old_action.sa_sigaction(sig, info, ctx);
	} else {
		auto h = reinterpret_cast<void *>(old_action.sa_handler);
		if (h && h != dfl && h != ign) old_action.sa_handler(sig);
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
		diag_line("INIT_SIGCHLD", (long long)(intptr_t)cur.sa_handler,
			  (long long)cur.sa_flags, 0);
		struct sigaction na {};
		na.sa_sigaction = diag_sigchld;
		sigemptyset(&na.sa_mask);
		na.sa_flags = SA_SIGINFO | SA_RESTART;
		if (sigaction(SIGCHLD, &na, &old_action) != 0)
			diag_line("INIT_SIGACTION_FAIL", (long long)errno, 0, 0);
		pthread_atfork(atfork_prepare, atfork_parent, atfork_child);
		diag_line("INIT_DONE", (long long)getppid(), 0, 0);
	}
} diag_init_instance;
} // namespace

extern "C" void echild_diag_note(const char *tag, long long a, long long b,
				 long long c) { diag_line(tag, a, b, c); }

extern "C" void echild_diag_wait4(long long pid, long long statusp,
				 long long options, long long rusage,
				 long long f0, long long f1)
{
	(void)statusp; (void)options; (void)rusage; (void)f0; (void)f1;
	diag_line("WAIT4", pid, 0, 0);
	// Real child pids in CI are small; garbage pointer-as-pid values are huge.
	if (pid > 1000000)
		scan_stack("GARBAGE_SCAN", pid);
}
