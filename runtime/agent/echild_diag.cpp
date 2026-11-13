// DIAGNOSTIC ONLY (diag-echild, never merge): capture the actual SIGSEGV
// backtrace in the forked child via an async-signal-safe frame walk, plus the
// wait4 identity/execve evidence from v8.
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <ucontext.h>

namespace
{
int diag_fd = STDERR_FILENO;
static char g_alt_stack[65536] __attribute__((aligned(16)));
long g_execve_count = 0;
long g_syscall_count = 0;

char *emit_int(char *p, char *end, long long v)
{
	char buf[24];
	int i = 0;
	if (v < 0) {
		if (p < end - 1)
			*p++ = '-';
		v = -v;
	}
	if (v == 0)
		buf[i++] = '0';
	while (v > 0) {
		buf[i++] = char('0' + v % 10);
		v /= 10;
	}
	while (i > 0 && p < end - 1)
		*p++ = buf[--i];
	return p;
}
void emit_str(char *&p, char *end, const char *s)
{
	while (s && *s && p < end - 1)
		*p++ = *s++;
}
void diag_line(const char *tag, long long a, long long b, long long c)
{
	char buf[256];
	char *p = buf;
	char *end = buf + sizeof(buf);
	p = emit_int(p, end, (long long)getpid());
	if (p < end - 1) *p++ = ' ';
	emit_str(p, end, tag);
	if (p < end - 1) *p++ = ' ';
	p = emit_int(p, end, a);
	if (p < end - 1) *p++ = ' ';
	p = emit_int(p, end, b);
	if (p < end - 1) *p++ = ' ';
	p = emit_int(p, end, c);
	if (p < end - 1) *p++ = '\n';
	(void)!write(diag_fd, buf, (size_t)(p - buf));
}
void diag_identity(const char *tag, long long pid_arg)
{
	char buf[256];
	char *p = buf;
	char *end = buf + sizeof(buf);
	p = emit_int(p, end, (long long)getpid());
	if (p < end - 1) *p++ = ' ';
	emit_str(p, end, tag);
	if (p < end - 1) *p++ = ' ';
	p = emit_int(p, end, pid_arg);
	if (p < end - 1) *p++ = ' ';
	p = emit_int(p, end, (long long)getppid());
	if (p < end - 1) *p++ = ' ';
	p = emit_int(p, end, (long long)syscall(SYS_gettid));
	if (p < end - 1) *p++ = ' ';
	p = emit_int(p, end, g_execve_count);
	if (p < end - 1) *p++ = ' ';
	p = emit_int(p, end, g_syscall_count);
	if (p < end - 1) *p++ = '\n';
	(void)!write(diag_fd, buf, (size_t)(p - buf));
}

struct Frame {
	uintptr_t rbp;
	uintptr_t ret;
};

void segv_backtrace(int sig, siginfo_t *info, void *ctx)
{
	(void)ctx;
	(void)!write(diag_fd, "SEGVHIT\n", 9);
	diag_line("SEGV", sig, (long long)(intptr_t)(info ? info->si_addr : 0),
		  (long long)getppid());
	auto *uc = (ucontext_t *)ctx;
	uintptr_t fault_rip = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
	uintptr_t fault_rbp = (uintptr_t)uc->uc_mcontext.gregs[REG_RBP];
	uintptr_t fault_rsp = (uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
	diag_line("SEGVREG", (long long)fault_rip, (long long)fault_rbp,
		  (long long)fault_rsp);
	// First entry: the exact faulting instruction resolved via dladdr.
	{
		char buf[320]; char *w = buf; char *e = buf + sizeof(buf);
		w = emit_int(w, e, (long long)getpid()); if (w < e-1) *w++ = ' ';
		emit_str(w, e, "SEGVRIP"); if (w < e-1) *w++ = ' ';
		Dl_info di {};
		if (dladdr((void *)fault_rip, &di) && di.dli_sname) {
			emit_str(w, e, di.dli_sname); if (w < e-1) *w++ = '+';
			w = emit_int(w, e, (long long)((char*)fault_rip-(char*)di.dli_saddr));
			if (di.dli_fname) { if (w < e-1) *w++ = ' '; emit_str(w, e, di.dli_fname); }
		} else emit_str(w, e, "UNKNOWN");
		if (w < e-1) *w++ = '\n';
		(void)!write(diag_fd, buf, (size_t)(w - buf));
	}
	// Dump the mapping containing RIP for ownership without dladdr.
	{
		int mf = open("/proc/self/maps", O_RDONLY);
		if (mf >= 0) {
			char mb[512];
			ssize_t n;
			while ((n = read(mf, mb, sizeof(mb) - 1)) > 0) {
				mb[n] = 0;
				unsigned long a = 0, b = 0;
				if (sscanf(mb, "%lx-%lx", &a, &b) == 2 &&
				    a <= fault_rip && fault_rip < b) {
					(void)!write(diag_fd, "RIPMAP ", 7);
					(void)!write(diag_fd, mb, (size_t)n);
					if (mb[n-1] != '\n') (void)!write(diag_fd, "\n", 1);
				}
			}
			close(mf);
		}
	}
	Frame *f = (Frame *)fault_rbp;
	for (int depth = 0; depth < 14 && f; ++depth) {
		uintptr_t ret = f->ret;
		char buf[320];
		char *p = buf;
		char *end = buf + sizeof(buf);
		p = emit_int(p, end, (long long)getpid());
		if (p < end - 1) *p++ = ' ';
		emit_str(p, end, "SEGVBT");
		if (p < end - 1) *p++ = ' ';
		p = emit_int(p, end, depth);
		if (p < end - 1) *p++ = ' ';
		Dl_info di {};
		if (dladdr((void *)ret, &di) && di.dli_sname) {
			emit_str(p, end, di.dli_sname);
			if (p < end - 1) *p++ = '+';
			p = emit_int(p, end,
				     (long long)((char *)ret -
							 (char *)di.dli_saddr));
			if (di.dli_fname) {
				if (p < end - 1) *p++ = ' ';
				emit_str(p, end, di.dli_fname);
			}
		} else {
			emit_str(p, end, "UNKNOWN");
		}
		if (p < end - 1) *p++ = '\n';
		(void)!write(diag_fd, buf, (size_t)(p - buf));
		uintptr_t next = f->rbp;
		if (next == 0 || next <= (uintptr_t)f || (next & 7) != 0)
			break;
		f = (Frame *)next;
	}
	// restore default and re-raise so the real crash/exit status is preserved
	struct sigaction dfl {};
	dfl.sa_handler = SIG_DFL;
	sigemptyset(&dfl.sa_mask);
	sigaction(sig, &dfl, nullptr);
	pthread_kill(pthread_self(), sig);
}

struct sigaction old_sigchld;
void diag_sigchld(int sig, siginfo_t *info, void *ctx)
{
	(void)sig;
	(void)ctx;
	diag_line("SIGCHLD", info ? (long long)info->si_pid : -1, -99, -99);
	auto dfl = reinterpret_cast<void *>(SIG_DFL);
	auto ign = reinterpret_cast<void *>(SIG_IGN);
	if (old_sigchld.sa_flags & SA_SIGINFO) {
		auto h = reinterpret_cast<void *>(old_sigchld.sa_sigaction);
		if (h && h != dfl && h != ign)
			old_sigchld.sa_sigaction(sig, info, ctx);
	} else {
		auto h = reinterpret_cast<void *>(old_sigchld.sa_handler);
		if (h && h != dfl && h != ign)
			old_sigchld.sa_handler(sig);
	}
}
void atfork_prepare() { diag_line("ATFORK_PREPARE", 0, 0, 0); }
void atfork_parent() { diag_line("ATFORK_PARENT", 0, 0, 0); }
void atfork_child() { diag_line("ATFORK_CHILD", 0, 0, 0); }

struct diag_init_t {
	diag_init_t()
	{
		stack_t ss {};
		ss.ss_sp = g_alt_stack;
		ss.ss_size = sizeof(g_alt_stack);
		ss.ss_flags = 0;
		sigaltstack(&ss, nullptr);
		struct sigaction sa {};
		sa.sa_sigaction = segv_backtrace;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;
		sigaction(SIGSEGV, &sa, nullptr);
		sigaction(SIGBUS, &sa, nullptr);

		struct sigaction cur {};
		sigaction(SIGCHLD, nullptr, &cur);
		diag_line("INIT_SIGCHLD", (long long)(intptr_t)cur.sa_handler,
			  (long long)cur.sa_flags, 0);
		struct sigaction na {};
		na.sa_sigaction = diag_sigchld;
		sigemptyset(&na.sa_mask);
		na.sa_flags = SA_SIGINFO | SA_RESTART;
		if (sigaction(SIGCHLD, &na, &old_sigchld) != 0)
			diag_line("INIT_SIGACTION_FAIL", (long long)errno, 0, 0);
		pthread_atfork(atfork_prepare, atfork_parent, atfork_child);
		diag_line("INIT_DONE", (long long)getppid(), 0, 0);
	}
} diag_init_instance;
} // namespace

extern "C" void echild_diag_syscall_enter(long long nr)
{
	++g_syscall_count;
	if (nr == 59 || nr == 322)
		++g_execve_count;
}
extern "C" void echild_diag_note(const char *tag, long long a, long long b,
				 long long c)
{
	diag_line(tag, a, b, c);
}
extern "C" void echild_diag_wait4(long long pid, long long s, long long o,
				 long long r, long long f0, long long f1)
{
	(void)s;
	(void)o;
	(void)r;
	(void)f0;
	(void)f1;
	diag_identity("W4ID", pid);
}
