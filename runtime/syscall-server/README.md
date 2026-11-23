# syscall_server.so

Use as a LD_PRELOAD to intercept bpf syscalls and mock them in userspace, or trace them and make kernel eBPF run with userspace eBPF.

## Run with userspace eBPF

The default behavior is to run with userspace eBPF. Using userspace eBPF means using userspace eBPF maps in shared memory, using userspace eBPF verifier and userspace eBPF runtime.

server

```sh
LD_PRELOAD=build/runtime/syscall-server/libbpftime-syscall-server.so example/malloc/malloc
```

client

```sh
LD_PRELOAD=build/runtime/agent/libbpftime-agent.so example/malloc/victim
```

## run with kernel

Set the environment variable `BPFTIME_RUN_WITH_KERNEL` to `true` to make the kernel eBPF run with userspace eBPF. This means using kernel eBPF maps instead of userspace eBPF maps, and using kernel eBPF verifier instead of userspace eBPF verifier.

```sh
BPFTIME_RUN_WITH_KERNEL=true
```

example start tracing:

```sh
SPDLOG_LEVEL=Debug BPFTIME_RUN_WITH_KERNEL=true LD_PRELOAD=build/runtime/syscall-server/libbpftime-syscall-server.so example/malloc/malloc
```

example run target program:

```sh
SPDLOG_LEVEL=Debug LD_PRELOAD=build/runtime/agent/libbpftime-agent.so example/malloc/victim
```

## Rootless defaults

A plain preload works without any extra environment variable:

```sh
LD_PRELOAD=build/runtime/syscall-server/libbpftime-syscall-server.so your_program
```

In this mode the library:

- installs the seccomp `USER_NOTIF` filter from its loader constructor, so
  runtimes that bypass libc (for example Go programs issuing raw `syscall`
  instructions) are intercepted the same way as ordinary C/C++ programs;
- emulates `BPF_RAW_TRACEPOINT_OPEN` for the `sys_enter` tracepoint with a
  synthetic handle, because an unprivileged process cannot open the real
  kernel-entry tracepoint. The matching `pt_regs` stack offset defaults to
  `4096`; set `BPFTIME_SYSTEM_ANALYSIS_PTREGS_OFFSET` to override it for an
  environment that needs a different value.

If the kernel rejects the seccomp filter (unsupported kernel or missing
privileges) the library fails open and the program keeps running with
ordinary syscalls.

Logging defaults to a silent sink that writes nothing to the host's stdio
and does no file I/O, so worker-thread logging cannot deadlock on a stdio
lock while a syscall is intercepted. Set `BPFTIME_LOG_OUTPUT=console` (or a
file path) to enable diagnostics.

Set `BPFTIME_RUN_WITH_KERNEL` to disable both defaults and route the
intercepted syscalls to the real kernel, as described above.

## skip verification for some programs

```sh
BPFTIME_NOT_LOAD_PATTERN=.*
```