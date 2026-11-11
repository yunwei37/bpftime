// SPDX-License-Identifier: Apache-2.0
//
// Single-process functional test for the no-frida embed path. It builds the
// same shm handler graph the collector would publish (one uprobe perf event on
// an exported trampoline + the echo BPF program), dlopens libomni-bpftime-embed,
// and calls omni_embed_trigger. Success means the embed bound the trampoline,
// synthesized pt_regs correctly, and executed the BPF program (R0 echoes arg1).
// No Ray, PID admission, ringbuf or collector is involved.
#include "omni_bpftime_embed.h"

#include "bpf_attach_ctx.hpp"
#include "bpftime_config.hpp"
#include "bpftime_object.hpp"
#include "bpftime_shm.hpp"
#include "handler/handler_manager.hpp"
#include "handler/link_handler.hpp"
#include "handler/perf_event_handler.hpp"
#include "spdlog/spdlog.h"

#include <boost/interprocess/creation_tags.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <dlfcn.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

using namespace boost::interprocess;
using namespace bpftime;

// Exported, non-inlined anchor symbols. The embed resolves these with dlsym,
// exactly as it resolves the real alloc shim trampolines.
extern "C" __attribute__((noinline, visibility("default"))) void
omni_profiler_sample_alloc(void *ptr, size_t size, uint32_t kind,
			   uint64_t *cell)
{
	asm volatile("" ::"r"(ptr), "r"(size), "r"(kind), "r"(cell)
		      : "memory");
}
extern "C" __attribute__((noinline, visibility("default"))) void
omni_profiler_sample_free(void *ptr)
{
	asm volatile("" ::"r"(ptr) : "memory");
}
extern "C" __attribute__((noinline, visibility("default"))) void
omni_profiler_pid_sync(uint32_t reason)
{
	asm volatile("" ::"r"(reason) : "memory");
}

static const char *SHM = "omni_embed_selftest_shm";

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "usage: %s <echo.bpf.o> <libomni-bpftime-embed.so>\n",
			argv[0]);
		return 2;
	}
	const char *bpf_obj = argv[1];
	const char *embed_so = argv[2];
	setenv("BPFTIME_GLOBAL_SHM_NAME", SHM, 1);
	shared_memory_object::remove(SHM);

	// 1. Create the shm and handler manager (collector-side equivalent).
	managed_shared_memory segment(create_only, SHM, 1 << 22);
	auto *manager = segment.construct<handler_manager>(
		DEFAULT_GLOBAL_HANDLER_NAME)(segment, DEFAULT_MAX_FD_COUNT);

	runtime_config config;
	config.set_vm_name("llvm");
	bpftime_object *obj = bpftime_object_open(bpf_obj, config);
	if (!obj) {
		fprintf(stderr, "FAIL: bpftime_object_open returned null\n");
		return 1;
	}
	bpftime_prog *prog = bpftime_object__next_program(obj, nullptr);
	if (!prog) {
		fprintf(stderr, "FAIL: no program in bpf object\n");
		return 1;
	}

	// Program handler at slot 0; one uprobe perf event + link per trampoline.
	manager->set_handler(
		0,
		bpf_prog_handler(segment, prog->get_insns().data(),
				 prog->get_insns().size(), prog->prog_name(),
				 (int)bpf_prog_type::BPF_PROG_TYPE_KPROBE),
		segment);

	struct anchor {
		const char *name;
		void *addr;
	};
	const anchor anchors[3] = {
		{ "omni_profiler_sample_alloc",
		  reinterpret_cast<void *>(&omni_profiler_sample_alloc) },
		{ "omni_profiler_sample_free",
		  reinterpret_cast<void *>(&omni_profiler_sample_free) },
		{ "omni_profiler_pid_sync",
		  reinterpret_cast<void *>(&omni_profiler_pid_sync) },
	};
	Dl_info info;
	dladdr(anchors[0].addr, &info);
	std::string mod = info.dli_fname ? info.dli_fname : "";
	auto slash = mod.find_last_of('/');
	if (slash != std::string::npos)
		mod = mod.substr(slash + 1);
	uintptr_t base = reinterpret_cast<uintptr_t>(info.dli_fbase);
	// Perf events at slots 4..6, each linked to program 0.
	for (int i = 0; i < 3; ++i) {
		uint64_t off =
			reinterpret_cast<uintptr_t>(anchors[i].addr) - base;
		int perf_fd = 4 + i;
		manager->set_handler(
			perf_fd,
			bpf_perf_event_handler(bpf_event_type::BPF_TYPE_UPROBE,
					       off, -1, mod.c_str(),
					       segment),
			segment);
		manager->set_handler_at_empty_slot(
			bpf_link_handler(0, perf_fd), segment);
		fprintf(stderr, "selftest: handler[%d] %s off=%#lx\n", i,
			anchors[i].name, (unsigned long)off);
	}

	// 2. dlopen and initialize the embed library against the same shm.
	void *h = dlopen(embed_so, RTLD_NOW | RTLD_LOCAL);
	if (!h) {
		fprintf(stderr, "FAIL: dlopen embed: %s\n", dlerror());
		return 1;
	}
	auto p_open = reinterpret_cast<int (*)(const char *, const char *)>(
		dlsym(h, "omni_embed_open"));
	auto p_trig =
		reinterpret_cast<int (*)(const struct omni_embed_ctx *)>(
			dlsym(h, "omni_embed_trigger"));
	auto p_ver = reinterpret_cast<int (*)(void)>(
		dlsym(h, "omni_embed_abi_version"));
	if (!p_open || !p_trig || !p_ver) {
		fprintf(stderr, "FAIL: missing embed symbols\n");
		return 1;
	}
	fprintf(stderr, "selftest: abi=%d (expect %d)\n", p_ver(),
		OMNI_EMBED_ABI_VERSION);
	int rc = p_open(SHM, nullptr);
	fprintf(stderr, "selftest: omni_embed_open rc=%d\n", rc);

	// 3. Trigger every trampoline with a distinct arg and verify BPF R0 echo.
	bool ok = (rc == 0);
	const int tramp[3] = { OMNI_EMBED_TRAMP_ALLOC, OMNI_EMBED_TRAMP_FREE,
			      OMNI_EMBED_TRAMP_PID_SYNC };
	for (int i = 0; i < 3; ++i) {
		uint64_t magic = 0x1000 + i;
		omni_embed_ctx ctx{};
		ctx.trampoline = tramp[i];
		ctx.arg1 = magic;
		int trc = p_trig(&ctx);
		uint64_t expect = magic & 0xffff;
		bool good = (trc == 0) && (ctx.result_out == expect);
		fprintf(stderr,
			"selftest: tramp=%d rc=%d result=%#llx expect=%#llx %s\n",
			tramp[i], trc,
			(unsigned long long)ctx.result_out,
			(unsigned long long)expect,
			good ? "ok" : "BAD");
		ok = ok && good;
	}

	manager->clear_all(segment);
	segment.destroy_ptr(manager);
	dlclose(h);
	shared_memory_object::remove(SHM);
	printf("%s: embed trigger executed BPF and echoed arg via R0\n",
	       ok ? "PASS" : "FAIL");
	return ok ? 0 : 1;
}
