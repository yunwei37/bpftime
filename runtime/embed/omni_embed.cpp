// SPDX-License-Identifier: Apache-2.0
//
// Omni Profiler no-frida in-process embed. The LD_PRELOAD alloc shim calls the
// C ABI below; instead of frida rewriting the trampoline entry points, the
// attached eBPF program is executed synchronously in the normal call context
// with a synthesized kernel-style pt_regs. No GumInterceptor / boost::fiber
// path is ever created, which removes the long-run fiber SIGSEGV surface.
#include "omni_bpftime_embed.h"

#include "attach_private_data.hpp"
#include "base_attach_impl.hpp"
#include "bpf_attach_ctx.hpp"
#include "bpftime_config.hpp"
#include "bpftime_shm.hpp"
#include "spdlog/cfg/env.h"
#include "spdlog/spdlog.h"

#include <array>
#include <cstring>
#include <dlfcn.h>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

// Attach type integers shared with the uprobe perf-event handlers. Defined
// locally so this target does not depend on the frida attach headers.
#define OMNI_ATTACH_UPROBE 6
#define OMNI_ATTACH_URETPROBE 7
#define OMNI_ATTACH_UPROBE_OVERRIDE 1008
#define OMNI_ATTACH_UREPLACE 1009
#define OMNI_MAX_TRAMPOLINES 8

#if defined(__x86_64__) || defined(_M_X64)
struct omni_pt_regs {
	uint64_t r15, r14, r13, r12, bp, bx, r11, r10, r9, r8, ax, cx, dx, si,
		di, orig_ax, ip, cs, flags, sp, ss;
};
#elif defined(__aarch64__) || defined(_M_ARM64)
struct omni_pt_regs {
	uint64_t regs[31];
	uint64_t sp;
	uint64_t pc;
	uint64_t pstate;
};
#else
#error "omni embed: unsupported architecture"
#endif

using namespace bpftime;
using namespace bpftime::attach;

namespace
{
struct omni_private_data : attach_private_data {
	std::string raw;
	bool has_colon = false;
	std::string module;
	uintptr_t address = 0;
	uintptr_t offset = 0;
	int initialize_from_string(const std::string_view &sv) override
	{
		raw = std::string(sv);
		auto pos = raw.find_last_of(':');
		try {
			if (pos == std::string::npos) {
				address = std::stoull(raw);
			} else {
				has_colon = true;
				module = raw.substr(0, pos);
				auto slash = module.find_last_of('/');
				if (slash != std::string::npos)
					module = module.substr(slash + 1);
				offset = std::stoull(raw.substr(pos + 1));
			}
		} catch (...) {
			return -EINVAL;
		}
		return 0;
	}
	std::string to_string() const override { return raw; }
};

struct slot {
	bool used = false;
	ebpf_run_callback cb;
};

// One impl owns all omni uprobe attaches; callbacks are indexed by the stable
// trampoline id so the shim can trigger them without any symbol lookup.
class omni_attach_impl final : public base_attach_impl
{
      public:
	std::array<slot, OMNI_MAX_TRAMPOLINES> slots;
	std::array<std::pair<std::string, uintptr_t>, OMNI_MAX_TRAMPOLINES>
		symbols{};

	int create_attach_with_ebpf_callback(
		ebpf_run_callback &&cb, const attach_private_data &pd,
		int /*attach_type*/) override
	{
		const auto &d = dynamic_cast<const omni_private_data &>(pd);
		int idx = resolve_slot(d);
		int id = allocate_id();
		if (idx < 0) {
			SPDLOG_DEBUG(
				"omni embed: unattached external uprobe `{}` ignored",
				d.raw);
			return id; // do not fail init for unrelated uprobes
		}
		slots[idx].used = true;
		slots[idx].cb = std::move(cb);
		SPDLOG_INFO("omni embed: bound trampoline {} to `{}`", idx + 1,
			    d.raw);
		return id;
	}
	int detach_by_id(int id) override { return id >= 0 ? 0 : -EINVAL; }

	int run(int trampoline, const omni_embed_ctx &e)
	{
		if (trampoline < 1 || trampoline > OMNI_MAX_TRAMPOLINES)
			return -EINVAL;
		auto &s = slots[trampoline - 1];
		if (!s.used || !s.cb)
			return -ENOENT;
		omni_pt_regs regs;
		std::memset(&regs, 0, sizeof(regs));
#if defined(__x86_64__) || defined(_M_X64)
		regs.di = e.arg1;
		regs.si = e.arg2;
		regs.dx = e.arg3;
		regs.cx = e.arg4;
		regs.bp = e.frame_bp;
		regs.ip = e.probe_ip;
		regs.sp = e.frame_bp;
#else
		regs.regs[0] = e.arg1;
		regs.regs[1] = e.arg2;
		regs.regs[2] = e.arg3;
		regs.regs[3] = e.arg4;
		regs.regs[29] = e.frame_bp;
		regs.regs[30] = e.caller_ip;
		regs.pc = e.probe_ip;
		regs.sp = e.frame_bp;
#endif
		uint64_t ret = 0;
		return s.cb(&regs, sizeof(regs), &ret);
	}

      private:
	int resolve_slot(const omni_private_data &d)
	{
		for (int i = 0; i < OMNI_MAX_TRAMPOLINES; ++i) {
			const auto &[mod, off] = symbols[i];
			if (mod.empty())
				continue;
			if (d.has_colon) {
				if (d.module == mod && d.offset == off)
					return i;
			} else if (d.address && d.address == symbols_addr(i)) {
				return i;
			}
		}
		return -1;
	}
	uintptr_t symbols_addr(int i) const
	{
		Dl_info info;
		void *p = dlsym(RTLD_DEFAULT, symbol_name(i));
		if (p && dladdr(p, &info))
			return reinterpret_cast<uintptr_t>(p);
		return 0;
	}
	static const char *symbol_name(int i)
	{
		static const char *names[OMNI_MAX_TRAMPOLINES] = {
			"omni_profiler_sample_alloc",
			"omni_profiler_sample_free",
			"omni_profiler_pid_sync",
		};
		return i < 3 ? names[i] : nullptr;
	}
};

std::once_flag g_once;
std::optional<bpf_attach_ctx> g_ctx;
omni_attach_impl *g_impl = nullptr;
int g_open_error = 0;

void build_symbols(omni_attach_impl &impl)
{
	static const char *names[3] = { "omni_profiler_sample_alloc",
					"omni_profiler_sample_free",
					"omni_profiler_pid_sync" };
	for (int i = 0; i < 3; ++i) {
		void *p = dlsym(RTLD_DEFAULT, names[i]);
		Dl_info info;
		if (p && dladdr(p, &info) && info.dli_fbase) {
			auto base = reinterpret_cast<uintptr_t>(info.dli_fbase);
			auto addr = reinterpret_cast<uintptr_t>(p);
			const char *fn = info.dli_fname ? info.dli_fname : "";
			auto slash = std::string(fn).find_last_of('/');
			std::string base_name =
				slash == std::string::npos ? fn :
							     std::string(fn)
								     .substr(slash + 1);
			impl.symbols[i] = { base_name, addr - base };
		}
	}
}
} // namespace

extern "C" int omni_embed_abi_version(void)
{
	return OMNI_EMBED_ABI_VERSION;
}

extern "C" int omni_embed_open(const char * /*shm_name*/,
			       const char * /*config_path*/)
{
	std::call_once(g_once, [] {
		try {
			spdlog::cfg::load_env_levels();
			bpftime_initialize_global_shm(
				shm_open_type::SHM_CREATE_OR_OPEN);
			g_ctx.emplace();
			auto impl = std::make_unique<omni_attach_impl>();
			g_impl = impl.get();
			build_symbols(*g_impl);
			g_ctx->register_attach_impl(
				{ OMNI_ATTACH_UPROBE, OMNI_ATTACH_URETPROBE,
				  OMNI_ATTACH_UPROBE_OVERRIDE,
				  OMNI_ATTACH_UREPLACE },
				std::move(impl),
				[](const std::string_view sv, int &err)
					-> std::unique_ptr<attach_private_data> {
					auto pd =
						std::make_unique<omni_private_data>();
					err = pd->initialize_from_string(sv);
					return err == 0 ?
						       std::unique_ptr<
							       attach_private_data>(
							       std::move(pd)) :
						       nullptr;
				});
			g_open_error = g_ctx->init_attach_ctx_from_handlers(
				bpftime_get_runtime_config());
		} catch (const std::exception &ex) {
			SPDLOG_ERROR("omni embed init failed: {}", ex.what());
			g_open_error = -1;
		}
	});
	return g_open_error;
}

extern "C" int omni_embed_trigger(const omni_embed_ctx *ctx)
{
	if (!ctx || !g_impl)
		return -ENXIO;
	try {
		return g_impl->run(ctx->trampoline, *ctx);
	} catch (const std::exception &ex) {
		SPDLOG_DEBUG("omni embed trigger failed: {}", ex.what());
		return -EFAULT;
	}
}

extern "C" void omni_embed_close(void)
{
	// Shared memory and programs outlive the shim and are torn down with
	// the process group; nothing to release per process here.
}
