/* SPDX-License-Identifier: Apache-2.0
 *
 * Stable C ABI between the LD_PRELOAD alloc shim and the no-frida bpftime
 * embed library. The shim resolves these symbols with dlsym() at runtime when
 * OMNI_PROFILER_EMBED_BPFTIME is compiled in. The bpftime embed library
 * implements them; the shim never links against the C++ runtime directly.
 *
 * Versioning: OMNI_EMBED_ABI_VERSION is bumped only on breaking changes to the
 * symbols or struct layout below.
 */
#ifndef OMNI_BPFTIME_EMBED_H
#define OMNI_BPFTIME_EMBED_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OMNI_EMBED_ABI_VERSION 1

/* Stable identifiers for the three shim trampolines. Values are part of the
 * ABI and must not be renumbered. */
enum omni_embed_trampoline {
  OMNI_EMBED_TRAMP_ALLOC = 1,
  OMNI_EMBED_TRAMP_FREE = 2,
  OMNI_EMBED_TRAMP_PID_SYNC = 3,
};

/* Architecture-neutral event descriptor captured by the shim at a trampoline.
 * The embed library maps it onto a kernel-style pt_regs before running the
 * attached eBPF program. */
struct omni_embed_ctx {
  int trampoline;
  uintptr_t arg1; /* alloc: ptr;  free: ptr;  pid_sync: reason */
  uintptr_t arg2; /* alloc: size; others: 0 */
  uintptr_t arg3; /* alloc: kind; others: 0 */
  uintptr_t arg4; /* alloc: &sample_bytes cell; others: 0 */
  uintptr_t frame_bp; /* frame pointer at the trampoline, for stack unwind */
  uintptr_t probe_ip; /* address of the trampoline symbol */
  uintptr_t caller_ip; /* return address into the shim caller chain */
};

/* Returns the ABI version implemented by the loaded embed library. The shim
 * treats a missing/incompatible symbol as "embedding unavailable". */
int omni_embed_abi_version(void);

/* One-time, idempotent initialization. shm_name names the bpftime global
 * shared memory (matches BPFTIME_GLOBAL_SHM_NAME); config_path is reserved for
 * an optional handler/config file and may be NULL. Returns 0 on success and a
 * non-zero errno-style code when embedding cannot be used. */
int omni_embed_open(const char *shm_name, const char *config_path);

/* Synchronously execute the eBPF program attached to the given trampoline.
 * Returns 0 when the program ran; any non-zero value is non-fatal and the shim
 * continues without the event. Must be safe to call from the allocator hot
 * path and re-entrancy guarded by the shim. */
int omni_embed_trigger(const struct omni_embed_ctx *ctx);

/* Release embed resources. Optional at process exit; safe to call once. */
void omni_embed_close(void);

#ifdef __cplusplus
}
#endif

#endif /* OMNI_BPFTIME_EMBED_H */
