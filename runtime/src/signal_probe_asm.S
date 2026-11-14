/* SPDX-License-Identifier: MIT
 * x86_64 protected copy with exact fault-instruction symbols.
 *
 * Input:  rdi=dst, rsi=src, rdx=n  (n > 0 guaranteed by the C++ caller)
 * Output: eax=1 copy succeeded; eax=0 a fault was recovered by the handler.
 *
 * Exactly two instruction addresses can fault on a host access:
 *   bpftime_pc_probe_load  (the source load)
 *   bpftime_pc_probe_store (the destination store)
 * The C++ handler compares the faulting RIP against these two global
 * symbols, which resolve through RIP-relative relocations and therefore stay
 * position-independent in the shared library. No control-flow instruction,
 * the success return, the recovery label or its return is recoverable, so a
 * signal delivered at any other PC is never treated as a copy fault. The
 * region stays a leaf: it contains no CALL.
 *
 * On a recoverable fault the signal handler redirects RIP to
 * bpftime_pc_probe_recovery, which returns 0 through the original return
 * address; the interrupted register state is otherwise untouched.
 */
	.text
	.globl	bpftime_pc_safe_copy_asm
	.type	bpftime_pc_safe_copy_asm, @function
bpftime_pc_safe_copy_asm:
	mov	$1, %eax		/* success marker; recovery overwrites it */
	.globl	bpftime_pc_probe_load
	.hidden	bpftime_pc_probe_load
	.type	bpftime_pc_probe_load, @function
bpftime_pc_probe_load:
	movzbl	(%rsi), %ecx		/* faulting source load (SEGV/BUS) */
	.globl	bpftime_pc_probe_store
	.hidden	bpftime_pc_probe_store
	.type	bpftime_pc_probe_store, @function
bpftime_pc_probe_store:
	movb	%cl, (%rdi)		/* faulting destination store */
	inc	%rsi
	inc	%rdi
	dec	%rdx
	jnz	bpftime_pc_probe_load
	ret
	.globl	bpftime_pc_probe_recovery
	.hidden	bpftime_pc_probe_recovery
	.type	bpftime_pc_probe_recovery, @function
bpftime_pc_probe_recovery:
	xor	%eax, %eax		/* recovered fault marker */
	ret
	.size	bpftime_pc_safe_copy_asm, .-bpftime_pc_safe_copy_asm

	.section .note.GNU-stack,"",@progbits
