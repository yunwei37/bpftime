/* SPDX-License-Identifier: MIT
 * x86_64 fixed-width protected copy region for fault-safe probe reads.
 *
 * Input:  rdi=dst, rsi=src, rdx=n  (n > 0 guaranteed by the C++ caller)
 * Output: eax=1 copy succeeded; eax=0 a fault was recovered by the handler.
 *
 * Invariant: the half-open range [bpftime_pc_probe_begin,
 * bpftime_pc_probe_end) contains only loads, stores and loop control --
 * never a CALL -- so a faulting RIP inside the range uniquely identifies an
 * access of this copy. The signal handler compares RIP against the two
 * boundary symbols and redirects RIP to bpftime_pc_probe_recovery; no
 * thread-local "active" window and no backtrace are needed.
 */
	.text
	.globl	bpftime_pc_safe_copy_asm
	.type	bpftime_pc_safe_copy_asm, @function
	.globl	bpftime_pc_probe_begin
	.globl	bpftime_pc_probe_recovery
	.globl	bpftime_pc_probe_end
bpftime_pc_safe_copy_asm:
bpftime_pc_probe_begin:
	mov	$1, %eax		/* success marker; recovery overwrites it */
1:
	movzbl	(%rsi), %ecx		/* faulting source load (SEGV/BUS) */
	movb	%cl, (%rdi)		/* faulting destination store */
	inc	%rsi
	inc	%rdi
	dec	%rdx
	jnz	1b
	ret
bpftime_pc_probe_recovery:
	xor	%eax, %eax		/* recovered fault marker */
	ret
bpftime_pc_probe_end:
	.size	bpftime_pc_safe_copy_asm, .-bpftime_pc_safe_copy_asm
	.section .note.GNU-stack,"",@progbits
