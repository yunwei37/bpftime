/* SPDX-License-Identifier: MIT
 * x86_64 protected copy with an exact fault-instruction table.
 *
 * Input:  rdi=dst, rsi=src, rdx=n  (n > 0 guaranteed by the C++ caller)
 * Output: eax=1 copy succeeded; eax=0 a fault was recovered by the handler.
 *
 * The half-open symbol table [bpftime_pc_fault_table,
 * bpftime_pc_fault_table_end) lists exactly the two instruction PCs that
 * can fault on a host access: the source load and the destination store.
 * No control-flow instruction, the success return, the recovery label or
 * its return are members, so a signal delivered at any other PC is never
 * treated as a copy fault. The region stays a leaf: it contains no CALL.
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
bpftime_pc_probe_load:
	movzbl	(%rsi), %ecx		/* faulting source load (SEGV/BUS) */
	.globl	bpftime_pc_probe_store
bpftime_pc_probe_store:
	movb	%cl, (%rdi)		/* faulting destination store */
	inc	%rsi
	inc	%rdi
	dec	%rdx
	jnz	bpftime_pc_probe_load
	ret
	.globl	bpftime_pc_probe_recovery
bpftime_pc_probe_recovery:
	xor	%eax, %eax		/* recovered fault marker */
	ret
	.size	bpftime_pc_safe_copy_asm, .-bpftime_pc_safe_copy_asm

	.section .rodata
	.balign 8
	.globl	bpftime_pc_fault_table
bpftime_pc_fault_table:
	.quad	bpftime_pc_probe_load
	.quad	bpftime_pc_probe_store
	.globl	bpftime_pc_fault_table_end
bpftime_pc_fault_table_end:

	.section .note.GNU-stack,"",@progbits
