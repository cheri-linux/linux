/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017 SiFive
 */

#include <linux/init.h>
#include <linux/linkage.h>

#include <asm/asm.h>
#include <asm/csr.h>
#include <asm/unistd.h>
#include <asm/thread_info.h>
#include <asm/asm-offsets.h>
#include <asm/errata_list.h>

#if !IS_ENABLED(CONFIG_PREEMPTION)
.set resume_kernel, restore_all
#endif

ENTRY(handle_exception)
#ifndef CONFIG_CPU_CHERI
	/*
	 * If coming from userspace, preserve the user thread pointer and load
	 * the kernel thread pointer.  If we came from the kernel, the scratch
	 * register will contain 0, and we should continue on the current TP.
	 */
	csrrw tp, CSR_SCRATCH, tp
	bnez tp, _save_context

_restore_kernel_tpsp:
	csrr tp, CSR_SCRATCH
	REG_S sp, TASK_TI_KERNEL_SP(tp)

#ifdef CONFIG_VMAP_STACK
	addi sp, sp, -(PT_SIZE_ON_STACK)
	srli sp, sp, THREAD_SHIFT
	andi sp, sp, 0x1
	bnez sp, handle_kernel_stack_overflow
	REG_L sp, TASK_TI_KERNEL_SP(tp)
#endif

_save_context:
	REG_S sp, TASK_TI_USER_SP(tp)
	REG_L sp, TASK_TI_KERNEL_SP(tp)
	addi sp, sp, -(PT_SIZE_ON_STACK)
	REG_S x1,  PT_RA(sp)
	REG_S x3,  PT_GP(sp)
	REG_S x5,  PT_T0(sp)
	REG_S x6,  PT_T1(sp)
	REG_S x7,  PT_T2(sp)
	REG_S x8,  PT_S0(sp)
	REG_S x9,  PT_S1(sp)
	REG_S x10, PT_A0(sp)
	REG_S x11, PT_A1(sp)
	REG_S x12, PT_A2(sp)
	REG_S x13, PT_A3(sp)
	REG_S x14, PT_A4(sp)
	REG_S x15, PT_A5(sp)
	REG_S x16, PT_A6(sp)
	REG_S x17, PT_A7(sp)
	REG_S x18, PT_S2(sp)
	REG_S x19, PT_S3(sp)
	REG_S x20, PT_S4(sp)
	REG_S x21, PT_S5(sp)
	REG_S x22, PT_S6(sp)
	REG_S x23, PT_S7(sp)
	REG_S x24, PT_S8(sp)
	REG_S x25, PT_S9(sp)
	REG_S x26, PT_S10(sp)
	REG_S x27, PT_S11(sp)
	REG_S x28, PT_T3(sp)
	REG_S x29, PT_T4(sp)
	REG_S x30, PT_T5(sp)
	REG_S x31, PT_T6(sp)

	/*
	 * Disable user-mode memory access as it should only be set in the
	 * actual user copy routines.
	 *
	 * Disable the FPU to detect illegal usage of floating point in kernel
	 * space.
	 */
	li t0, SR_SUM | SR_FS

	REG_L s0, TASK_TI_USER_SP(tp)
	csrrc s1, CSR_STATUS, t0
	csrr s2, CSR_EPC
	csrr s3, CSR_TVAL
	csrr s4, CSR_CAUSE
	csrr s5, CSR_SCRATCH
	REG_S s0, PT_SP(sp)
	REG_S s1, PT_STATUS(sp)
	REG_S s2, PT_EPC(sp)
	REG_S s3, PT_BADADDR(sp)
	REG_S s4, PT_CAUSE(sp)
	REG_S s5, PT_TP(sp)

	/*
	 * Set the scratch register to 0, so that if a recursive exception
	 * occurs, the exception vector knows it came from the kernel
	 */
	csrw CSR_SCRATCH, x0

#else	/* CHERI */
.option push
.option capmode
	/*
	 * If coming from userspace, preserve the user thread pointer and load
	 * the kernel thread pointer.  If we came from the kernel, the scratch
	 * register will contain 0, and we should continue on the current TP.
	 */
	cspecialrw ctp, sscratchc, ctp
	bnez tp, _save_context

_restore_kernel_tpsp:
	cspecialr ctp, sscratchc
#ifndef CONFIG_CPU_CHERI_PURECAP
	// hybrid kernel needs to re-build ctp and csp
	// preserve ct0
	cspecialw sscratchc, ct0
	// build valid ctp
	cspecialr ct0, stdc
	csetaddr ct0, ct0, tp
	cmove ctp, ct0
	// build valid csp
	csetaddr ct0, ct0, sp
	cmove csp, ct0
	// restore ct0
	cspecialr ct0, sscratchc
	// store ctp back
	cspecialw sscratchc, ctp
#endif
	csc csp, TASK_TI_KERNEL_SP(ctp)

#ifdef CONFIG_VMAP_STACK
	cspecialw sscratchc, ct0
	cgetaddr t0, csp
	addi t0, t0, -(PT_SIZE_ON_STACK)
	srli t0, t0, THREAD_SHIFT
	andi t0, t0, 0x1
	bnez t0, handle_kernel_stack_overflow
	cspecialr ct0, sscratchc
	cspecialw sscratchc, ctp
	clc csp, TASK_TI_KERNEL_SP(ctp)
#endif

_save_context:
	csc csp, TASK_TI_USER_SP(ctp)
	clc csp, TASK_TI_KERNEL_SP(ctp)
	cincoffset csp, csp, -(PT_SIZE_ON_STACK)
	csc c1,  PT_RA(csp)
	csc c3,  PT_GP(csp)
	csc c5,  PT_T0(csp)
	csc c6,  PT_T1(csp)
	csc c7,  PT_T2(csp)
	csc c8,  PT_S0(csp)
	csc c9,  PT_S1(csp)
	csc c10, PT_A0(csp)
	csc c11, PT_A1(csp)
	csc c12, PT_A2(csp)
	csc c13, PT_A3(csp)
	csc c14, PT_A4(csp)
	csc c15, PT_A5(csp)
	csc c16, PT_A6(csp)
	csc c17, PT_A7(csp)
	csc c18, PT_S2(csp)
	csc c19, PT_S3(csp)
	csc c20, PT_S4(csp)
	csc c21, PT_S5(csp)
	csc c22, PT_S6(csp)
	csc c23, PT_S7(csp)
	csc c24, PT_S8(csp)
	csc c25, PT_S9(csp)
	csc c26, PT_S10(csp)
	csc c27, PT_S11(csp)
	csc c28, PT_T3(csp)
	csc c29, PT_T4(csp)
	csc c30, PT_T5(csp)
	csc c31, PT_T6(csp)

	/* store ddc */
	cspecialr ct0, ddc
	csc ct0, PT_DDC(csp)
	/* set kernel ddc */
	cspecialr ct0, stdc
	cspecialw ddc, ct0

	/*
	 * Disable user-mode memory access as it should only be set in the
	 * actual user copy routines.
	 *
	 * Disable the FPU to detect illegal usage of floating point in kernel
	 * space.
	 */
	li t0, SR_SUM | SR_FS

	clc cs0, TASK_TI_USER_SP(ctp)
	csrrc s1, CSR_STATUS, t0
	cspecialr cs2, sepcc
	csrr s3, CSR_TVAL
	csrr s4, CSR_CAUSE
	cspecialr cs5, sscratchc
	csc cs0, PT_SP(csp)
	csd s1, PT_STATUS(csp)
	csc cs2, PT_EPC(csp)
	csd s3, PT_BADADDR(csp)
	csd s4, PT_CAUSE(csp)
	csc cs5, PT_TP(csp)

	/*
	 * Set the scratch register to 0, so that if a recursive exception
	 * occurs, the exception vector knows it came from the kernel
	 */
	cmove ct0, cnull
	cspecialw sscratchc, ct0

#ifndef CONFIG_CPU_CHERI_PURECAP
	/* Switch to non-capmode PCC. */
	cllc ct0, 1f
	csetflags ct0, ct0, x0
	cjr ct0
.align 2
1:
#endif
.option pop
#endif	/* endof CHERI */

	/* Load the global pointer */
.option push
.option norelax
#ifndef CONFIG_CPU_CHERI_PURECAP
	la gp, __global_pointer$
#else
	cllc cgp, __global_pointer$
#endif
.option pop

#ifdef CONFIG_TRACE_IRQFLAGS
	call __trace_hardirqs_off
#endif

#ifdef CONFIG_CONTEXT_TRACKING
	/* If previous state is in user mode, call context_tracking_user_exit. */
	li   a0, SR_PP
	and a0, s1, a0
	bnez a0, skip_context_tracking
	call context_tracking_user_exit
skip_context_tracking:
#endif

	/*
	 * MSB of cause differentiates between
	 * interrupts and exceptions
	 */
	bge s4, zero, 1f

#ifndef CONFIG_CPU_CHERI_PURECAP
	la ra, ret_from_exception
#else
	cllc cra, ret_from_exception
#endif

	/* Handle interrupts */
#ifndef CONFIG_CPU_CHERI_PURECAP
	move a0, sp /* pt_regs */
	la a1, handle_arch_irq
	REG_L a1, (a1)
	jr a1
#else
	cmove ca0, csp /* pt_regs */
	cllc ca1, handle_arch_irq
	clc ca1, 0(ca1)
	cjr ca1
#endif

1:
	/*
	 * Exceptions run with interrupts enabled or disabled depending on the
	 * state of SR_PIE in m/sstatus.
	 */
	andi t0, s1, SR_PIE
	beqz t0, 1f
	/* kprobes, entered via ebreak, must have interrupts disabled. */
	li t0, EXC_BREAKPOINT
	beq s4, t0, 1f
#ifdef CONFIG_TRACE_IRQFLAGS
	call __trace_hardirqs_on
#endif
	csrs CSR_STATUS, SR_IE

1:
#ifndef CONFIG_CPU_CHERI_PURECAP
	la ra, ret_from_exception
#else
	cllc cra, ret_from_exception
#endif
	/* Handle syscalls */
	li t0, EXC_SYSCALL
	beq s4, t0, handle_syscall

#ifndef CONFIG_CPU_CHERI_PURECAP
	move a0, sp /* pt_regs */
#else
	cmove ca0, csp /* pt_regs */
#endif

#ifdef CONFIG_CPU_CHERI
#if 1
	// enable user access for user-space gdb backtrace in kernel breakpoint
	li t0, SR_SUM
	csrs CSR_STATUS, t0
#endif
	li t0, EXC_CHERI
	beq s4, t0, 2f
#endif

	/* Handle other exceptions */
	slli t0, s4, RISCV_LGPTR

#ifndef CONFIG_CPU_CHERI_PURECAP
	la t1, excp_vect_table
	la t2, excp_vect_table_end
	add t0, t1, t0
	/* Check if exception code lies within bounds */
	bgeu t0, t2, 1f
	REG_L t0, 0(t0)
	jr t0
1:
	tail do_trap_unknown

#ifdef CONFIG_CPU_CHERI
2:
	tail do_trap_cheri
#endif

#else // CONFIG_CPU_CHERI_PURECAP

	cllc ct1, excp_vect_table
	cllc ct2, excp_vect_table_end
	cincoffset ct0, ct1, t0
	/* Check if exception code lies within bounds */
	bgeu t0, t2, 1f
	clc ct0, 0(ct0)
	cjr ct0
1:
	cllc ct0, do_trap_unknown
	cjr ct0

2:
	cllc ct0, do_trap_cheri
	cjr ct0

#endif


handle_syscall:
#ifdef CONFIG_RISCV_M_MODE
	/*
	 * When running is M-Mode (no MMU config), MPIE does not get set.
	 * As a result, we need to force enable interrupts here because
	 * handle_exception did not do set SR_IE as it always sees SR_PIE
	 * being cleared.
	 */
	csrs CSR_STATUS, SR_IE
#endif
#if defined(CONFIG_TRACE_IRQFLAGS) || defined(CONFIG_CONTEXT_TRACKING)
	/* Recover a0 - a7 for system calls */
	REG_L a0, PT_A0(sp)
	REG_L a1, PT_A1(sp)
	REG_L a2, PT_A2(sp)
	REG_L a3, PT_A3(sp)
	REG_L a4, PT_A4(sp)
	REG_L a5, PT_A5(sp)
	REG_L a6, PT_A6(sp)
	REG_L a7, PT_A7(sp)
#endif
#ifndef CONFIG_CPU_CHERI
	 /* save the initial A0 value (needed in signal handlers) */
	REG_S a0, PT_ORIG_A0(sp)
	/*
	 * Advance SEPC to avoid executing the original
	 * scall instruction on sret
	 */
	addi s2, s2, 0x4
	REG_S s2, PT_EPC(sp)
#else
.option push
.option capmode
	 /* save the initial A0 value (needed in signal handlers) */
	csc ca0, PT_ORIG_A0(csp)
	/*
	 * Advance SEPC to avoid executing the original
	 * scall instruction on sret
	 */
	cincoffset cs2, cs2, 0x4
	csc cs2, PT_EPC(csp)
.option pop
#endif
	/* Trace syscalls, but only if requested by the user. */
#ifndef CONFIG_CPU_CHERI_PURECAP
	REG_L t0, TASK_TI_FLAGS(tp)
#else
	cld t0, TASK_TI_FLAGS(ctp)
#endif
	andi t0, t0, _TIF_SYSCALL_WORK
	bnez t0, handle_syscall_trace_enter
check_syscall_nr:
	/* Check to make sure we don't jump to a bogus syscall number. */
	li t0, __NR_syscalls
#ifndef CONFIG_CPU_CHERI_PURECAP
	la s0, sys_ni_syscall
#else
	cllc cs0, sys_ni_syscall
#endif
	/*
	 * Syscall number held in a7.
	 * If syscall number is above allowed value, redirect to ni_syscall.
	 */
	bgeu a7, t0, 1f
	slli t0, a7, RISCV_LGPTR
	/* Call syscall */
#ifndef CONFIG_CPU_CHERI_PURECAP
	la s0, sys_call_table
	add s0, s0, t0
	REG_L s0, 0(s0)
1:
	jalr s0
#else
	cllc cs0, sys_call_table
	cincoffset cs0, cs0, t0
	clc cs0, 0(cs0)
1:
	cjalr cs0
#endif

ret_from_syscall:
	/* Set user a0 to kernel a0 */
#ifndef CONFIG_CPU_CHERI_PURECAP
	REG_S a0, PT_A0(sp)
#else
	csc ca0, PT_A0(csp)
#endif
	/*
	 * We didn't execute the actual syscall.
	 * Seccomp already set return value for the current task pt_regs.
	 * (If it was configured with SECCOMP_RET_ERRNO/TRACE)
	 */
ret_from_syscall_rejected:
	/* Trace syscalls, but only if requested by the user. */
#ifndef CONFIG_CPU_CHERI_PURECAP
	REG_L t0, TASK_TI_FLAGS(tp)
#else
	cld t0, TASK_TI_FLAGS(ctp)
#endif
	andi t0, t0, _TIF_SYSCALL_WORK
	bnez t0, handle_syscall_trace_exit

ret_from_exception:
#ifndef CONFIG_CPU_CHERI_PURECAP
	REG_L s0, PT_STATUS(sp)
#else
	cld s0, PT_STATUS(csp)
#endif
	csrc CSR_STATUS, SR_IE
#ifdef CONFIG_TRACE_IRQFLAGS
	call __trace_hardirqs_off
#endif
#ifdef CONFIG_RISCV_M_MODE
	/* the MPP value is too large to be used as an immediate arg for addi */
	li t0, SR_MPP
	and s0, s0, t0
#else
	andi s0, s0, SR_SPP
#endif
	bnez s0, resume_kernel

resume_userspace:
	/* Interrupts must be disabled here so flags are checked atomically */
#ifndef CONFIG_CPU_CHERI_PURECAP
	REG_L s0, TASK_TI_FLAGS(tp) /* current_thread_info->flags */
#else
	cld s0, TASK_TI_FLAGS(ctp) /* current_thread_info->flags */
#endif

	andi s1, s0, _TIF_WORK_MASK
	bnez s1, work_pending

#ifdef CONFIG_CONTEXT_TRACKING
	call context_tracking_user_enter
#endif

#ifndef CONFIG_CPU_CHERI

	/* Save unwound kernel stack pointer in thread_info */
	addi s0, sp, PT_SIZE_ON_STACK
	REG_S s0, TASK_TI_KERNEL_SP(tp)

	/*
	 * Save TP into the scratch register , so we can find the kernel data
	 * structures again.
	 */
	csrw CSR_SCRATCH, tp

restore_all:
#ifdef CONFIG_TRACE_IRQFLAGS
	REG_L s1, PT_STATUS(sp)
	andi t0, s1, SR_PIE
	beqz t0, 1f
	call __trace_hardirqs_on
	j 2f
1:
	call __trace_hardirqs_off
2:
#endif
	REG_L a0, PT_STATUS(sp)
	/*
	 * The current load reservation is effectively part of the processor's
	 * state, in the sense that load reservations cannot be shared between
	 * different hart contexts.  We can't actually save and restore a load
	 * reservation, so instead here we clear any existing reservation --
	 * it's always legal for implementations to clear load reservations at
	 * any point (as long as the forward progress guarantee is kept, but
	 * we'll ignore that here).
	 *
	 * Dangling load reservations can be the result of taking a trap in the
	 * middle of an LR/SC sequence, but can also be the result of a taken
	 * forward branch around an SC -- which is how we implement CAS.  As a
	 * result we need to clear reservations between the last CAS and the
	 * jump back to the new context.  While it is unlikely the store
	 * completes, implementations are allowed to expand reservations to be
	 * arbitrarily large.
	 */
	REG_L  a2, PT_EPC(sp)
	REG_SC x0, a2, PT_EPC(sp)

	csrw CSR_STATUS, a0
	csrw CSR_EPC, a2

	REG_L x1,  PT_RA(sp)
	REG_L x3,  PT_GP(sp)
	REG_L x4,  PT_TP(sp)
	REG_L x5,  PT_T0(sp)
	REG_L x6,  PT_T1(sp)
	REG_L x7,  PT_T2(sp)
	REG_L x8,  PT_S0(sp)
	REG_L x9,  PT_S1(sp)
	REG_L x10, PT_A0(sp)
	REG_L x11, PT_A1(sp)
	REG_L x12, PT_A2(sp)
	REG_L x13, PT_A3(sp)
	REG_L x14, PT_A4(sp)
	REG_L x15, PT_A5(sp)
	REG_L x16, PT_A6(sp)
	REG_L x17, PT_A7(sp)
	REG_L x18, PT_S2(sp)
	REG_L x19, PT_S3(sp)
	REG_L x20, PT_S4(sp)
	REG_L x21, PT_S5(sp)
	REG_L x22, PT_S6(sp)
	REG_L x23, PT_S7(sp)
	REG_L x24, PT_S8(sp)
	REG_L x25, PT_S9(sp)
	REG_L x26, PT_S10(sp)
	REG_L x27, PT_S11(sp)
	REG_L x28, PT_T3(sp)
	REG_L x29, PT_T4(sp)
	REG_L x30, PT_T5(sp)
	REG_L x31, PT_T6(sp)

	REG_L x2,  PT_SP(sp)

#else	/* CHERI */
#ifndef CONFIG_CPU_CHERI_PURECAP
	/* Switch to capmode PCC. */
	lla t1, 1f
	cspecialr ct0, pcc
	csetaddr ct0, ct0, t1
	li t1, 1
	csetflags ct0, ct0, t1
.option push
.option capmode
#ifdef __riscv_xcheri_mode_dependent_jumps
	jr.cap  ct0
#else
	cjr     ct0
#endif
.align 2
1:
	// hybrid kernel needs to re-build ctp and csp
	// build valid ctp
	cspecialr ct0, stdc
	csetaddr ct0, ct0, tp
	cmove ctp, ct0
	// build valid csp
	csetaddr ct0, ct0, sp
	cmove csp, ct0
#else
.option push
.option capmode
#endif

	/* Save unwound kernel stack pointer in thread_info */
	cincoffset cs0, csp, PT_SIZE_ON_STACK
	csc cs0, TASK_TI_KERNEL_SP(ctp)

	/*
	 * Save TP into the scratch register , so we can find the kernel data
	 * structures again.
	 */
	cspecialw sscratchc, ctp

restore_all:
	cld a0, PT_STATUS(csp)
	/*
	 * The current load reservation is effectively part of the processor's
	 * state, in the sense that load reservations cannot be shared between
	 * different hart contexts.  We can't actually save and restore a load
	 * reservation, so instead here we clear any existing reservation --
	 * it's always legal for implementations to clear load reservations at
	 * any point (as long as the forward progress guarantee is kept, but
	 * we'll ignore that here).
	 *
	 * Dangling load reservations can be the result of taking a trap in the
	 * middle of an LR/SC sequence, but can also be the result of a taken
	 * forward branch around an SC -- which is how we implement CAS.  As a
	 * result we need to clear reservations between the last CAS and the
	 * jump back to the new context.  While it is unlikely the store
	 * completes, implementations are allowed to expand reservations to be
	 * arbitrarily large.
	 */
	clc  ca2, PT_EPC(csp)
	csc.c.aqrl x0, ca2, PT_EPC(csp)

	csrw CSR_STATUS, a0

	cspecialw sepcc, ca2

	/* restore ddc */
	clc ct0, PT_DDC(csp)
	cspecialw ddc, ct0

	clc c1,  PT_RA(csp)
	clc c3,  PT_GP(csp)
	clc c4,  PT_TP(csp)
	clc c5,  PT_T0(csp)
	clc c6,  PT_T1(csp)
	clc c7,  PT_T2(csp)
	clc c8,  PT_S0(csp)
	clc c9,  PT_S1(csp)
	clc c10, PT_A0(csp)
	clc c11, PT_A1(csp)
	clc c12, PT_A2(csp)
	clc c13, PT_A3(csp)
	clc c14, PT_A4(csp)
	clc c15, PT_A5(csp)
	clc c16, PT_A6(csp)
	clc c17, PT_A7(csp)
	clc c18, PT_S2(csp)
	clc c19, PT_S3(csp)
	clc c20, PT_S4(csp)
	clc c21, PT_S5(csp)
	clc c22, PT_S6(csp)
	clc c23, PT_S7(csp)
	clc c24, PT_S8(csp)
	clc c25, PT_S9(csp)
	clc c26, PT_S10(csp)
	clc c27, PT_S11(csp)
	clc c28, PT_T3(csp)
	clc c29, PT_T4(csp)
	clc c30, PT_T5(csp)
	clc c31, PT_T6(csp)

	clc c2,  PT_SP(csp)
.option pop
#endif	/* endof CHERI */

#ifdef CONFIG_RISCV_M_MODE
	mret
#else
	sret
#endif

#if IS_ENABLED(CONFIG_PREEMPTION)
resume_kernel:
	REG_L s0, TASK_TI_PREEMPT_COUNT(tp)
	bnez s0, restore_all
	REG_L s0, TASK_TI_FLAGS(tp)
	andi s0, s0, _TIF_NEED_RESCHED
	beqz s0, restore_all
	call preempt_schedule_irq
	j restore_all
#endif

work_pending:
	/* Enter slow path for supplementary processing */
#ifndef CONFIG_CPU_CHERI_PURECAP
	la ra, ret_from_exception
#else
	cllc cra, ret_from_exception
#endif
	andi s1, s0, _TIF_NEED_RESCHED
	bnez s1, work_resched
work_notifysig:
	/* Handle pending signals and notify-resume requests */
	csrs CSR_STATUS, SR_IE /* Enable interrupts for do_notify_resume() */
#ifndef CONFIG_CPU_CHERI_PURECAP
	move a0, sp /* pt_regs */
	move a1, s0 /* current_thread_info->flags */
	tail do_notify_resume
work_resched:
	tail schedule
#else
	cmove ca0, csp /* pt_regs */
	cmove ca1, cs0 /* current_thread_info->flags */
	cllc ct0, do_notify_resume
	cjr ct0
work_resched:
	cllc ct0, schedule
	cjr ct0
#endif

/* Slow paths for ptrace. */
#ifndef CONFIG_CPU_CHERI_PURECAP
handle_syscall_trace_enter:
	move a0, sp
	call do_syscall_trace_enter
	move t0, a0
	REG_L a0, PT_A0(sp)
	REG_L a1, PT_A1(sp)
	REG_L a2, PT_A2(sp)
	REG_L a3, PT_A3(sp)
	REG_L a4, PT_A4(sp)
	REG_L a5, PT_A5(sp)
	REG_L a6, PT_A6(sp)
	REG_L a7, PT_A7(sp)
	bnez t0, ret_from_syscall_rejected
	j check_syscall_nr
handle_syscall_trace_exit:
	move a0, sp
	call do_syscall_trace_exit
	j ret_from_exception
#else
handle_syscall_trace_enter:
	cmove ca0, csp
	cllc ct0, do_syscall_trace_enter
	cjalr ct0
	cmove ct0, ca0
	clc ca0, PT_A0(csp)
	clc ca1, PT_A1(csp)
	clc ca2, PT_A2(csp)
	clc ca3, PT_A3(csp)
	clc ca4, PT_A4(csp)
	clc ca5, PT_A5(csp)
	clc ca6, PT_A6(csp)
	clc ca7, PT_A7(csp)
	bnez t0, ret_from_syscall_rejected
	j check_syscall_nr
handle_syscall_trace_exit:
	cmove ca0, csp
	cllc ct0, do_syscall_trace_exit
	cjalr ct0
	j ret_from_exception
#endif

#ifdef CONFIG_VMAP_STACK
#ifndef CONFIG_CPU_CHERI_PURECAP
handle_kernel_stack_overflow:
	la sp, shadow_stack
	addi sp, sp, SHADOW_OVERFLOW_STACK_SIZE

	//save caller register to shadow stack
	addi sp, sp, -(PT_SIZE_ON_STACK)
	REG_S x1,  PT_RA(sp)
	REG_S x5,  PT_T0(sp)
	REG_S x6,  PT_T1(sp)
	REG_S x7,  PT_T2(sp)
	REG_S x10, PT_A0(sp)
	REG_S x11, PT_A1(sp)
	REG_S x12, PT_A2(sp)
	REG_S x13, PT_A3(sp)
	REG_S x14, PT_A4(sp)
	REG_S x15, PT_A5(sp)
	REG_S x16, PT_A6(sp)
	REG_S x17, PT_A7(sp)
	REG_S x28, PT_T3(sp)
	REG_S x29, PT_T4(sp)
	REG_S x30, PT_T5(sp)
	REG_S x31, PT_T6(sp)

	la ra, restore_caller_reg
	tail get_overflow_stack

restore_caller_reg:
	//save per-cpu overflow stack
	REG_S a0, -8(sp)
	//restore caller register from shadow_stack
	REG_L x1,  PT_RA(sp)
	REG_L x5,  PT_T0(sp)
	REG_L x6,  PT_T1(sp)
	REG_L x7,  PT_T2(sp)
	REG_L x10, PT_A0(sp)
	REG_L x11, PT_A1(sp)
	REG_L x12, PT_A2(sp)
	REG_L x13, PT_A3(sp)
	REG_L x14, PT_A4(sp)
	REG_L x15, PT_A5(sp)
	REG_L x16, PT_A6(sp)
	REG_L x17, PT_A7(sp)
	REG_L x28, PT_T3(sp)
	REG_L x29, PT_T4(sp)
	REG_L x30, PT_T5(sp)
	REG_L x31, PT_T6(sp)

	//load per-cpu overflow stack
	REG_L sp, -8(sp)
	addi sp, sp, -(PT_SIZE_ON_STACK)

	//save context to overflow stack
	REG_S x1,  PT_RA(sp)
	REG_S x3,  PT_GP(sp)
	REG_S x5,  PT_T0(sp)
	REG_S x6,  PT_T1(sp)
	REG_S x7,  PT_T2(sp)
	REG_S x8,  PT_S0(sp)
	REG_S x9,  PT_S1(sp)
	REG_S x10, PT_A0(sp)
	REG_S x11, PT_A1(sp)
	REG_S x12, PT_A2(sp)
	REG_S x13, PT_A3(sp)
	REG_S x14, PT_A4(sp)
	REG_S x15, PT_A5(sp)
	REG_S x16, PT_A6(sp)
	REG_S x17, PT_A7(sp)
	REG_S x18, PT_S2(sp)
	REG_S x19, PT_S3(sp)
	REG_S x20, PT_S4(sp)
	REG_S x21, PT_S5(sp)
	REG_S x22, PT_S6(sp)
	REG_S x23, PT_S7(sp)
	REG_S x24, PT_S8(sp)
	REG_S x25, PT_S9(sp)
	REG_S x26, PT_S10(sp)
	REG_S x27, PT_S11(sp)
	REG_S x28, PT_T3(sp)
	REG_S x29, PT_T4(sp)
	REG_S x30, PT_T5(sp)
	REG_S x31, PT_T6(sp)

	REG_L s0, TASK_TI_KERNEL_SP(tp)
	csrr s1, CSR_STATUS
	csrr s2, CSR_EPC
	csrr s3, CSR_TVAL
	csrr s4, CSR_CAUSE
	csrr s5, CSR_SCRATCH
	REG_S s0, PT_SP(sp)
	REG_S s1, PT_STATUS(sp)
	REG_S s2, PT_EPC(sp)
	REG_S s3, PT_BADADDR(sp)
	REG_S s4, PT_CAUSE(sp)
	REG_S s5, PT_TP(sp)
	move a0, sp
	tail handle_bad_stack
#else
handle_kernel_stack_overflow:
	cspecialr ct0, sscratchc
	cspecialw sscratchc, ctp
	cllc csp, shadow_stack
	cincoffset csp, csp, SHADOW_OVERFLOW_STACK_SIZE

	//save caller register to shadow stack
	cincoffset csp, csp, -(PT_SIZE_ON_STACK)
	csc c1,  PT_RA(csp)
	csc c5,  PT_T0(csp)
	csc c6,  PT_T1(csp)
	csc c7,  PT_T2(csp)
	csc c10, PT_A0(csp)
	csc c11, PT_A1(csp)
	csc c12, PT_A2(csp)
	csc c13, PT_A3(csp)
	csc c14, PT_A4(csp)
	csc c15, PT_A5(csp)
	csc c16, PT_A6(csp)
	csc c17, PT_A7(csp)
	csc c28, PT_T3(csp)
	csc c29, PT_T4(csp)
	csc c30, PT_T5(csp)
	csc c31, PT_T6(csp)

	cllc cra, restore_caller_reg
	cllc ct0, get_overflow_stack
	cjr ct0

restore_caller_reg:
	//save per-cpu overflow stack
	csc ca0, -16(csp)
	//restore caller register from shadow_stack
	clc c1,  PT_RA(csp)
	clc c5,  PT_T0(csp)
	clc c6,  PT_T1(csp)
	clc c7,  PT_T2(csp)
	clc c10, PT_A0(csp)
	clc c11, PT_A1(csp)
	clc c12, PT_A2(csp)
	clc c13, PT_A3(csp)
	clc c14, PT_A4(csp)
	clc c15, PT_A5(csp)
	clc c16, PT_A6(csp)
	clc c17, PT_A7(csp)
	clc c28, PT_T3(csp)
	clc c29, PT_T4(csp)
	clc c30, PT_T5(csp)
	clc c31, PT_T6(csp)

	//load per-cpu overflow stack
	clc csp, -16(csp)
	cincoffset csp, csp, -(PT_SIZE_ON_STACK)

	//save context to overflow stack
	csc c1,  PT_RA(csp)
	csc c3,  PT_GP(csp)
	csc c5,  PT_T0(csp)
	csc c6,  PT_T1(csp)
	csc c7,  PT_T2(csp)
	csc c8,  PT_S0(csp)
	csc c9,  PT_S1(csp)
	csc c10, PT_A0(csp)
	csc c11, PT_A1(csp)
	csc c12, PT_A2(csp)
	csc c13, PT_A3(csp)
	csc c14, PT_A4(csp)
	csc c15, PT_A5(csp)
	csc c16, PT_A6(csp)
	csc c17, PT_A7(csp)
	csc c18, PT_S2(csp)
	csc c19, PT_S3(csp)
	csc c20, PT_S4(csp)
	csc c21, PT_S5(csp)
	csc c22, PT_S6(csp)
	csc c23, PT_S7(csp)
	csc c24, PT_S8(csp)
	csc c25, PT_S9(csp)
	csc c26, PT_S10(csp)
	csc c27, PT_S11(csp)
	csc c28, PT_T3(csp)
	csc c29, PT_T4(csp)
	csc c30, PT_T5(csp)
	csc c31, PT_T6(csp)

	clc cs0, TASK_TI_KERNEL_SP(ctp)
	csrr s1, CSR_STATUS
	cspecialr cs2, sepcc
	csrr s3, CSR_TVAL
	csrr s4, CSR_CAUSE
	cspecialr cs5, sscratchc
	csc cs0, PT_SP(csp)
	csd s1, PT_STATUS(csp)
	csc cs2, PT_EPC(csp)
	csd s3, PT_BADADDR(csp)
	csd s4, PT_CAUSE(csp)
	csc cs5, PT_TP(csp)
	cmove ca0, csp
	cllc ct0, handle_bad_stack
	cjr ct0
#endif // CHERI_PURECAP
#endif

ENDPROC(handle_exception)

#ifndef CONFIG_CPU_CHERI_PURECAP

ENTRY(ret_from_fork)
	la ra, ret_from_exception
	tail schedule_tail
ENDPROC(ret_from_fork)

ENTRY(ret_from_kernel_thread)
	call schedule_tail
	/* Call fn(arg) */
	la ra, ret_from_exception
	move a0, s1
	jr s0
ENDPROC(ret_from_kernel_thread)

#else
ENTRY(ret_from_fork)
	cllc cra, ret_from_exception
	cllc ct0, schedule_tail
	cjr ct0
ENDPROC(ret_from_fork)

ENTRY(ret_from_kernel_thread)
	cllc ct0, schedule_tail
	cjalr ct0
	/* Call fn(arg) */
	cllc cra, ret_from_exception
	cmove ca0, cs1
	cjr cs0
ENDPROC(ret_from_kernel_thread)

#endif


/*
 * Integer register context switch
 * The callee-saved registers must be saved and restored.
 *
 *   a0: previous task_struct (must be preserved across the switch)
 *   a1: next task_struct
 *
 * The value of a0 and a1 must be preserved by this function, as that's how
 * arguments are passed to schedule_tail.
 */
#ifndef CONFIG_CPU_CHERI_PURECAP
ENTRY(__switch_to)
	/* Save context into prev->thread */
	li    a4,  TASK_THREAD_RA
	add   a3, a0, a4
	add   a4, a1, a4
#ifndef CONFIG_CPU_CHERI
	REG_S ra,  TASK_THREAD_RA_RA(a3)
	REG_S sp,  TASK_THREAD_SP_RA(a3)
	REG_S s0,  TASK_THREAD_S0_RA(a3)
	REG_S s1,  TASK_THREAD_S1_RA(a3)
	REG_S s2,  TASK_THREAD_S2_RA(a3)
	REG_S s3,  TASK_THREAD_S3_RA(a3)
	REG_S s4,  TASK_THREAD_S4_RA(a3)
	REG_S s5,  TASK_THREAD_S5_RA(a3)
	REG_S s6,  TASK_THREAD_S6_RA(a3)
	REG_S s7,  TASK_THREAD_S7_RA(a3)
	REG_S s8,  TASK_THREAD_S8_RA(a3)
	REG_S s9,  TASK_THREAD_S9_RA(a3)
	REG_S s10, TASK_THREAD_S10_RA(a3)
	REG_S s11, TASK_THREAD_S11_RA(a3)
	/* Restore context from next->thread */
	REG_L ra,  TASK_THREAD_RA_RA(a4)
	REG_L sp,  TASK_THREAD_SP_RA(a4)
	REG_L s0,  TASK_THREAD_S0_RA(a4)
	REG_L s1,  TASK_THREAD_S1_RA(a4)
	REG_L s2,  TASK_THREAD_S2_RA(a4)
	REG_L s3,  TASK_THREAD_S3_RA(a4)
	REG_L s4,  TASK_THREAD_S4_RA(a4)
	REG_L s5,  TASK_THREAD_S5_RA(a4)
	REG_L s6,  TASK_THREAD_S6_RA(a4)
	REG_L s7,  TASK_THREAD_S7_RA(a4)
	REG_L s8,  TASK_THREAD_S8_RA(a4)
	REG_L s9,  TASK_THREAD_S9_RA(a4)
	REG_L s10, TASK_THREAD_S10_RA(a4)
	REG_L s11, TASK_THREAD_S11_RA(a4)
#else
	sc cra,  TASK_THREAD_RA_RA(a3)
	sc csp,  TASK_THREAD_SP_RA(a3)
	sc cs0,  TASK_THREAD_S0_RA(a3)
	sc cs1,  TASK_THREAD_S1_RA(a3)
	sc cs2,  TASK_THREAD_S2_RA(a3)
	sc cs3,  TASK_THREAD_S3_RA(a3)
	sc cs4,  TASK_THREAD_S4_RA(a3)
	sc cs5,  TASK_THREAD_S5_RA(a3)
	sc cs6,  TASK_THREAD_S6_RA(a3)
	sc cs7,  TASK_THREAD_S7_RA(a3)
	sc cs8,  TASK_THREAD_S8_RA(a3)
	sc cs9,  TASK_THREAD_S9_RA(a3)
	sc cs10, TASK_THREAD_S10_RA(a3)
	sc cs11, TASK_THREAD_S11_RA(a3)
	/* Restore context from next->thread */
	lc cra,  TASK_THREAD_RA_RA(a4)
	lc csp,  TASK_THREAD_SP_RA(a4)
	lc cs0,  TASK_THREAD_S0_RA(a4)
	lc cs1,  TASK_THREAD_S1_RA(a4)
	lc cs2,  TASK_THREAD_S2_RA(a4)
	lc cs3,  TASK_THREAD_S3_RA(a4)
	lc cs4,  TASK_THREAD_S4_RA(a4)
	lc cs5,  TASK_THREAD_S5_RA(a4)
	lc cs6,  TASK_THREAD_S6_RA(a4)
	lc cs7,  TASK_THREAD_S7_RA(a4)
	lc cs8,  TASK_THREAD_S8_RA(a4)
	lc cs9,  TASK_THREAD_S9_RA(a4)
	lc cs10, TASK_THREAD_S10_RA(a4)
	lc cs11, TASK_THREAD_S11_RA(a4)
#endif
	/* Swap the CPU entry around. */
	lw a3, TASK_TI_CPU(a0)
	lw a4, TASK_TI_CPU(a1)
	sw a3, TASK_TI_CPU(a1)
	sw a4, TASK_TI_CPU(a0)
	/* The offset of thread_info in task_struct is zero. */
	move tp, a1
	ret
ENDPROC(__switch_to)
#else
ENTRY(__switch_to)
	/* Save context into prev->thread */
	li    a4,  TASK_THREAD_RA
	cincoffset ca3, ca0, a4
	cincoffset ca4, ca1, a4
	csc cra,  TASK_THREAD_RA_RA(ca3)
	csc csp,  TASK_THREAD_SP_RA(ca3)
	csc cs0,  TASK_THREAD_S0_RA(ca3)
	csc cs1,  TASK_THREAD_S1_RA(ca3)
	csc cs2,  TASK_THREAD_S2_RA(ca3)
	csc cs3,  TASK_THREAD_S3_RA(ca3)
	csc cs4,  TASK_THREAD_S4_RA(ca3)
	csc cs5,  TASK_THREAD_S5_RA(ca3)
	csc cs6,  TASK_THREAD_S6_RA(ca3)
	csc cs7,  TASK_THREAD_S7_RA(ca3)
	csc cs8,  TASK_THREAD_S8_RA(ca3)
	csc cs9,  TASK_THREAD_S9_RA(ca3)
	csc cs10, TASK_THREAD_S10_RA(ca3)
	csc cs11, TASK_THREAD_S11_RA(ca3)
	/* Restore context from next->thread */
	clc cra,  TASK_THREAD_RA_RA(ca4)
	clc csp,  TASK_THREAD_SP_RA(ca4)
	clc cs0,  TASK_THREAD_S0_RA(ca4)
	clc cs1,  TASK_THREAD_S1_RA(ca4)
	clc cs2,  TASK_THREAD_S2_RA(ca4)
	clc cs3,  TASK_THREAD_S3_RA(ca4)
	clc cs4,  TASK_THREAD_S4_RA(ca4)
	clc cs5,  TASK_THREAD_S5_RA(ca4)
	clc cs6,  TASK_THREAD_S6_RA(ca4)
	clc cs7,  TASK_THREAD_S7_RA(ca4)
	clc cs8,  TASK_THREAD_S8_RA(ca4)
	clc cs9,  TASK_THREAD_S9_RA(ca4)
	clc cs10, TASK_THREAD_S10_RA(ca4)
	clc cs11, TASK_THREAD_S11_RA(ca4)
	/* Swap the CPU entry around. */
	clw a3, TASK_TI_CPU(ca0)
	clw a4, TASK_TI_CPU(ca1)
	csw a3, TASK_TI_CPU(ca1)
	csw a4, TASK_TI_CPU(ca0)
#if TASK_TI != 0
#error "TASK_TI != 0: tp will contain a 'struct thread_info', not a 'struct task_struct' so get_current() won't work."
	cincoffset ctp, ca1, TASK_TI
#else
	cmove ctp, ca1
#endif
	cret
ENDPROC(__switch_to)
#endif

#ifndef CONFIG_MMU
#define do_page_fault do_trap_unknown
#endif

	.section ".rodata"
	.align LGREG
	/* Exception vector table */
ENTRY(excp_vect_table)
	RISCV_PTR do_trap_insn_misaligned
	ALT_INSN_FAULT(RISCV_PTR do_trap_insn_fault)
	RISCV_PTR do_trap_insn_illegal
	RISCV_PTR do_trap_break
	RISCV_PTR do_trap_load_misaligned
	RISCV_PTR do_trap_load_fault
	RISCV_PTR do_trap_store_misaligned
	RISCV_PTR do_trap_store_fault
	RISCV_PTR do_trap_ecall_u /* system call, gets intercepted */
	RISCV_PTR do_trap_ecall_s
	RISCV_PTR do_trap_unknown
	RISCV_PTR do_trap_ecall_m
	/* instruciton page fault */
	ALT_PAGE_FAULT(RISCV_PTR do_page_fault)
	RISCV_PTR do_page_fault   /* load page fault */
	RISCV_PTR do_trap_unknown
	RISCV_PTR do_page_fault   /* store page fault */
excp_vect_table_end:
END(excp_vect_table)

#ifndef CONFIG_MMU
ENTRY(__user_rt_sigreturn)
	li a7, __NR_rt_sigreturn
	scall
ENDPROC(__user_rt_sigreturn)
#endif
