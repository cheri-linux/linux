/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _UAPI_ASM_RISCV_PTRACE_H
#define _UAPI_ASM_RISCV_PTRACE_H

#ifndef __ASSEMBLY__

#include <linux/types.h>

#ifdef __CHERI__
#include <linux/cheri.h>
#endif

/*
 * User-mode register state for core dumps, ptrace, sigcontext
 *
 * This decouples struct pt_regs from the userspace ABI.
 * struct user_regs_struct must form a prefix of struct pt_regs.
 */
struct user_regs_struct {
#ifdef __CHERI__
	register_t pc;
	register_t ra;
	register_t sp;
	register_t gp;
	register_t tp;
	register_t t0;
	register_t t1;
	register_t t2;
	register_t s0;
	register_t s1;
	register_t a0;
	register_t a1;
	register_t a2;
	register_t a3;
	register_t a4;
	register_t a5;
	register_t a6;
	register_t a7;
	register_t s2;
	register_t s3;
	register_t s4;
	register_t s5;
	register_t s6;
	register_t s7;
	register_t s8;
	register_t s9;
	register_t s10;
	register_t s11;
	register_t t3;
	register_t t4;
	register_t t5;
	register_t t6;
	register_t ddc;
#else
	unsigned long pc;
	unsigned long ra;
	unsigned long sp;
	unsigned long gp;
	unsigned long tp;
	unsigned long t0;
	unsigned long t1;
	unsigned long t2;
	unsigned long s0;
	unsigned long s1;
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long a7;
	unsigned long s2;
	unsigned long s3;
	unsigned long s4;
	unsigned long s5;
	unsigned long s6;
	unsigned long s7;
	unsigned long s8;
	unsigned long s9;
	unsigned long s10;
	unsigned long s11;
	unsigned long t3;
	unsigned long t4;
	unsigned long t5;
	unsigned long t6;
#endif
};

struct __riscv_f_ext_state {
	__u32 f[32];
	__u32 fcsr;
};

struct __riscv_d_ext_state {
	__u64 f[32];
	__u32 fcsr;
};

struct __riscv_q_ext_state {
	__u64 f[64] __attribute__((aligned(16)));
	__u32 fcsr;
	/*
	 * Reserved for expansion of sigcontext structure.  Currently zeroed
	 * upon signal, and must be zero upon sigreturn.
	 */
	__u32 reserved[3];
};

union __riscv_fp_state {
	struct __riscv_f_ext_state f;
	struct __riscv_d_ext_state d;
	struct __riscv_q_ext_state q;
};

#endif /* __ASSEMBLY__ */

#endif /* _UAPI_ASM_RISCV_PTRACE_H */
