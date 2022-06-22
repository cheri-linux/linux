/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2014 Regents of the University of California
 */

#include <linux/init.h>
#include <linux/linkage.h>
#include <asm/page.h>

	__PAGE_ALIGNED_DATA

	.globl vdso_cheri_start, vdso_cheri_end
	.balign PAGE_SIZE
vdso_cheri_start:
	.incbin "arch/riscv/kernel/vdso-cheri/vdso.so"
	.balign PAGE_SIZE
vdso_cheri_end:

	.previous
