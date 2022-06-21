/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2013 Regents of the University of California
 */


#include <linux/linkage.h>
#include <asm/asm.h>

#ifndef CONFIG_CPU_CHERI_PURECAP
#define __REG(reg)	reg
#define __REG_S		REG_S
#else
#define __REG(reg)	c##reg
#define __REG_S		csd
#endif

/* void *memset(void *, int, size_t) */
ENTRY(__memset)
WEAK(memset)
#ifndef CONFIG_CPU_CHERI_PURECAP
	move t0, a0  /* Preserve return value */
#else
	cmove ct0, ca0
#endif

	/* Defer to byte-oriented fill for small sizes */
	sltiu a3, a2, 16
	bnez a3, 4f

	/*
	 * Round to nearest XLEN-aligned address
	 * greater than or equal to start address
	 */
	addi a3, t0, SZREG-1
	andi a3, a3, ~(SZREG-1)
	beq a3, t0, 2f  /* Skip if already aligned */
	/* Handle initial misalignment */
	sub a4, a3, t0
1:
#ifndef CONFIG_CPU_CHERI_PURECAP
	sb a1, 0(t0)
	addi t0, t0, 1
#else
	csb a1, 0(ct0)
	cincoffset ct0, ct0, 1
#endif
	bltu t0, a3, 1b
	sub a2, a2, a4  /* Update count */

2: /* Duff's device with 32 XLEN stores per iteration */
	/* Broadcast value into all bytes */
	andi a1, a1, 0xff
	slli a3, a1, 8
	or a1, a3, a1
	slli a3, a1, 16
	or a1, a3, a1
#ifdef CONFIG_64BIT
	slli a3, a1, 32
	or a1, a3, a1
#endif

	/* Calculate end address */
	andi a4, a2, ~(SZREG-1)
	add a3, t0, a4

	andi a4, a4, 31*SZREG  /* Calculate remainder */
	beqz a4, 3f            /* Shortcut if no remainder */
	neg a4, a4
	addi a4, a4, 32*SZREG  /* Calculate initial offset */

	/* Adjust start address with offset */
#ifndef CONFIG_CPU_CHERI_PURECAP
	sub t0, t0, a4
#else
	neg a5, a4
	cincoffset ct0, ct0, a5
#endif

	/* Jump into loop body */
	/* Assumes 32-bit instruction lengths */
#ifdef CONFIG_64BIT
	srli a4, a4, 1
#endif
#ifndef CONFIG_CPU_CHERI_PURECAP
	la a5, 3f
	add a5, a5, a4
	jr a5
#else
	cllc ca5, 3f
	cincoffset ca5, ca5, a4
	cjr ca5
#endif
3:
	__REG_S a1,        0(__REG(t0))
	__REG_S a1,    SZREG(__REG(t0))
	__REG_S a1,  2*SZREG(__REG(t0))
	__REG_S a1,  3*SZREG(__REG(t0))
	__REG_S a1,  4*SZREG(__REG(t0))
	__REG_S a1,  5*SZREG(__REG(t0))
	__REG_S a1,  6*SZREG(__REG(t0))
	__REG_S a1,  7*SZREG(__REG(t0))
	__REG_S a1,  8*SZREG(__REG(t0))
	__REG_S a1,  9*SZREG(__REG(t0))
	__REG_S a1, 10*SZREG(__REG(t0))
	__REG_S a1, 11*SZREG(__REG(t0))
	__REG_S a1, 12*SZREG(__REG(t0))
	__REG_S a1, 13*SZREG(__REG(t0))
	__REG_S a1, 14*SZREG(__REG(t0))
	__REG_S a1, 15*SZREG(__REG(t0))
	__REG_S a1, 16*SZREG(__REG(t0))
	__REG_S a1, 17*SZREG(__REG(t0))
	__REG_S a1, 18*SZREG(__REG(t0))
	__REG_S a1, 19*SZREG(__REG(t0))
	__REG_S a1, 20*SZREG(__REG(t0))
	__REG_S a1, 21*SZREG(__REG(t0))
	__REG_S a1, 22*SZREG(__REG(t0))
	__REG_S a1, 23*SZREG(__REG(t0))
	__REG_S a1, 24*SZREG(__REG(t0))
	__REG_S a1, 25*SZREG(__REG(t0))
	__REG_S a1, 26*SZREG(__REG(t0))
	__REG_S a1, 27*SZREG(__REG(t0))
	__REG_S a1, 28*SZREG(__REG(t0))
	__REG_S a1, 29*SZREG(__REG(t0))
	__REG_S a1, 30*SZREG(__REG(t0))
	__REG_S a1, 31*SZREG(__REG(t0))
#ifndef CONFIG_CPU_CHERI_PURECAP
	addi t0, t0, 32*SZREG
#else
	cincoffset ct0, ct0, 32*SZREG
#endif
	bltu t0, a3, 3b
	andi a2, a2, SZREG-1  /* Update count */

4:
	/* Handle trailing misalignment */
	beqz a2, 6f
	add a3, t0, a2
5:
#ifndef CONFIG_CPU_CHERI_PURECAP
	sb a1, 0(t0)
	addi t0, t0, 1
#else
	csb a1, 0(ct0)
	cincoffset ct0, ct0, 1
#endif
	bltu t0, a3, 5b
6:
#ifndef CONFIG_CPU_CHERI_PURECAP
	ret
#else
	cret
#endif
ENDPROC(memset)
ENDPROC(__memset)
