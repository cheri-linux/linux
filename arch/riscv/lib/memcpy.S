/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2013 Regents of the University of California
 */

#include <linux/linkage.h>
#include <asm/asm.h>

#ifdef CONFIG_CPU_CHERI
#include <asm/cherireg.h>
#endif

#ifndef CONFIG_CPU_CHERI_PURECAP

/* void *memcpy(void *, const void *, size_t) */
ENTRY(__memcpy)
WEAK(memcpy)
	move t6, a0  /* Preserve return value */

	/* Defer to byte-oriented copy for small sizes */
	sltiu a3, a2, 128
	bnez a3, 4f
	/* Use word-oriented copy only if low-order bits match */
	andi a3, t6, SZREG-1
	andi a4, a1, SZREG-1
	bne a3, a4, 4f

	beqz a3, 2f  /* Skip if already aligned */
	/*
	 * Round to nearest double word-aligned address
	 * greater than or equal to start address
	 */
	andi a3, a1, ~(SZREG-1)
	addi a3, a3, SZREG
	/* Handle initial misalignment */
	sub a4, a3, a1
1:
	lb a5, 0(a1)
	addi a1, a1, 1
	sb a5, 0(t6)
	addi t6, t6, 1
	bltu a1, a3, 1b
	sub a2, a2, a4  /* Update count */

2:
	andi a4, a2, ~((16*SZREG)-1)
	beqz a4, 4f
	add a3, a1, a4
3:
	REG_L a4,       0(a1)
	REG_L a5,   SZREG(a1)
	REG_L a6, 2*SZREG(a1)
	REG_L a7, 3*SZREG(a1)
	REG_L t0, 4*SZREG(a1)
	REG_L t1, 5*SZREG(a1)
	REG_L t2, 6*SZREG(a1)
	REG_L t3, 7*SZREG(a1)
	REG_L t4, 8*SZREG(a1)
	REG_L t5, 9*SZREG(a1)
	REG_S a4,       0(t6)
	REG_S a5,   SZREG(t6)
	REG_S a6, 2*SZREG(t6)
	REG_S a7, 3*SZREG(t6)
	REG_S t0, 4*SZREG(t6)
	REG_S t1, 5*SZREG(t6)
	REG_S t2, 6*SZREG(t6)
	REG_S t3, 7*SZREG(t6)
	REG_S t4, 8*SZREG(t6)
	REG_S t5, 9*SZREG(t6)
	REG_L a4, 10*SZREG(a1)
	REG_L a5, 11*SZREG(a1)
	REG_L a6, 12*SZREG(a1)
	REG_L a7, 13*SZREG(a1)
	REG_L t0, 14*SZREG(a1)
	REG_L t1, 15*SZREG(a1)
	addi a1, a1, 16*SZREG
	REG_S a4, 10*SZREG(t6)
	REG_S a5, 11*SZREG(t6)
	REG_S a6, 12*SZREG(t6)
	REG_S a7, 13*SZREG(t6)
	REG_S t0, 14*SZREG(t6)
	REG_S t1, 15*SZREG(t6)
	addi t6, t6, 16*SZREG
	bltu a1, a3, 3b
	andi a2, a2, (16*SZREG)-1  /* Update count */

4:
	/* Handle trailing misalignment */
	beqz a2, 6f
	add a3, a1, a2

	/* Use word-oriented copy if co-aligned to word boundary */
	or a5, a1, t6
	or a5, a5, a3
	andi a5, a5, 3
	bnez a5, 5f
7:
	lw a4, 0(a1)
	addi a1, a1, 4
	sw a4, 0(t6)
	addi t6, t6, 4
	bltu a1, a3, 7b

	ret

5:
	lb a4, 0(a1)
	addi a1, a1, 1
	sb a4, 0(t6)
	addi t6, t6, 1
	bltu a1, a3, 5b
6:
	ret
ENDPROC(memcpy)
ENDPROC(__memcpy)

#ifdef CONFIG_CPU_CHERI

/* aligned version */
ENTRY(__cheri_memcpy_aligned)
        beqz a2, return
        and a2, a2, -CHERICAP_SIZE
        add a2, a1, a2
loop:
        lc ct0, 0(a1)
        sc ct0, 0(a0)
        addi a1, a1, CHERICAP_SIZE
        addi a0, a0, CHERICAP_SIZE
        bne a1, a2, loop
return:
        jr      ra
ENDPROC(__cheri_memcpy_aligned)

#endif

#else

/* void *memcpy(void *, const void *, size_t) */
ENTRY(__memcpy)
WEAK(memcpy)
	cmove ct6, ca0  /* Preserve return value */

	/* get end address */
	add a3, a1, a2

	/* check if src and dst have same alignment */
	andi t0, a0, CHERICAP_SIZE - 1
	andi t1, a1, CHERICAP_SIZE - 1
	/* if not same alignment then jump next */
	bne t0, t1, 3f

	/* align up src up */
	addi t0, a1, CHERICAP_SIZE - 1
	andi t0, t0, ~(CHERICAP_SIZE - 1)
	/* get aligned end address */
	andi t1, a3, ~(CHERICAP_SIZE - 1)
	/*
	 * a3: terminal address of source region
	 * t0: lowest CHERICAP_SIZE-aligned address in source
	 * t1: highest CHERICAP_SIZE-aligned address in source
	 */
	bgeu t0, t1, 3f
	bgeu a1, t0, 2f
1:
	clbu t2, (ca1)
	csb t2, (ca0)
	cincoffset ca1, ca1, 1
	cincoffset ca0, ca0, 1
	bltu a1, t0, 1b
2:
	clc ct2, (ca1)
	csc ct2, (ca0)
	cincoffset ca1, ca1, CHERICAP_SIZE
	cincoffset ca0, ca0, CHERICAP_SIZE
	bltu a1, t1, 2b
3:
	bgeu a1, a3, 5f
4:
	clbu t2, (ca1)
	csb t2, (ca0)
	cincoffset ca1, ca1, 1
	cincoffset ca0, ca0, 1
	bltu a1, a3, 4b
5:
	cmove ca0, ct6
	cret
ENDPROC(memcpy)
ENDPROC(__memcpy)

#ifdef CONFIG_CPU_CHERI

/* aligned version */
/* void *memcpy(void *, const void *, size_t) */
ENTRY(__cheri_memcpy_aligned)
        beqz a2, return
        and a2, a2, -CHERICAP_SIZE
        add a2, a1, a2
loop:
        clc ct0, 0(ca1)
        csc ct0, 0(ca0)
        cincoffset ca1, ca1, CHERICAP_SIZE
        cincoffset ca0, ca0, CHERICAP_SIZE
        bne a1, a2, loop
return:
	cret
ENDPROC(__cheri_memcpy_aligned)

#endif

#endif
