#include <linux/linkage.h>
#include <asm-generic/export.h>
#include <asm/asm.h>
#include <asm/csr.h>

#ifdef CONFIG_CPU_CHERI
#include <asm/cherireg.h>
#endif

	.macro fixup op reg addr lbl
100:
	\op \reg, \addr
	.section __ex_table,"a"
	.balign RISCV_SZPTR
	RISCV_PTR 100b, \lbl
	.previous
	.endm

ENTRY(__asm_copy_to_user)
ENTRY(__asm_copy_from_user)

	/* Enable access to user memory */
	li t6, SR_SUM
	csrs CSR_STATUS, t6

	/* Save for return value */
	mv	t5, a2

	/*
	 * Register allocation for code below:
	 * a0 - start of uncopied dst
	 * a1 - start of uncopied src
	 * a2 - size
	 * t0 - end of uncopied dst
	 */
	add	t0, a0, a2

	/*
	 * Use byte copy only if too small.
	 * SZREG holds 4 for RV32 and 8 for RV64
	 */
	li	a3, 9*SZREG /* size must be larger than size in word_copy */
	bltu	a2, a3, .Lbyte_copy_tail

	/*
	 * Copy first bytes until dst is aligned to word boundary.
	 * a0 - start of dst
	 * t1 - start of aligned dst
	 */
	addi	t1, a0, SZREG-1
	andi	t1, t1, ~(SZREG-1)
	/* dst is already aligned, skip */
	beq	a0, t1, .Lskip_align_dst
1:
	/* a5 - one byte for copying data */
	fixup lb      a5, 0(a1), 10f
	addi	a1, a1, 1	/* src */
	fixup sb      a5, 0(a0), 10f
	addi	a0, a0, 1	/* dst */
	bltu	a0, t1, 1b	/* t1 - start of aligned dst */

.Lskip_align_dst:
	/*
	 * Now dst is aligned.
	 * Use shift-copy if src is misaligned.
	 * Use word-copy if both src and dst are aligned because
	 * can not use shift-copy which do not require shifting
	 */
	/* a1 - start of src */
	andi	a3, a1, SZREG-1
	bnez	a3, .Lshift_copy

.Lword_copy:
        /*
	 * Both src and dst are aligned, unrolled word copy
	 *
	 * a0 - start of aligned dst
	 * a1 - start of aligned src
	 * t0 - end of aligned dst
	 */
	addi	t0, t0, -(8*SZREG) /* not to over run */
2:
	fixup REG_L   a4,        0(a1), 10f
	fixup REG_L   a5,    SZREG(a1), 10f
	fixup REG_L   a6,  2*SZREG(a1), 10f
	fixup REG_L   a7,  3*SZREG(a1), 10f
	fixup REG_L   t1,  4*SZREG(a1), 10f
	fixup REG_L   t2,  5*SZREG(a1), 10f
	fixup REG_L   t3,  6*SZREG(a1), 10f
	fixup REG_L   t4,  7*SZREG(a1), 10f
	fixup REG_S   a4,        0(a0), 10f
	fixup REG_S   a5,    SZREG(a0), 10f
	fixup REG_S   a6,  2*SZREG(a0), 10f
	fixup REG_S   a7,  3*SZREG(a0), 10f
	fixup REG_S   t1,  4*SZREG(a0), 10f
	fixup REG_S   t2,  5*SZREG(a0), 10f
	fixup REG_S   t3,  6*SZREG(a0), 10f
	fixup REG_S   t4,  7*SZREG(a0), 10f
	addi	a0, a0, 8*SZREG
	addi	a1, a1, 8*SZREG
	bltu	a0, t0, 2b

	addi	t0, t0, 8*SZREG /* revert to original value */
	j	.Lbyte_copy_tail

.Lshift_copy:

	/*
	 * Word copy with shifting.
	 * For misaligned copy we still perform aligned word copy, but
	 * we need to use the value fetched from the previous iteration and
	 * do some shifts.
	 * This is safe because reading is less than a word size.
	 *
	 * a0 - start of aligned dst
	 * a1 - start of src
	 * a3 - a1 & mask:(SZREG-1)
	 * t0 - end of uncopied dst
	 * t1 - end of aligned dst
	 */
	/* calculating aligned word boundary for dst */
	andi	t1, t0, ~(SZREG-1)
	/* Converting unaligned src to aligned src */
	andi	a1, a1, ~(SZREG-1)

	/*
	 * Calculate shifts
	 * t3 - prev shift
	 * t4 - current shift
	 */
	slli	t3, a3, 3 /* converting bytes in a3 to bits */
	li	a5, SZREG*8
	sub	t4, a5, t3

	/* Load the first word to combine with second word */
	fixup REG_L   a5, 0(a1), 10f

3:
	/* Main shifting copy
	 *
	 * a0 - start of aligned dst
	 * a1 - start of aligned src
	 * t1 - end of aligned dst
	 */

	/* At least one iteration will be executed */
	srl	a4, a5, t3
	fixup REG_L   a5, SZREG(a1), 10f
	addi	a1, a1, SZREG
	sll	a2, a5, t4
	or	a2, a2, a4
	fixup REG_S   a2, 0(a0), 10f
	addi	a0, a0, SZREG
	bltu	a0, t1, 3b

	/* Revert src to original unaligned value  */
	add	a1, a1, a3

.Lbyte_copy_tail:
	/*
	 * Byte copy anything left.
	 *
	 * a0 - start of remaining dst
	 * a1 - start of remaining src
	 * t0 - end of remaining dst
	 */
	bgeu	a0, t0, .Lout_copy_user  /* check if end of copy */
4:
	fixup lb      a5, 0(a1), 10f
	addi	a1, a1, 1	/* src */
	fixup sb      a5, 0(a0), 10f
	addi	a0, a0, 1	/* dst */
	bltu	a0, t0, 4b	/* t0 - end of dst */

.Lout_copy_user:
	/* Disable access to user memory */
	csrc CSR_STATUS, t6
	li	a0, 0
	ret
ENDPROC(__asm_copy_to_user)
ENDPROC(__asm_copy_from_user)
EXPORT_SYMBOL(__asm_copy_to_user)
EXPORT_SYMBOL(__asm_copy_from_user)


ENTRY(__clear_user)

	/* Enable access to user memory */
	li t6, SR_SUM
	csrs CSR_STATUS, t6

	add a3, a0, a1
	addi t0, a0, SZREG-1
	andi t1, a3, ~(SZREG-1)
	andi t0, t0, ~(SZREG-1)
	/*
	 * a3: terminal address of target region
	 * t0: lowest doubleword-aligned address in target region
	 * t1: highest doubleword-aligned address in target region
	 */
	bgeu t0, t1, 2f
	bltu a0, t0, 4f
1:
	fixup REG_S, zero, (a0), 11f
	addi a0, a0, SZREG
	bltu a0, t1, 1b
2:
	bltu a0, a3, 5f

3:
	/* Disable access to user memory */
	csrc CSR_STATUS, t6
	li a0, 0
	ret
4: /* Edge case: unalignment */
	fixup sb, zero, (a0), 11f
	addi a0, a0, 1
	bltu a0, t0, 4b
	j 1b
5: /* Edge case: remainder */
	fixup sb, zero, (a0), 11f
	addi a0, a0, 1
	bltu a0, a3, 5b
	j 3b
ENDPROC(__clear_user)
EXPORT_SYMBOL(__clear_user)


#ifdef CONFIG_CPU_CHERI
ENTRY(__asm_cheri_user_memcpy)

	/* enable access to user memory */
	li t6, SR_SUM
	csrs CSR_STATUS, t6

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
	bltu a1, t0, 5f
1:
	/* cheri copy */
#if 0
.option push
.option capmode
	cfromptr ca0, ddc, a0
	cfromptr ca1, ddc, a1
2:
	fixup clc, ct2, (ca1), 10f
	fixup csc, ct2, (ca0), 10f
	cincoffset ca1, ca1, CHERICAP_SIZE
	cincoffset ca0, ca0, CHERICAP_SIZE
.option pop
#else
2:
	fixup lc, ct2, (a1), 10f
	fixup sc, ct2, (a0), 10f
#endif
	addi a1, a1, CHERICAP_SIZE
	addi a0, a0, CHERICAP_SIZE
	bltu a1, t1, 2b
3:
	bltu a1, a3, 6f

4:
	/* Disable access to user memory */
	csrc CSR_STATUS, t6
	li a0, 0
	ret
5: /* Edge case: unalignment */
	fixup lbu, t2, (a1), 10f
	fixup sb, t2, (a0), 10f
	addi a1, a1, 1
	addi a0, a0, 1
	bltu a1, t0, 5b
	j 1b
6: /* Edge case: remainder */
	fixup lbu, t2, (a1), 10f
	fixup sb, t2, (a0), 10f
	addi a1, a1, 1
	addi a0, a0, 1
	bltu a1, a3, 6b
	j 4b
ENDPROC(__asm_cheri_user_memcpy)

/* aligned version */
ENTRY(__asm_cheri_user_memcpy_aligned)

	/* enable access to user memory */
	li t6, SR_SUM
	csrs CSR_STATUS, t6

	beqz a2, 2f
	and a3, a2, -CHERICAP_SIZE
	add a3, a1, a3
#if 0
.option push
.option capmode
	cfromptr ca0, ddc, a0
	cfromptr ca1, ddc, a1
1:
	fixup clc, ct0, (ca1), 10f
	fixup csc, ct0, (ca0), 10f
	cincoffset ca1, ca1, CHERICAP_SIZE
	cincoffset ca0, ca0, CHERICAP_SIZE
.option pop
#else
1:
	fixup lc, ct0, (a1), 10f
	fixup sc, ct0, (a0), 10f
	addi a1, a1, CHERICAP_SIZE
	addi a0, a0, CHERICAP_SIZE
#endif
	bne a1, a3, 1b
2:
	/* disable access to user memory */
	csrc CSR_STATUS, t6
	li a0, 0
	jr ra
END(__asm_cheri_user_memcpy_aligned)

#endif

	.section .fixup,"ax"
	.balign 4
	/* Fixup code for __copy_user(10) and __clear_user(11) */
10:
	/* Disable access to user memory */
	csrc CSR_STATUS, t6
	mv a0, t5
	ret
11:
	csrc CSR_STATUS, t6
	mv a0, a1
	ret
	.previous
