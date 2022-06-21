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
	RISCV_PTR 100b
	RISCV_PTR \lbl
	.previous
	.endm

#ifndef CONFIG_CPU_CHERI_PURECAP

ENTRY(__asm_copy_to_user)
ENTRY(__asm_copy_from_user)

	/* Enable access to user memory */
	li t6, SR_SUM
	csrs CSR_STATUS, t6

	add a3, a1, a2
	/* Use word-oriented copy only if low-order bits match */
	andi t0, a0, SZREG-1
	andi t1, a1, SZREG-1
	bne t0, t1, 2f

	addi t0, a1, SZREG-1
	andi t1, a3, ~(SZREG-1)
	andi t0, t0, ~(SZREG-1)
	/*
	 * a3: terminal address of source region
	 * t0: lowest XLEN-aligned address in source
	 * t1: highest XLEN-aligned address in source
	 */
	bgeu t0, t1, 2f
	bltu a1, t0, 4f
1:
	fixup REG_L, t2, (a1), 10f
	fixup REG_S, t2, (a0), 10f
	addi a1, a1, SZREG
	addi a0, a0, SZREG
	bltu a1, t1, 1b
2:
	bltu a1, a3, 5f

3:
	/* Disable access to user memory */
	csrc CSR_STATUS, t6
	li a0, 0
	ret
4: /* Edge case: unalignment */
	fixup lbu, t2, (a1), 10f
	fixup sb, t2, (a0), 10f
	addi a1, a1, 1
	addi a0, a0, 1
	bltu a1, t0, 4b
	j 1b
5: /* Edge case: remainder */
	fixup lbu, t2, (a1), 10f
	fixup sb, t2, (a0), 10f
	addi a1, a1, 1
	addi a0, a0, 1
	bltu a1, a3, 5b
	j 3b
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
	bne t0, t1, 2f

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
	bgeu t0, t1, 2f
	bltu a1, t0, 4f
1:
	/* cheri copy */
	fixup lc, ct2, (a1), 10f
	fixup sc, ct2, (a0), 10f
	addi a1, a1, CHERICAP_SIZE
	addi a0, a0, CHERICAP_SIZE
	bltu a1, t1, 1b
2:
	bltu a1, a3, 5f

3:
	/* Disable access to user memory */
	csrc CSR_STATUS, t6
	li a0, 0
	ret
4: /* Edge case: unalignment */
	fixup lbu, t2, (a1), 10f
	fixup sb, t2, (a0), 10f
	addi a1, a1, 1
	addi a0, a0, 1
	bltu a1, t0, 4b
	j 1b
5: /* Edge case: remainder */
	fixup lbu, t2, (a1), 10f
	fixup sb, t2, (a0), 10f
	addi a1, a1, 1
	addi a0, a0, 1
	bltu a1, a3, 5b
	j 3b
ENDPROC(__asm_cheri_user_memcpy)

/* aligned version */
ENTRY(__asm_cheri_user_memcpy_aligned)

	/* enable access to user memory */
	li t6, SR_SUM
	csrs CSR_STATUS, t6

	beqz a2, 2f
	and a3, a2, -CHERICAP_SIZE
	add a3, a1, a3
1:
	fixup lc, ct0, (a1), 10f
	fixup sc, ct0, (a0), 10f
	addi a1, a1, CHERICAP_SIZE
	addi a0, a0, CHERICAP_SIZE
	bne a1, a3, 1b
2:
	/* disable access to user memory */
	csrc CSR_STATUS, t6
	li a0, 0
	jr ra
ENDPROC(__asm_cheri_user_memcpy_aligned)

#endif

#else // CONFIG_CPU_CHERI_PURECAP

ENTRY(__asm_copy_to_user)
ENTRY(__asm_copy_from_user)
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
	bne t0, t1, 2f

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
	bgeu t0, t1, 2f
	bltu a1, t0, 4f
1:
	/* cheri copy */
	fixup clc, ct2, (ca1), 10f
	fixup csc, ct2, (ca0), 10f
	cincoffset ca1, ca1, CHERICAP_SIZE
	cincoffset ca0, ca0, CHERICAP_SIZE
	bltu a1, t1, 1b
2:
	bltu a1, a3, 5f

3:
	/* Disable access to user memory */
	csrc CSR_STATUS, t6
	li a0, 0
	cret
4: /* Edge case: unalignment */
	fixup clbu, t2, (ca1), 10f
	fixup csb, t2, (ca0), 10f
	cincoffset ca1, ca1, 1
	cincoffset ca0, ca0, 1
	bltu a1, t0, 4b
	j 1b
5: /* Edge case: remainder */
	fixup clbu, t2, (ca1), 10f
	fixup csb, t2, (ca0), 10f
	cincoffset ca1, ca1, 1
	cincoffset ca0, ca0, 1
	bltu a1, a3, 5b
	j 3b
ENDPROC(__asm_cheri_user_memcpy)
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
	fixup csd, zero, (ca0), 11f
	cincoffset ca0, ca0, SZREG
	bltu a0, t1, 1b
2:
	bltu a0, a3, 5f

3:
	/* Disable access to user memory */
	csrc CSR_STATUS, t6
	li a0, 0
	cret
4: /* Edge case: unalignment */
	fixup csb, zero, (ca0), 11f
	cincoffset ca0, ca0, 1
	bltu a0, t0, 4b
	j 1b
5: /* Edge case: remainder */
	fixup csb, zero, (ca0), 11f
	cincoffset ca0, ca0, 1
	bltu a0, a3, 5b
	j 3b
ENDPROC(__clear_user)
EXPORT_SYMBOL(__clear_user)
#endif // CONFIG_CPU_CHERI_PURECAP


	.section .fixup,"ax"
	.balign 4
	/* Fixup code for __copy_user(10) and __clear_user(11) */
10:
	/* Disable access to user memory */
	csrc CSR_STATUS, t6
	mv a0, a2
#ifndef CONFIG_CPU_CHERI_PURECAP
	ret
#else
	cret
#endif
11:
	csrc CSR_STATUS, t6
	mv a0, a1
#ifndef CONFIG_CPU_CHERI_PURECAP
	ret
#else
	cret
#endif
	.previous
