// SPDX-License-Identifier: GPL-2.0
/*
 *  cheri.h
 *
 *  Copyright (C) 2019-2020 Huawei Technologies
 *      Dmitry Kasatkin <dmitry.kasatkin@huawei.com>
 */

#ifndef __ASM_CHERI_H
#define __ASM_CHERI_H

#define	VM_MINUSER_ADDRESS	0x0000000000000000UL
//#define	VM_MAXUSER_ADDRESS	0xffff000000000000UL
#define	VM_MAXUSER_ADDRESS	0x0000010000000000UL

#ifndef __ASSEMBLY__

#include <linux/linkage.h>
#include <linux/init.h>
#include <linux/cheric.h>

struct pt_regs;

extern register_t swap_restore_cap;
extern register_t kernel_data_cap;
extern register_t kernel_code_cap;
extern register_t userspace_data_cap;
extern register_t userspace_code_cap;

void __init cheri_init(void);
void cheri_setup_caps(void);

void cheri_copy_regs(struct pt_regs *childregs, struct pt_regs *regs);
void cheri_cleanup_regs(struct pt_regs *regs);

void cheri_show_regs(const struct pt_regs *regs);

const char *cheri_exccode_string(int exccode);
int cheri_sccsr_to_sicode(size_t sccsr);
void cheri_show_excinfo(struct pt_regs *regs);

extern asmlinkage void *__cheri_memcpy_aligned(void *, const void *, size_t);

#define cheri_memcpy_aligned __cheri_memcpy_aligned

unsigned long __cheri_copy_from_user(void *to, const void __user *from, unsigned long n);
unsigned long cheri_copy_from_user(void *to, const void __user *from, unsigned long n);
unsigned long __cheri_copy_to_user(void __user *to, const void *from, unsigned long n);
unsigned long cheri_copy_to_user(void __user *to, const void *from, unsigned long n);

unsigned long __asm_cheri_user_memcpy(void *dst, const void *src, size_t len);

void *cheri_memcpy(void *dst, const void *src, size_t len);
void * __capability  memcpy_c(void * __capability __restrict,
			      const void * __capability __restrict, size_t);

void cheri_print_cap(const char *msg, register_t cap);

#endif

#endif
