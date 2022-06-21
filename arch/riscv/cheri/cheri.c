// SPDX-License-Identifier: GPL-2.0
/*
 *  cheri.c
 *
 *  Copyright (C) 2019-2020 Huawei Technologies
 *      Dmitry Kasatkin <dmitry.kasatkin@huawei.com>
 */

#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
#include <linux/printk.h>
#include <linux/context_tracking.h>

#include <linux/ptrace.h>
#include <linux/cheri.h>

void cheri_print_cap(const char *msg, register_t _cap);

register_t swap_restore_cap;
register_t kernel_data_cap;
register_t kernel_code_cap;
register_t userspace_code_cap;
register_t userspace_data_cap;

#ifdef CONFIG_CPU_CHERI_PURECAP
#include <cheri_init_globals.h>

void __init init_cap_relocs(void *data_cap, void *pc_cap)
{
	cheri_init_globals_3(data_cap, pc_cap, data_cap);
}
#endif

void __init cheri_setup_caps()
{
	/* FIXCHERI
	 * this is wrong behavior
	 * - it has to be intialized from head.S in assembly
	 * and passed to init_cap_relocs() to get function
	 * capabilities with proper permissions
	 * - cheri_getdefault() use all over needs to be replaced with data_cap
	 * - ddc needs to be burned
	 */

	register_t pcc = (register_t)cheri_getpcc();
	register_t ddc = (register_t)cheri_getdefault();

	kernel_data_cap = (register_t)cheri_setoffset(ddc,
			CHERI_CAP_KERN_BASE);
	kernel_data_cap = (register_t)cheri_csetbounds(kernel_data_cap,
			CHERI_CAP_KERN_LENGTH);
	kernel_data_cap = (register_t)cheri_andperm(kernel_data_cap,
			CHERI_PERMS_KERNEL_DATA | CHERI_PERMS_KERNEL_CODE);

	kernel_code_cap = (register_t)cheri_setoffset(pcc,
			CHERI_CAP_KERN_BASE);
	kernel_code_cap = (register_t)cheri_csetbounds(kernel_code_cap,
			CHERI_CAP_KERN_LENGTH);
	kernel_code_cap = (register_t)cheri_andperm(kernel_code_cap,
			CHERI_PERMS_KERNEL_CODE);

	userspace_data_cap = (register_t)cheri_setoffset(ddc,
			CHERI_CAP_USER_DATA_BASE);
	userspace_data_cap = (register_t)cheri_csetbounds(userspace_data_cap,
			CHERI_CAP_USER_DATA_LENGTH);
	userspace_data_cap = (register_t)cheri_andperm(userspace_data_cap,
			CHERI_PERMS_USERSPACE_DATA | CHERI_PERMS_USERSPACE_CODE);

	userspace_code_cap = (register_t)cheri_setoffset(pcc,
			CHERI_CAP_USER_CODE_BASE);
	userspace_code_cap = (register_t)cheri_csetbounds(userspace_code_cap,
			CHERI_CAP_USER_CODE_LENGTH);
	userspace_code_cap = (register_t)cheri_andperm(userspace_code_cap,
			CHERI_PERMS_USERSPACE_CODE);

	swap_restore_cap = (register_t)cheri_setoffset(pcc, 0);
}

void __init cheri_init(void)
{
	pr_info("CHERI caps init\n");

	cheri_setup_caps();

	// init_task ptregs
	current_pt_regs()->ddc = kernel_data_cap;

	/* initial kernel process DDC
	 * processes will fork from this
	 * may be need limited privileges for user space already here
	 */

	cheri_print_cap("swap: ", swap_restore_cap);
	cheri_print_cap("kcode: ", kernel_code_cap);
	cheri_print_cap("kdata: ", kernel_data_cap);
	cheri_print_cap("ucode: ", userspace_code_cap);
	cheri_print_cap("udata: ", userspace_data_cap);
}

void __init arch_task_cache_init(void)
{
	cheri_init();
}

unsigned long __cheri_copy_from_user(void *to, const void __user *from, unsigned long n)
{
	might_fault();
	kasan_check_write(to, n);
	check_object_size(to, n, false);
	return __asm_cheri_user_memcpy(to, from, n);
}

unsigned long __cheri_copy_to_user(void __user *to, const void *from, unsigned long n)
{
	might_fault();
	kasan_check_read(from, n);
	check_object_size(from, n, true);
	return __asm_cheri_user_memcpy(to, from, n);
}

void cheri_copy_regs(struct pt_regs *childregs, struct pt_regs *regs)
{
	struct pt_regs_cregs *cregs = (struct pt_regs_cregs*)regs;
	struct pt_regs_cregs *childcregs = (struct pt_regs_cregs*)childregs;
	int i;

	childregs->status = regs->status;
	childregs->badaddr = regs->badaddr;
	childregs->cause = regs->cause;
	childregs->orig_a0 = regs->orig_a0;

	for (i = 0; i < ARRAY_SIZE(cregs->creg); i++)
		childcregs->creg[i] = cregs->creg[i];
}

void cheri_cleanup_regs(struct pt_regs *regs)
{
	struct pt_regs_cregs *cregs = (struct pt_regs_cregs*)regs;
	int i;

	for (i = 0; i < ARRAY_SIZE(cregs->creg); i++)
		cregs->creg[i] = 0;
	/* it is called from start_thread from elf loader
	 * so set userspace capability
	 */
	regs->ddc = userspace_data_cap;
}

void cheri_print_cap(const char *msg, register_t _cap)
{
	unsigned long c_addr, c_perms, c_otype, c_base, c_length, c_offset;
	unsigned int c_tag, c_sealed, c_flags;
	const char *l = "", *t = "";
	void* __capability cap = (void * __capability)_cap;

	c_addr = cheri_getaddress(cap);
	c_tag = cheri_gettag(cap);
	c_sealed = cheri_getsealed(cap);
	c_perms = cheri_getperm(cap);
	c_flags = cheri_getflags(cap);
	c_otype = cheri_gettype(cap);
	c_base = cheri_getbase(cap);
	c_length = cheri_getlen(cap);
	c_offset = cheri_getoffset(cap);

	if (c_length == -1) {
		l = "-";
		c_length = 1;
	}

	if (c_otype == -1) {
		t = "-";
		c_otype = 1;
	}

	pr_cont("%s%016lx v:%u s:%u p:%04lx f:%01x b:%lx o:%lx l:%s%lx t:%s%ld\n",
		msg, c_addr, c_tag, c_sealed, c_perms, c_flags, c_base, c_offset,
		l, c_length, t, c_otype);
}

static const char *reg_names[] = {
	"cnull", "cra", "csp", "cgp", "ctp", "ct0", "ct1", "ct2",
	"cs0", "cs1", "ca0", "ca1", "ca2", "ca3", "ca4", "ca5",
	"ca6", "ca7", "cs2", "cs3", "cs4", "cs5", "cs6", "cs7",
	"cs8", "cs9", "cs10", "cs11", "ct3", "ct4", "ct5", "ct6"
};

void cheri_show_regs(const struct pt_regs *regs)
{
	struct pt_regs_cregs *cregs = (struct pt_regs_cregs*)regs;
	int i;

	cheri_print_cap(" ddc: ", regs->ddc);
	cheri_print_cap(" epc: ", regs->epc);
	for (i = 1; i < ARRAY_SIZE(cregs->creg) - 1; i++) {
		printk("%4s: ", reg_names[i]);
		cheri_print_cap("", cregs->creg[i]);
	}
}


/* codes for SIGPROT - XXXRW: under incorrect ifdef */
#define	PROT_CHERI_BOUNDS	1	/* Capability bounds fault	*/
#define	PROT_CHERI_TAG		2	/* Capability tag fault		*/
#define	PROT_CHERI_SEALED	3	/* Capability sealed fault	*/
#define	PROT_CHERI_TYPE		4	/* Type mismatch fault		*/
#define	PROT_CHERI_PERM		5	/* Capability permission fault	*/
#define	PROT_CHERI_STORETAG	6	/* Tag-store page fault		*/
#define	PROT_CHERI_IMPRECISE	7	/* Imprecise bounds fault	*/
#define	PROT_CHERI_STORELOCAL	8	/* Store-local fault		*/
#define	PROT_CHERI_CCALL	9	/* CCall fault			*/
#define	PROT_CHERI_CRETURN	10	/* CReturn fault		*/
#define	PROT_CHERI_SYSREG	11	/* Capability system register fault */
#define	PROT_CHERI_UNSEALED	61	/* CCall unsealed argument fault */
#define	PROT_CHERI_OVERFLOW	62	/* Trusted stack oveflow fault	*/
#define	PROT_CHERI_UNDERFLOW	63	/* Trusted stack underflow fault */
#define	PROT_CHERI_CCALLREGS	64	/* CCall argument fault		*/
#define	PROT_CHERI_LOCALARG	65	/* CCall local argument fault	*/
#define	PROT_CHERI_LOCALRET	66	/* CReturn local retval fault	*/

static const char *cheri_exccode_descr[] = {
	[CHERI_EXCCODE_NONE] = "none",
	[CHERI_EXCCODE_LENGTH] = "length violation",
	[CHERI_EXCCODE_TAG] = "tag violation",
	[CHERI_EXCCODE_SEAL] = "seal violation",
	[CHERI_EXCCODE_TYPE] = "type violation",
	[CHERI_EXCCODE_CALL] = "call trap",
	[CHERI_EXCCODE_RETURN] = "return trap",
	[CHERI_EXCCODE_PERM_USER] = "user-defined permission violation",
	[CHERI_EXCCODE_TLBSTORE] = "TLB prohibits store capability",
	[CHERI_EXCCODE_IMPRECISE] = "bounds cannot be represented precisely",
	[CHERI_EXCCODE_UNALIGNED_BASE] = "Unaligned PCC base",
	[CHERI_EXCCODE_GLOBAL] = "global violation",
	[CHERI_EXCCODE_PERM_EXECUTE] = "permit execute violation",
	[CHERI_EXCCODE_PERM_LOAD] = "permit load violation",
	[CHERI_EXCCODE_PERM_STORE] = "permit store violation",
	[CHERI_EXCCODE_PERM_LOADCAP] = "permit load capability violation",
	[CHERI_EXCCODE_PERM_STORECAP] = "permit store capability violation",
	[CHERI_EXCCODE_STORE_LOCALCAP] = "permit store local capability violation",
	[CHERI_EXCCODE_PERM_SEAL] = "permit seal violation",
	[CHERI_EXCCODE_SYSTEM_REGS] = "access system registers violation",
	[CHERI_EXCCODE_PERM_CCALL] = "permit ccall violation",
	[CHERI_EXCCODE_CCALL_IDC] = "access ccall IDC violation",
	[CHERI_EXCCODE_PERM_UNSEAL] = "permit unseal violation",
	[CHERI_EXCCODE_PERM_SET_CID] = "permit CSetCID violation",
};

const char *cheri_exccode_string(int exccode)
{

	if (exccode >= ARRAY_SIZE(cheri_exccode_descr) ||
	    cheri_exccode_descr[exccode] == NULL) {
		if (exccode >= CHERI_EXCCODE_SW_BASE)
			return ("unknown software exception");
		else
			return ("unknown ISA exception");
	}
	return (cheri_exccode_descr[exccode]);
}

int cheri_sccsr_to_sicode(size_t sccsr)
{
	uint8_t exccode;

	exccode = (sccsr & SCCSR_CAUSE_MASK) >> SCCSR_CAUSE_SHIFT;
	switch (exccode) {
	case CHERI_EXCCODE_LENGTH:
		return (PROT_CHERI_BOUNDS);

	case CHERI_EXCCODE_TAG:
		return (PROT_CHERI_TAG);

	case CHERI_EXCCODE_SEAL:
		return (PROT_CHERI_SEALED);

	case CHERI_EXCCODE_TYPE:
		return (PROT_CHERI_TYPE);

	case CHERI_EXCCODE_PERM_EXECUTE:
	case CHERI_EXCCODE_PERM_LOAD:
	case CHERI_EXCCODE_PERM_STORE:
	case CHERI_EXCCODE_PERM_LOADCAP:
	case CHERI_EXCCODE_PERM_STORECAP:
	case CHERI_EXCCODE_PERM_SEAL:
	case CHERI_EXCCODE_PERM_UNSEAL:
	case CHERI_EXCCODE_USER_PERM:
	case CHERI_EXCCODE_PERM_SET_CID:
		return (PROT_CHERI_PERM);

	case CHERI_EXCCODE_TLBSTORE:
		return (PROT_CHERI_STORETAG);

	case CHERI_EXCCODE_IMPRECISE:
		return (PROT_CHERI_IMPRECISE);

	case CHERI_EXCCODE_GLOBAL:
	case CHERI_EXCCODE_STORE_LOCALCAP:
		return (PROT_CHERI_STORELOCAL);

	case CHERI_EXCCODE_CALL:
		return (PROT_CHERI_CCALL);

	case CHERI_EXCCODE_RETURN:
		return (PROT_CHERI_CRETURN);

	case CHERI_EXCCODE_SYSTEM_REGS:
		return (PROT_CHERI_SYSREG);

	case CHERI_EXCCODE_NONE:
	default:
		pr_crit(
		    "%s: Warning: Unknown exccode %u, returning si_code 0\n",
		    __func__, exccode);
		return (0);
	}
}

static const char *scr_names[] = {
        [0] = "pcc",
        [1] = "ddc",
        [4] = "utcc",
        [5] = "utdc",
        [6] = "uscratchc",
        [7] = "uepcc",
        [12] = "stcc",
        [13] = "stdc",
        [14] = "sscratchc",
        [15] = "sepcc",
        [28] = "mtcc",
        [29] = "mtdc",
        [30] = "mscratchc",
        [31] = "mepcc"
};

#define cscr_read(scr)                                                  \
({      uintcap_t val;                                                  \
        __asm __volatile("cspecialr %0, " #scr : "=C" (val));           \
        val;                                                            \
})

void cheri_show_excinfo(struct pt_regs *regs)
{
	unsigned long sccsr = csr_read(sccsr);
	unsigned long stval = csr_read(stval);
	unsigned long cause = (stval & SCCSR_CAUSE_MASK) >> SCCSR_CAUSE_SHIFT;
	unsigned long cap_idx = (stval & SCCSR_CAP_IDX_MASK) >> SCCSR_CAP_IDX_SHIFT;
	const char *msg = cheri_exccode_string(cause);
	struct long_pt_regs *lr = (struct long_pt_regs *)regs;

	pr_crit("CHERI exception %#x at 0x%016lx (%s)\n",
		cause, (unsigned long)regs->epc, msg);

	pr_info("sccsr: %s, %s, cause: 0x%02x, ",
		sccsr & SCCSR_E ? "enabled" : "disabled",
		sccsr & SCCSR_D ? "dirty" : "clean",
		cause);

	if (cap_idx < 32)
		pr_cont("reg: %s ", reg_names[cap_idx]);
	else if (cap_idx - 32 < ARRAY_SIZE(scr_names) &&
		scr_names[cap_idx - 32] != NULL)
		pr_cont("reg: %s ", scr_names[cap_idx - 32]);
	else
		pr_cont("reg: invalid (%d) ", cap_idx);

	pr_cont("(%s)\n", msg);

	cheri_show_regs(regs);

	pr_info("Kernel CAP regs:\n");

        cheri_print_cap("ddc: ",  cscr_read(ddc));
        cheri_print_cap("pcc: ",  cscr_read(pcc));
        cheri_print_cap("stcc: ",  cscr_read(stcc));
        cheri_print_cap("stdc: ",  cscr_read(stdc));
        cheri_print_cap("sscratchc: ",  cscr_read(sscratchc));
        cheri_print_cap("sepcc: ",  cscr_read(sepcc));

	pr_info("trace FP/PC/RA: %#lx %#lx %#lx\n",
		(long)regs->s0, (long)regs->epc, (long)regs->ra);
}
